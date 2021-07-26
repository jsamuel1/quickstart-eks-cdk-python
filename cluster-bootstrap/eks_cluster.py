"""
Purpose

Example of how to provision an EKS cluster, create the IAM Roles for Service Accounts (IRSA) mappings,
and then deploy various common cluster add-ons (AWS LB Controller, ExternalDNS, EBS/EFS CSI Drivers,
Cluster Autoscaler, AWS Elasticsearch, Prometheus & Grafana, Calico NetworkPolicy enforceement, 
OPA Gatekeeper w/example policies, etc.)

NOTE: This pulls many parameters/options for what you'd like from the cdk.json context section.
Have a look there for many options you can chance to customise this template for your environments/needs.
"""

from constructs import Construct

from aws_cdk import (
    Stack, 
    RemovalPolicy, 
    CfnOutput, 
    aws_ec2 as ec2,
    aws_eks as eks,
    aws_iam as iam,
    aws_elasticsearch as es,
)
from awslbcontroller import AwsLoadBalancerControllerStack

# Import the custom resource to switch on control plane logging from ekslogs_custom_resource.py
from ekslogs_custom_resource import EKSLogsObjectResource

# Import the feature stacks
from caliconetworkprovider import CalicoNetworkProviderStack
from bastion import BastionStack
from clientvpn import ClientVpnStack
from eks_charts import EKSChartsStack

class EKSClusterStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Either create a new IAM role to administrate the cluster or create a new one
        if (self.node.try_get_context("create_new_cluster_admin_role") == "True"):
            cluster_admin_role = iam.Role(self, "ClusterAdminRole",
                assumed_by=iam.CompositePrincipal(
                    iam.AccountRootPrincipal(),
                    iam.ServicePrincipal("ec2.amazonaws.com")
                )
            )
            cluster_admin_policy_statement_json_1 = {
                "Effect": "Allow",
                "Action": [
                    "eks:DescribeCluster"
                ],
                "Resource": "*"
            }
            cluster_admin_role.add_to_policy(iam.PolicyStatement.from_json(cluster_admin_policy_statement_json_1))
        else:
            # You'll also need to add a trust relationship to ec2.amazonaws.com to sts:AssumeRole to this as well
            cluster_admin_role = iam.Role.from_role_arn(self, "ClusterAdminRole",
                role_arn=self.node.try_get_context("existing_admin_role_arn")
            )
    
        # Either create a new VPC with the options below OR import an existing one by name
        if (self.node.try_get_context("create_new_vpc") == "True"):
            eks_vpc = ec2.Vpc(
                self, "VPC",
                # We are choosing to spread our VPC across 3 availability zones
                max_azs=3,
                # We are creating a VPC that has a /22, 1024 IPs, for our EKS cluster.
                # I am using that instead of a /16 etc. as I know many companies have constraints here
                # If you can go bigger than this great - but I would try not to go much smaller if you can
                # I use https://www.davidc.net/sites/default/subnets/subnets.html to me work out the CIDRs
                cidr=self.node.try_get_context("vpc_cidr"),
                subnet_configuration=[
                    # 3 x Public Subnets (1 per AZ) with 64 IPs each for our ALBs and NATs
                    ec2.SubnetConfiguration(
                        subnet_type=ec2.SubnetType.PUBLIC,
                        name="Public",
                        cidr_mask=self.node.try_get_context("vpc_cidr_mask_public")
                    ), 
                    # 3 x Private Subnets (1 per AZ) with 256 IPs each for our Nodes and Pods
                    ec2.SubnetConfiguration(
                        subnet_type=ec2.SubnetType.PRIVATE,
                        name="Private",
                        cidr_mask=self.node.try_get_context("vpc_cidr_mask_private")
                    )
                ]
            )   
        else:
            eks_vpc = ec2.Vpc.from_lookup(self, 'VPC', vpc_name=self.node.try_get_context("existing_vpc_name"))

        # Create an EKS Cluster
        eks_cluster = eks.Cluster(
            self, "cluster",
            vpc=eks_vpc,
            masters_role=cluster_admin_role,
            cluster_name=self.node.try_get_context("cluster_name"),
            # Make our cluster's control plane accessible only within our private VPC
            # This means that we'll have to ssh to a jumpbox/bastion or set up a VPN to manage it
            endpoint_access=eks.EndpointAccess.PRIVATE,
            version=eks.KubernetesVersion.of(self.node.try_get_context("eks_version")),
            default_capacity=0
        )

        # Add a Managed Node Group
        eks_node_group = eks_cluster.add_nodegroup_capacity(
            "cluster-default-ng",
            desired_size=self.node.try_get_context("eks_node_quantity"),
            disk_size=self.node.try_get_context("eks_node_disk_size"),
            # The default in CDK is to force upgrades through even if they violate - it is safer to not do that
            force_update=False,
            instance_types=[ec2.InstanceType(self.node.try_get_context("eks_node_instance_type"))],
            release_version=self.node.try_get_context("eks_node_ami_version")
        )
        eks_node_group.role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore"))
        
        # AWS Load Balancer Controller
        if (self.node.try_get_context("deploy_aws_lb_controller") == "True"):
            AwsLoadBalancerControllerStack(self, "AWSLoadBalancerControllerStack", eks_cluster=eks_cluster, vpc_id=eks_vpc.vpc_id)
            

        # External DNS Controller
        if (self.node.try_get_context("deploy_external_dns") == "True"):
            externaldns_service_account = eks_cluster.add_service_account(
                "external-dns",
                name="external-dns",
                namespace="kube-system"
            )

            # Create the PolicyStatements to attach to the role
            # NOTE that this will give External DNS access to all Route53 zones
            # For production you'll likely want to replace 'Resourece *' with specific resources
            externaldns_policy_statement_json_1 = {
            "Effect": "Allow",
                "Action": [
                    "route53:ChangeResourceRecordSets"
                ],
                "Resource": [
                    "arn:aws:route53:::hostedzone/*"
                ]
            }
            externaldns_policy_statement_json_2 = {
                "Effect": "Allow",
                "Action": [
                    "route53:ListHostedZones",
                    "route53:ListResourceRecordSets"
                ],
                "Resource": [
                    "*"
                ]
            }

            # Attach the necessary permissions
            externaldns_service_account.add_to_principal_policy(iam.PolicyStatement.from_json(externaldns_policy_statement_json_1))
            externaldns_service_account.add_to_principal_policy(iam.PolicyStatement.from_json(externaldns_policy_statement_json_2))

            # Deploy External DNS from the bitnami Helm chart
            # For more info see https://github.com/bitnami/charts/tree/master/bitnami/external-dns
            externaldns_chart = eks_cluster.add_helm_chart(
                "external-dns",
                chart="external-dns",
                version="5.0.2",
                release="externaldns",
                repository="https://charts.bitnami.com/bitnami",
                namespace="kube-system",
                values={
                    "provider": "aws",
                    "aws": {
                        "region": self.region
                    },
                    "serviceAccount": {
                        "create": False,
                        "name": "external-dns"
                    },
                    "podSecurityContext": {
                        "fsGroup": 65534
                    },
                    "replicas": 2
                }
            )
            externaldns_chart.node.add_dependency(externaldns_service_account)    

        # AWS EBS CSI Driver
        if (self.node.try_get_context("deploy_aws_ebs_csi") == "True"):
            awsebscsidriver_service_account = eks_cluster.add_service_account(
                "awsebscsidriver",
                name="awsebscsidriver",
                namespace="kube-system"
            )

            # Create the PolicyStatements to attach to the role
            awsebscsidriver_policy_statement_json_1 = {
                "Effect": "Allow",
                "Action": [
                    "ec2:AttachVolume",
                    "ec2:CreateSnapshot",
                    "ec2:CreateTags",
                    "ec2:CreateVolume",
                    "ec2:DeleteSnapshot",
                    "ec2:DeleteTags",
                    "ec2:DeleteVolume",
                    "ec2:DescribeAvailabilityZones",
                    "ec2:DescribeInstances",
                    "ec2:DescribeSnapshots",
                    "ec2:DescribeTags",
                    "ec2:DescribeVolumes",
                    "ec2:DescribeVolumesModifications",
                    "ec2:DetachVolume",
                    "ec2:ModifyVolume"
                ],
                "Resource": "*"
            }

            # Attach the necessary permissions
            awsebscsidriver_service_account.add_to_principal_policy(iam.PolicyStatement.from_json(awsebscsidriver_policy_statement_json_1))

            # Install the AWS EBS CSI Driver
            # For more info see https://github.com/kubernetes-sigs/aws-ebs-csi-driver
            awsebscsi_chart = eks_cluster.add_helm_chart(
                "aws-ebs-csi-driver",
                chart="aws-ebs-csi-driver",
                version="1.2.0",
                release="awsebscsidriver",
                repository="https://kubernetes-sigs.github.io/aws-ebs-csi-driver",
                namespace="kube-system",
                values={
                    "region": self.region,
                    "enableVolumeScheduling": True,
                    "enableVolumeResizing": True,
                    "enableVolumeSnapshot": True,
                    "serviceAccount": {
                        "controller": {
                            "create": False,
                            "name": "awsebscsidriver"
                        },
                        "snapshot": {
                            "create": False,
                            "name": "awsebscsidriver"
                        }
                    }
                }
            )
            awsebscsi_chart.node.add_dependency(awsebscsidriver_service_account)

        # AWS EFS CSI Driver
        if (self.node.try_get_context("deploy_aws_efs_csi") == "True"):
            awsefscsidriver_service_account = eks_cluster.add_service_account(
                "awsefscsidriver",
                name="awsefscsidriver",
                namespace="kube-system"
            )

            # Create the PolicyStatements to attach to the role
            awsefscsidriver_policy_statement_json_1 = {
                "Effect": "Allow",
                "Action": [
                    "elasticfilesystem:DescribeAccessPoints",
                    "elasticfilesystem:DescribeFileSystems"
                ],
                "Resource": "*"
            }
            awsefscsidriver_policy_statement_json_2 = {
                "Effect": "Allow",
                "Action": [
                    "elasticfilesystem:CreateAccessPoint"
                ],
                "Resource": "*",
                "Condition": {
                    "StringLike": {
                    "aws:RequestTag/efs.csi.aws.com/cluster": "true"
                    }
                }
            }
            awsefscsidriver_policy_statement_json_3 = {
                "Effect": "Allow",
                "Action": "elasticfilesystem:DeleteAccessPoint",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                    "aws:ResourceTag/efs.csi.aws.com/cluster": "true"
                    }
                }
            }

            # Attach the necessary permissions
            awsefscsidriver_service_account.add_to_principal_policy(iam.PolicyStatement.from_json(awsefscsidriver_policy_statement_json_1))
            awsefscsidriver_service_account.add_to_principal_policy(iam.PolicyStatement.from_json(awsefscsidriver_policy_statement_json_2))
            awsefscsidriver_service_account.add_to_principal_policy(iam.PolicyStatement.from_json(awsefscsidriver_policy_statement_json_3))

            # Install the AWS EFS CSI Driver
            # For more info see https://github.com/kubernetes-sigs/aws-efs-csi-driver
            awsefscsi_chart = eks_cluster.add_helm_chart(
                "aws-efs-csi-driver",
                chart="aws-efs-csi-driver",
                version="2.0.0",
                release="awsefscsidriver",
                repository="https://kubernetes-sigs.github.io/aws-efs-csi-driver/",
                namespace="kube-system",
                values={
                    "serviceAccount": {
                        "controller": {
                            "create": False,
                            "name": "awsefscsidriver"
                        }
                    }
                }
            )
            awsefscsi_chart.node.add_dependency(awsefscsidriver_service_account)

        # cluster-autoscaler
        if (self.node.try_get_context("deploy_cluster_autoscaler") == "True"):
            clusterautoscaler_service_account = eks_cluster.add_service_account(
                "clusterautoscaler",
                name="clusterautoscaler",
                namespace="kube-system"
            )

            # Create the PolicyStatements to attach to the role
            clusterautoscaler_policy_statement_json_1 = {
                "Effect": "Allow",
                "Action": [
                    "autoscaling:DescribeAutoScalingGroups",
                    "autoscaling:DescribeAutoScalingInstances",
                    "autoscaling:DescribeLaunchConfigurations",
                    "autoscaling:DescribeTags",
                    "autoscaling:SetDesiredCapacity",
                    "autoscaling:TerminateInstanceInAutoScalingGroup"
                ],
                "Resource": "*"
            }

            # Attach the necessary permissions
            clusterautoscaler_service_account.add_to_principal_policy(iam.PolicyStatement.from_json(clusterautoscaler_policy_statement_json_1))

            # Install the Cluster Autoscaler
            # For more info see https://github.com/kubernetes/autoscaler
            clusterautoscaler_chart = eks_cluster.add_helm_chart(
                "cluster-autoscaler",
                chart="cluster-autoscaler",
                version="9.9.2",
                release="clusterautoscaler",
                repository="https://kubernetes.github.io/autoscaler",
                namespace="kube-system",
                values={
                    "autoDiscovery": {
                        "clusterName": eks_cluster.cluster_name
                    },
                    "awsRegion": self.region,
                    "rbac": {
                        "serviceAccount": {
                            "create": False,
                            "name": "clusterautoscaler"
                        }
                    },
                    "replicaCount": 2
                }
            )
            clusterautoscaler_chart.node.add_dependency(clusterautoscaler_service_account)
        
        # Deploy a managed Amazon Elasticsearch and a fluent-bit to ship our container logs there
        if (self.node.try_get_context("deploy_managed_elasticsearch") == "True"):
            # Create a new ElasticSearch Domain
            # NOTE: I changed this to a removal_policy of DESTROY to help cleanup while I was 
            # developing/iterating on the project. If you comment out that line it defaults to keeping 
            # the Domain upon deletion of the CloudFormation stack so you won't lose your log data
            
            # The capacity in Nodes and Volume Size/Type for the AWS Elasticsearch
            es_capacity = es.CapacityConfig(
                data_nodes=self.node.try_get_context("es_data_nodes"),
                data_node_instance_type=self.node.try_get_context("es_data_node_instance_type"),
                master_nodes=self.node.try_get_context("es_master_nodes"),
                master_node_instance_type=self.node.try_get_context("es_master_node_instance_type")
            )
            es_ebs = es.EbsOptions(
                enabled=True,
                volume_type=ec2.EbsDeviceVolumeType.GP2,
                volume_size=self.node.try_get_context("es_ebs_volume_size")
            )

            es_access_policy_statement_json_1 = {
                "Effect": "Allow",
                "Action": "es:*",
                "Principal": {
                    "AWS": "*"
                },
                "Resource": "*"
            }

            # Create SecurityGroup for Elastic
            elastic_security_group = ec2.SecurityGroup(
                self, "ElasticSecurityGroup",
                vpc=eks_vpc,
                allow_all_outbound=True
            )
            # Add a rule to allow our new SG to talk to the EKS control plane
            eks_cluster.cluster_security_group.add_ingress_rule(
                elastic_security_group,
                ec2.Port.all_traffic()
            )
            # Add a rule to allow the EKS control plane to talk to our new SG
            elastic_security_group.add_ingress_rule(
                eks_cluster.cluster_security_group,
                ec2.Port.all_traffic()
            )

            # Note that this AWS Elasticsearch domain is optimised for cost rather than availability
            # and defaults to one node in a single availability zone
            es_domain = es.Domain(
                self, "ESDomain",
                removal_policy=RemovalPolicy.DESTROY,
                version=es.ElasticsearchVersion.V7_9,
                vpc=eks_vpc,
                vpc_subnets=[ec2.SubnetSelection(subnets=[eks_vpc.private_subnets[0]])],
                security_groups=[elastic_security_group],
                capacity=es_capacity,
                ebs=es_ebs,
                access_policies=[iam.PolicyStatement.from_json(es_access_policy_statement_json_1)]
            )
            
            # Create the Service Account
            fluentbit_service_account = eks_cluster.add_service_account(
                "fluentbit",
                name="fluentbit",
                namespace="kube-system"
            )

            fluentbit_policy_statement_json_1 = {
            "Effect": "Allow",
                "Action": [
                    "es:ESHttp*"
                ],
                "Resource": [
                    es_domain.domain_arn
                ]
            }

            # Add the policies to the service account
            fluentbit_service_account.add_to_principal_policy(iam.PolicyStatement.from_json(fluentbit_policy_statement_json_1))
            es_domain.grant_write(fluentbit_service_account)

            # For more info check out https://github.com/fluent/helm-charts/tree/main/charts/fluent-bit
            fluentbit_chart = eks_cluster.add_helm_chart(
                "fluentbit",
                chart="fluent-bit",
                version="0.15.13",
                release="fluent-bit",
                repository="https://fluent.github.io/helm-charts",
                namespace="kube-system",
                values={
                    "config": {
                        "outputs": "[OUTPUT]\n    Name            es\n    Match           *\n    AWS_Region      "+self.region+"\n    AWS_Auth        On\n    Host            "+es_domain.domain_endpoint+"\n    Port            443\n    TLS             On\n    Replace_Dots    On\n"
                    }
                }
            )
            fluentbit_chart.node.add_dependency(fluentbit_service_account)

            # Output the Kibana address in our CloudFormation Stack
            CfnOutput(
                self, "KibanaAddress",
                value="https://" + es_domain.domain_endpoint + "/_plugin/kibana/",
                description="Private endpoint for this EKS environment's Kibana to consume the logs",

            )

        # Deploy Prometheus and Grafana
        if (self.node.try_get_context("deploy_kube_prometheus_operator") == "True"):
            # TODO Replace this with the new AWS Managed Prometheus and Grafana when it is Generally Available (GA)
            # For more information see https://github.com/prometheus-community/helm-charts/tree/main/charts/kube-prometheus-stack
            prometheus_chart = eks_cluster.add_helm_chart(
                "metrics",
                chart="kube-prometheus-stack",
                version="16.1.2",
                release="prometheus",
                repository="https://prometheus-community.github.io/helm-charts",
                namespace="kube-system",
                values={
                    "prometheus": {
                        "prometheusSpec": {
                        "storageSpec": {
                            "volumeClaimTemplate": {
                            "spec": {
                                "accessModes": [
                                "ReadWriteOnce"
                                ],
                                "resources": {
                                "requests": {
                                    "storage": self.node.try_get_context("prometheus_disk_size")
                                }
                                },
                                "storageClassName": "gp2"
                            }
                            }
                        }
                        }
                    },
                    "alertmanager": {
                        "alertmanagerSpec": {
                        "storage": {
                            "volumeClaimTemplate": {
                            "spec": {
                                "accessModes": [
                                "ReadWriteOnce"
                                ],
                                "resources": {
                                "requests": {
                                    "storage": self.node.try_get_context("alertmanager_disk_size")
                                }
                                },
                                "storageClassName": "gp2"
                            }
                            }
                        }
                        }
                    },
                    "grafana": {
                        "persistence": {
                            "enabled": "true",
                            "storageClassName": "gp2",
                            "size": self.node.try_get_context("grafana_disk_size")
                        }
                    }
                }          
            )

            # Deploy an internal NLB to Grafana
            grafananlb_manifest = eks_cluster.add_manifest("GrafanaNLB",{
                "kind": "Service",
                "apiVersion": "v1",
                "metadata": {
                    "name": "grafana-nlb",
                    "namespace": "kube-system",
                    "annotations": {
                        "service.beta.kubernetes.io/aws-load-balancer-type": "nlb-ip",
                        "service.beta.kubernetes.io/aws-load-balancer-internal": "true"
                    }
                },
                "spec": {
                    "ports": [
                    {
                        "name": "service",
                        "protocol": "TCP",
                        "port": 80,
                        "targetPort": 3000
                    }
                    ],
                    "selector": {
                        "app.kubernetes.io/name": "grafana"
                    },
                    "type": "LoadBalancer"
                }
            })

        # Install the metrics-server (required for the HPA)
        if (self.node.try_get_context("deploy_metrics_server") == "True"):
            # For more info see https://github.com/bitnami/charts/tree/master/bitnami/metrics-server
            metricsserver_chart = eks_cluster.add_helm_chart(
                "metrics-server",
                chart="metrics-server",
                version="5.8.9",
                release="metricsserver",
                repository="https://charts.bitnami.com/bitnami",
                namespace="kube-system",
                values={
                    "replicas": 2
                }
            )

        # Install Calico to enforce NetworkPolicies
        if (self.node.try_get_context("deploy_calico_np") == "True"):
            CalicoNetworkProviderStack(self, "CalicoNetworkPolicies", eks_cluster=eks_cluster)

        # Deploy SSM Agent
        if (self.node.try_get_context("deploy_ssm_agent") == "True"):
            # For more information see https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/install-ssm-agent-on-amazon-eks-worker-nodes-by-using-kubernetes-daemonset.html
            ssm_agent_manifest = eks_cluster.add_manifest("SSMAgentManifest",
            {
                "apiVersion":"apps/v1",
                "kind":"DaemonSet",
                "metadata":{
                    "labels":{
                        "k8s-app":"ssm-installer"
                    },
                    "name":"ssm-installer",
                    "namespace":"kube-system"
                },
                "spec":{
                    "selector":{
                        "matchLabels":{
                            "k8s-app":"ssm-installer"
                        }
                    },
                    "template":{
                        "metadata":{
                            "labels":{
                            "k8s-app":"ssm-installer"
                            }
                        },
                        "spec":{
                            "containers":[
                            {
                                "image":"amazonlinux",
                                "imagePullPolicy":"Always",
                                "name":"ssm",
                                "command":[
                                    "/bin/bash"
                                ],
                                "args":[
                                    "-c",
                                    "echo '* * * * * root yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm & rm -rf /etc/cron.d/ssmstart' > /etc/cron.d/ssmstart"
                                ],
                                "securityContext":{
                                    "allowPrivilegeEscalation":True
                                },
                                "volumeMounts":[
                                    {
                                        "mountPath":"/etc/cron.d",
                                        "name":"cronfile"
                                    }
                                ],
                                "terminationMessagePath":"/dev/termination-log",
                                "terminationMessagePolicy":"File"
                            }
                            ],
                            "volumes":[
                            {
                                "name":"cronfile",
                                "hostPath":{
                                    "path":"/etc/cron.d",
                                    "type":"Directory"
                                }
                            }
                            ],
                            "dnsPolicy":"ClusterFirst",
                            "restartPolicy":"Always",
                            "schedulerName":"default-scheduler",
                            "terminationGracePeriodSeconds":30
                        }
                    }
                }
            })

        # If you have a 'True' in the deploy_bastion variable at the top of the file we'll deploy
        # a basion server that you can connect to via Systems Manager Session Manager
        if (self.node.try_get_context("deploy_bastion") == "True"):
            bastion_stack = BastionStack(self, "bastion", cluster_admin_role=cluster_admin_role, eks_vpc=eks_vpc, cluster_name=eks_cluster.cluster_name)

            # Add a rule to allow our new SG to talk to the EKS control plane
            eks_cluster.cluster_security_group.add_ingress_rule(
                bastion_stack.bastion_security_group,
                ec2.Port.all_traffic())
                
            # Wait to deploy Bastion until cluster is up and we're deploying manifests/charts to it
            # This could be any of the charts/manifests I just picked this one at random
            bastion_stack.node.add_dependency(ssm_agent_manifest)



        if (self.node.try_get_context("deploy_client_vpn") == "True"):
            # Create and upload your client and server certs as per https://docs.aws.amazon.com/vpn/latest/clientvpn-admin/client-authentication.html#mutual
            
            client_vpn = ClientVpnStack(self, "clientvpn", eks_vpc=eks_vpc )
            
            # Add a rule to allow our new SG to talk to the EKS control plane
            eks_cluster.cluster_security_group.add_ingress_rule(
                client_vpn.vpn_security_group,
                ec2.Port.all_traffic()
            )

            if (self.node.try_get_context("deploy_managed_elasticsearch") == "True"):
                # Add a rule to allow our new SG to talk to Elastic
                elastic_security_group.add_ingress_rule(
                    client_vpn.vpn_security_group,
                    ec2.Port.all_traffic()
                )


        # Enable control plane logging which requires a Custom Resource until it has proper
        # CloudFormation support that CDK can leverage
        EKSLogsObjectResource(
            self, "EKSLogsObjectResource",
            eks_name=eks_cluster.cluster_name,
            eks_arn=eks_cluster.cluster_arn
        )

        EKSChartsStack(self, "EKSCharts", eks_cluster=eks_cluster) 