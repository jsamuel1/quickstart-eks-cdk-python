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
)

class CalicoNetworkProviderStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, *, eks_cluster, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)


        # Install Calico to enforce NetworkPolicies
        if (self.node.try_get_context("deploy_calico_np") == "True"):
            # For more info see https://docs.aws.amazon.com/eks/latest/userguide/calico.html 
            # and https://github.com/aws/amazon-vpc-cni-k8s/tree/master/charts/aws-calico

            # First we need to install the CRDs which are not part of the Chart
            calico_crds_manifest_1 = eks_cluster.add_manifest("CalicoCRDManifest1",            
                {
                "apiVersion": "apiextensions.k8s.io/v1beta1",
                "kind": "CustomResourceDefinition",
                "metadata": {
                    "name": "felixconfigurations.crd.projectcalico.org"
                },
                "spec": {
                    "scope": "Cluster",
                    "group": "crd.projectcalico.org",
                    "versions": [
                    {
                        "name": "v1",
                        "served": True,
                        "storage": True
                    }
                    ],
                    "names": {
                    "kind": "FelixConfiguration",
                    "plural": "felixconfigurations",
                    "singular": "felixconfiguration"
                    }
                }
                })
            calico_crds_manifest_2 = eks_cluster.add_manifest("CalicoCRDManifest2",
                {
                "apiVersion": "apiextensions.k8s.io/v1beta1",
                "kind": "CustomResourceDefinition",
                "metadata": {
                    "name": "ipamblocks.crd.projectcalico.org"
                },
                "spec": {
                    "scope": "Cluster",
                    "group": "crd.projectcalico.org",
                    "versions": [
                    {
                        "name": "v1",
                        "served": True,
                        "storage": True
                    }
                    ],
                    "names": {
                    "kind": "IPAMBlock",
                    "plural": "ipamblocks",
                    "singular": "ipamblock"
                    }
                }
                })
            calico_crds_manifest_3 = eks_cluster.add_manifest("CalicoCRDManifest3",            
                {
                "apiVersion": "apiextensions.k8s.io/v1beta1",
                "kind": "CustomResourceDefinition",
                "metadata": {
                    "name": "blockaffinities.crd.projectcalico.org"
                },
                "spec": {
                    "scope": "Cluster",
                    "group": "crd.projectcalico.org",
                    "versions": [
                    {
                        "name": "v1",
                        "served": True,
                        "storage": True
                    }
                    ],
                    "names": {
                    "kind": "BlockAffinity",
                    "plural": "blockaffinities",
                    "singular": "blockaffinity"
                    }
                }
                })
            calico_crds_manifest_4 = eks_cluster.add_manifest("CalicoCRDManifest4",
                {
                "apiVersion": "apiextensions.k8s.io/v1beta1",
                "kind": "CustomResourceDefinition",
                "metadata": {
                    "name": "bgpconfigurations.crd.projectcalico.org"
                },
                "spec": {
                    "scope": "Cluster",
                    "group": "crd.projectcalico.org",
                    "versions": [
                    {
                        "name": "v1",
                        "served": True,
                        "storage": True
                    }
                    ],
                    "names": {
                    "kind": "BGPConfiguration",
                    "plural": "bgpconfigurations",
                    "singular": "bgpconfiguration"
                    }
                }
                })
            calico_crds_manifest_5 = eks_cluster.add_manifest("CalicoCRDManifest5",
                {
                "apiVersion": "apiextensions.k8s.io/v1beta1",
                "kind": "CustomResourceDefinition",
                "metadata": {
                    "name": "bgppeers.crd.projectcalico.org"
                },
                "spec": {
                    "scope": "Cluster",
                    "group": "crd.projectcalico.org",
                    "versions": [
                    {
                        "name": "v1",
                        "served": True,
                        "storage": True
                    }
                    ],
                    "names": {
                    "kind": "BGPPeer",
                    "plural": "bgppeers",
                    "singular": "bgppeer"
                    }
                }
                })
            calico_crds_manifest_6 = eks_cluster.add_manifest("CalicoCRDManifest6",
                {
                "apiVersion": "apiextensions.k8s.io/v1beta1",
                "kind": "CustomResourceDefinition",
                "metadata": {
                    "name": "ippools.crd.projectcalico.org"
                },
                "spec": {
                    "scope": "Cluster",
                    "group": "crd.projectcalico.org",
                    "versions": [
                    {
                        "name": "v1",
                        "served": True,
                        "storage": True
                    }
                    ],
                    "names": {
                    "kind": "IPPool",
                    "plural": "ippools",
                    "singular": "ippool"
                    }
                }
                })
            calico_crds_manifest_7 = eks_cluster.add_manifest("CalicoCRDManifest7",
                {
                "apiVersion": "apiextensions.k8s.io/v1beta1",
                "kind": "CustomResourceDefinition",
                "metadata": {
                    "name": "hostendpoints.crd.projectcalico.org"
                },
                "spec": {
                    "scope": "Cluster",
                    "group": "crd.projectcalico.org",
                    "versions": [
                    {
                        "name": "v1",
                        "served": True,
                        "storage": True
                    }
                    ],
                    "names": {
                    "kind": "HostEndpoint",
                    "plural": "hostendpoints",
                    "singular": "hostendpoint"
                    }
                }
                })
            calico_crds_manifest_8 = eks_cluster.add_manifest("CalicoCRDManifest8",
                {
                "apiVersion": "apiextensions.k8s.io/v1beta1",
                "kind": "CustomResourceDefinition",
                "metadata": {
                    "name": "clusterinformations.crd.projectcalico.org"
                },
                "spec": {
                    "scope": "Cluster",
                    "group": "crd.projectcalico.org",
                    "versions": [
                    {
                        "name": "v1",
                        "served": True,
                        "storage": True
                    }
                    ],
                    "names": {
                    "kind": "ClusterInformation",
                    "plural": "clusterinformations",
                    "singular": "clusterinformation"
                    }
                }
                })
            calico_crds_manifest_9 = eks_cluster.add_manifest("CalicoCRDManifest9",
                {
                "apiVersion": "apiextensions.k8s.io/v1beta1",
                "kind": "CustomResourceDefinition",
                "metadata": {
                    "name": "globalnetworkpolicies.crd.projectcalico.org"
                },
                "spec": {
                    "scope": "Cluster",
                    "group": "crd.projectcalico.org",
                    "versions": [
                    {
                        "name": "v1",
                        "served": True,
                        "storage": True
                    }
                    ],
                    "names": {
                    "kind": "GlobalNetworkPolicy",
                    "plural": "globalnetworkpolicies",
                    "singular": "globalnetworkpolicy"
                    }
                }
                })
            calico_crds_manifest_10 = eks_cluster.add_manifest("CalicoCRDManifest10",
                {
                "apiVersion": "apiextensions.k8s.io/v1beta1",
                "kind": "CustomResourceDefinition",
                "metadata": {
                    "name": "globalnetworksets.crd.projectcalico.org"
                },
                "spec": {
                    "scope": "Cluster",
                    "group": "crd.projectcalico.org",
                    "versions": [
                    {
                        "name": "v1",
                        "served": True,
                        "storage": True
                    }
                    ],
                    "names": {
                    "kind": "GlobalNetworkSet",
                    "plural": "globalnetworksets",
                    "singular": "globalnetworkset"
                    }
                }
                })
            calico_crds_manifest_11 = eks_cluster.add_manifest("CalicoCRDManifest11",
                {
                "apiVersion": "apiextensions.k8s.io/v1beta1",
                "kind": "CustomResourceDefinition",
                "metadata": {
                    "name": "networkpolicies.crd.projectcalico.org"
                },
                "spec": {
                    "scope": "Namespaced",
                    "group": "crd.projectcalico.org",
                    "versions": [
                    {
                        "name": "v1",
                        "served": True,
                        "storage": True
                    }
                    ],
                    "names": {
                    "kind": "NetworkPolicy",
                    "plural": "networkpolicies",
                    "singular": "networkpolicy"
                    }
                }
                })
            calico_crds_manifest_12 = eks_cluster.add_manifest("CalicoCRDManifest12",
                {
                "apiVersion": "apiextensions.k8s.io/v1beta1",
                "kind": "CustomResourceDefinition",
                "metadata": {
                    "name": "networksets.crd.projectcalico.org"
                },
                "spec": {
                    "scope": "Namespaced",
                    "group": "crd.projectcalico.org",
                    "versions": [
                    {
                        "name": "v1",
                        "served": True,
                        "storage": True
                    }
                    ],
                    "names": {
                    "kind": "NetworkSet",
                    "plural": "networksets",
                    "singular": "networkset"
                    }
                }
                })
            # Then we can install the Helm Chart
            calico_np_chart = eks_cluster.add_helm_chart(
                "calico",
                chart="aws-calico",
                version="0.3.4",
                release="calico",
                repository="https://aws.github.io/eks-charts",
                namespace="kube-system"
            )
            # The Helm Chart depends on all the CRDs
            calico_np_chart.node.add_dependency(calico_crds_manifest_1)
            calico_np_chart.node.add_dependency(calico_crds_manifest_2)
            calico_np_chart.node.add_dependency(calico_crds_manifest_3)
            calico_np_chart.node.add_dependency(calico_crds_manifest_4)
            calico_np_chart.node.add_dependency(calico_crds_manifest_5)
            calico_np_chart.node.add_dependency(calico_crds_manifest_6)
            calico_np_chart.node.add_dependency(calico_crds_manifest_7)
            calico_np_chart.node.add_dependency(calico_crds_manifest_8)
            calico_np_chart.node.add_dependency(calico_crds_manifest_9)
            calico_np_chart.node.add_dependency(calico_crds_manifest_10)
            calico_np_chart.node.add_dependency(calico_crds_manifest_11)
            calico_np_chart.node.add_dependency(calico_crds_manifest_12)

