"""
Bastion
"""

from constructs import Construct

from aws_cdk import (
    Stack, 
    RemovalPolicy, 
    CfnOutput, 
    Environment, 
    App,
    aws_ec2 as ec2,
    aws_eks as eks,
    aws_iam as iam,
    aws_elasticsearch as es,
    aws_logs as logs,
    aws_certificatemanager as cm
)
import os

# Import the custom resource to switch on control plane logging from ekslogs_custom_resource.py
from ekslogs_custom_resource import EKSLogsObjectResource

class BastionStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, *, cluster_admin_role, eks_vpc, cluster_name, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # If you have a 'True' in the deploy_bastion variable at the top of the file we'll deploy
        # a basion server that you can connect to via Systems Manager Session Manager
        if (self.node.try_get_context("deploy_bastion") == "True"):
            # Create an Instance Profile for our Admin Role to assume w/EC2
            cluster_admin_role_instance_profile = iam.CfnInstanceProfile(
                self, "ClusterAdminRoleInstanceProfile",
                roles=[cluster_admin_role.role_name]
            )

            # Another way into our Bastion is via Systems Manager Session Manager
            if (self.node.try_get_context("create_new_cluster_admin_role") == "True"):
                cluster_admin_role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore"))

            # Create Bastion
            # Get Latest Amazon Linux AMI
            amzn_linux = ec2.MachineImage.latest_amazon_linux(
                generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2,
                edition=ec2.AmazonLinuxEdition.STANDARD,
                virtualization=ec2.AmazonLinuxVirt.HVM,
                storage=ec2.AmazonLinuxStorage.GENERAL_PURPOSE
                )

            # Create SecurityGroup for bastion
            # export this parameter for use by parent stack
            self.bastion_security_group = ec2.SecurityGroup(
                self, "BastionSecurityGroup",
                vpc=eks_vpc,
                allow_all_outbound=True
            )


            # Create our EC2 instance for bastion
            bastion_instance = ec2.Instance(
                self, "BastionInstance",
                instance_type=ec2.InstanceType(self.node.try_get_context("basiton_node_type")),
                machine_image=amzn_linux,
                role=cluster_admin_role,
                vpc=eks_vpc,
                vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
                security_group=self.bastion_security_group,
                block_devices=[ec2.BlockDevice(device_name="/dev/xvda", volume=ec2.BlockDeviceVolume.ebs(self.node.try_get_context("basiton_disk_size")))]
            )

            # Set up our kubectl and fluxctl
            bastion_instance.user_data.add_commands("curl -o kubectl https://amazon-eks.s3.us-west-2.amazonaws.com/1.20.4/2021-04-12/bin/linux/amd64/kubectl")
            bastion_instance.user_data.add_commands("chmod +x ./kubectl")
            bastion_instance.user_data.add_commands("mv ./kubectl /usr/bin")
            bastion_instance.user_data.add_commands("aws eks update-kubeconfig --name " + cluster_name + " --region " + self.region)
            bastion_instance.user_data.add_commands("curl -o fluxctl https://github.com/fluxcd/flux/releases/download/1.22.1/fluxctl_linux_amd64")
            bastion_instance.user_data.add_commands("chmod +x ./fluxctl")
            bastion_instance.user_data.add_commands("mv ./fluxctl /usr/bin")

