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

class ClientVPNStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, *, eks_vpc, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        eks_vpc = kwargs.get('eks_vpc')
        if (self.node.try_get_context("deploy_client_vpn") == "True"):
            # Create and upload your client and server certs as per https://docs.aws.amazon.com/vpn/latest/clientvpn-admin/client-authentication.html#mutual
            # And then put the ARNs for them into the items below
            client_cert = cm.Certificate.from_certificate_arn(
                self, "ClientCert",
                certificate_arn=self.node.try_get_context("vpn_client_certificate_arn"))
            server_cert = cm.Certificate.from_certificate_arn(
                self, "ServerCert",
                certificate_arn=self.node.try_get_context("vpn_server_certificate_arn"))

            # Create SecurityGroup for VPN
            self.vpn_security_group = ec2.SecurityGroup(
                self, "VPNSecurityGroup",
                vpc=eks_vpc,
                allow_all_outbound=True
            )

            # Create CloudWatch Log Group and Stream and keep the logs for 1 month
            log_group = logs.LogGroup(
                self, "VPNLogGroup",
                retention=logs.RetentionDays.ONE_MONTH
            )
            log_stream = log_group.add_stream("VPNLogStream")

            endpoint = ec2.CfnClientVpnEndpoint(
                self, "VPNEndpoint",
                description="EKS Client VPN",
                authentication_options=[{
                    "type": "certificate-authentication",
                    "mutualAuthentication": {
                        "clientRootCertificateChainArn": client_cert.certificate_arn
                    }
                }],
                client_cidr_block=self.node.try_get_context("vpn_client_cidr_block"),
                server_certificate_arn=server_cert.certificate_arn,
                connection_log_options={
                    "enabled": True,
                    "cloudwatchLogGroup": log_group.log_group_name,
                    "cloudwatchLogStream": log_stream.log_stream_name
                },
                split_tunnel=True,
                security_group_ids=[self.vpn_security_group.security_group_id],
                vpc_id=eks_vpc.vpc_id
            )

            ec2.CfnClientVpnAuthorizationRule(
                self, "ClientVpnAuthRule",
                client_vpn_endpoint_id=endpoint.ref,
                target_network_cidr=eks_vpc.vpc_cidr_block,
                authorize_all_groups=True,
                description="Authorize the Client VPN access to our VPC CIDR"
            )

            ec2.CfnClientVpnTargetNetworkAssociation(
                self, "ClientVpnNetworkAssociation",
                client_vpn_endpoint_id=endpoint.ref,
                subnet_id=eks_vpc.private_subnets[0].subnet_id
            )
