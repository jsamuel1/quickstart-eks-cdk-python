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


class EKSChartsStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, *, eks_cluster, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Install the OPA Gatekeeper
        if (self.node.try_get_context("deploy_opa_gatekeeper") == "True"):
            # For more info see https://github.com/open-policy-agent/gatekeeper
            gatekeeper_chart = eks_cluster.add_helm_chart(
                "gatekeeper",
                chart="gatekeeper",
                version="3.4.0",
                release="gatekeeper",
                repository="https://open-policy-agent.github.io/gatekeeper/charts",
                namespace="kube-system"
            )

        if (self.node.try_get_context("deploy_gatekeeper_policies") == "True"):
            # For more info see https://github.com/aws-quickstart/quickstart-eks-cdk-python/tree/main/gatekeeper-policies
            # and https://github.com/fluxcd/flux/tree/master/chart/flux
            flux_gatekeeper_chart = eks_cluster.add_helm_chart(
                "flux-gatekeeper",
                chart="flux",
                version="1.9.0",
                release="flux-gatekeeper",
                repository="https://charts.fluxcd.io",
                namespace="kube-system",
                values={
                    "git": {
                        "url": self.node.try_get_context("gatekeeper_policies_git_url"),
                        "branch": self.node.try_get_context("gatekeeper_policies_git_branch"),
                        "path": self.node.try_get_context("gatekeeper_policies_git_path")
                    }
                }
            )

