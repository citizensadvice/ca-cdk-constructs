from typing import Optional

import aws_cdk as cdk
import aws_cdk.custom_resources as cr
from aws_cdk import CfnOutput, Fn, Stack
from aws_cdk.aws_ec2 import IVpc
from aws_cdk.aws_eks import Cluster, OpenIdConnectProvider
from aws_cdk.aws_iam import AccountRootPrincipal, IRole, Role
from aws_cdk.lambda_layer_kubectl_v34 import KubectlV34Layer as KubectlLayer
from constructs import Construct


class EksClusterIntegration(Construct):
    """Looks up an existing EKS cluster by name and provisions (or uses an existing) kubectl IAM role needed for deployments to the cluster."""

    def __init__(
        self,
        scope: Construct,
        id: str,
        vpc: IVpc,
        cluster_name: str,
        role_name: Optional[str] = None,
        role: Optional[IRole] = None,
        prune: bool = True,
    ):
        """

        Args:
            scope (Construct): parent Construct
            id (str): id
            vpc (IVpc): EC2 Vpc, needed to lookup the cluster
            cluster_name (str): the name of the EKS cluster
            role_name (str, optional): The name of the kubectl IAM role that will be created to enable deployments to the cluster. Defaults to None.
            role (IRole, optional): Existing kubectl IAM role to use for deployments to the cluster. Either this or role_name must be set. Defaults to None.
            prune (bool, optional): Indicates whether Kubernetes resources added through ``addManifest()`` can be automatically pruned. Defaults to True.

        Raises:
            Exception: if neither or both of role_name, role are set
        """
        super().__init__(scope, id)

        if not bool(role) ^ bool(role_name):
            raise Exception("Either role or role_name must be set")

        self.role = role or Role(
            self,
            "KubernetesAuthRole",
            assumed_by=AccountRootPrincipal(),
            role_name=role_name,
            description="Role used by the AWS CDK project to authenticate with Kubernetes",
        )

        describe_cluster_sdk_call = cr.AwsSdkCall(
            service="EKS",
            action="describeCluster",
            physical_resource_id=cr.PhysicalResourceId.of("DescribeClusterLookup"),
            parameters={"name": cluster_name},
            output_paths=[
                "cluster.identity.oidc.issuer",
                "cluster.resourcesVpcConfig.clusterSecurityGroupId",
            ],
        )

        # we need the OIDC provider in order to deploy Service accounts
        # to the imported cluster
        describe_cluster_cr = cr.AwsCustomResource(
            self,
            "OidcConfigNameLookup",
            on_create=describe_cluster_sdk_call,
            on_update=describe_cluster_sdk_call,
            policy=cr.AwsCustomResourcePolicy.from_sdk_calls(
                resources=cr.AwsCustomResourcePolicy.ANY_RESOURCE
            ),
        )

        oidc_provider_arn = Fn.join(
            "",
            [
                f"arn:aws:iam::{Stack.of(self).account}:oidc-provider/",
                Fn.select(
                    1,
                    Fn.split(
                        "https://",
                        describe_cluster_cr.get_response_field("cluster.identity.oidc.issuer"),
                    ),
                ),
            ],
        )

        sg_id = describe_cluster_cr.get_response_field(
            "cluster.resourcesVpcConfig.clusterSecurityGroupId"
        )

        private_subnets = [s.subnet_id for s in vpc.private_subnets]
        oidc_provider = OpenIdConnectProvider.from_open_id_connect_provider_arn(
            self, "ClusterOIDCProvider", open_id_connect_provider_arn=oidc_provider_arn
        )

        self.cluster = Cluster.from_cluster_attributes(
            self,
            "Resource",
            kubectl_role_arn=self.role.role_arn,
            open_id_connect_provider=oidc_provider,
            cluster_name=cluster_name,
            kubectl_private_subnet_ids=private_subnets,
            kubectl_security_group_id=sg_id,
            kubectl_layer=KubectlLayer(self, "KubectlLayer"),
            vpc=vpc,
            prune=prune,  # https://github.com/aws/aws-cdk/issues/19843
        )

        # Acknowledge missing route table warnings as workaround for https://github.com/aws/aws-cdk/issues/19786#issuecomment-1892761555
        # If the Cluster object starts using the routetable later, this might be causing deployment-time issues, but that's unlikely
        cdk.Annotations.of(self.cluster).acknowledge_warning(
            "@aws-cdk/aws-ec2:noSubnetRouteTableId"
        )

        # useful to debug sdk lookup calls
        CfnOutput(self, "EksClusterSecurityGroupId", value=sg_id)
        CfnOutput(self, "EksClusterOidcProviderArn", value=oidc_provider_arn)

        CfnOutput(self, "K8sAuthRoleName", description="Role name", value=self.role.role_name)
        CfnOutput(self, "K8sAuthRoleArn", description="Role ARN", value=self.role.role_arn)
