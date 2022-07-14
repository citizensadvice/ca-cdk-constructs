from aws_cdk import CfnOutput, Fn, Stack
from aws_cdk.aws_ec2 import IVpc
from aws_cdk.aws_eks import Cluster, OpenIdConnectProvider
from aws_cdk.aws_iam import Role, AccountRootPrincipal
import aws_cdk.custom_resources as cr
from constructs import Construct


class EksClusterIntegration(Construct):
    """Looks up an existing EKS cluster by name and provisions the kubectl IAM role needed for deployments to the cluster."""

    def __init__(self, scope: Construct, id: str, vpc: IVpc, cluster_name: str):
        super().__init__(scope, id)

        self.role = Role(
            self,
            "KubernetesAuthRole",
            assumed_by=AccountRootPrincipal(),
            description="Role used by the AWS CDK project to authenticate with Kubernetes",
        )

        describe_cluster_sdk_call = cr.AwsSdkCall(
            service="EKS",
            action="describeCluster",
            physical_resource_id=cr.PhysicalResourceId.of("ClusterOidcProviderLookup"),
            parameters={"name": cluster_name},
            output_paths=[
                "cluster.identity.oidc.issuer",
                "cluster.resourcesVpcConfig.clusterSecurityGroupId",
            ],
        )

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

        private_subnets = list(map(lambda s: s.subnet_id, vpc.private_subnets))
        oidc_provider = OpenIdConnectProvider.from_open_id_connect_provider_arn(
            self, "ClusterOIDCProvider", open_id_connect_provider_arn=oidc_provider_arn
        )

        self.cluster = Cluster.from_cluster_attributes(
            self,
            cluster_name,
            kubectl_role_arn=self.role.role_arn,
            open_id_connect_provider=oidc_provider,
            cluster_name=cluster_name,
            kubectl_private_subnet_ids=private_subnets,
            kubectl_security_group_id=sg_id,
            vpc=vpc,
        )

        # useful to debug sdk lookup calls
        CfnOutput(self, "EksClusterSecurityGroupId", value=sg_id)
        CfnOutput(self, "EksClusterOidcProviderArn", value=oidc_provider_arn)

        CfnOutput(self, "K8sAuthRoleName", description="Role name", value=self.role.role_name)
        CfnOutput(self, "K8sAuthRoleArn", description="Role ARN", value=self.role.role_arn)
