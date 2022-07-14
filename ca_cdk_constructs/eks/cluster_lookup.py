from aws_cdk import CfnOutput, Fn, Stack
from aws_cdk.aws_ec2 import IVpc
from aws_cdk.aws_eks import Cluster, ICluster, OpenIdConnectProvider
import aws_cdk.custom_resources as cr
from constructs import Construct


def get_eks_cluster(
    scope: Construct, env_name: str, kubectl_role_arn: str, vpc: IVpc
) -> ICluster:
    """_summary_

    Args:
        scope (Construct): scope
        env_name (str): environment name
        kubectl_role_arn (str): ARN of a role with deployment access to the namespace(s) used in this CDK project
        vpc (IVpc): The cluster VPC

    Returns:
        ICluster: _description_
    """
    cluster_name = {
        "test": "test-eks-controlplane",
        "qa": "devops-eks-controlplane",
        "staging": "prod-eks-controlplane",
        "prod": "prod-eks-controlplane",
    }[env_name]

    describe_cluster_sdk_call = cr.AwsSdkCall(
        service="EKS",
        action="describeCluster",
        physical_resource_id=cr.PhysicalResourceId.of(f"{env_name}ClusterOidcProviderLookup"),
        parameters={"name": cluster_name},
        output_paths=[
            "cluster.identity.oidc.issuer",
            "cluster.resourcesVpcConfig.clusterSecurityGroupId",
        ],
    )

    describe_cluster_cr = cr.AwsCustomResource(
        scope,
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
            f"arn:aws:iam::{Stack.of(scope).account}:oidc-provider/",
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
        scope, "ClusterOIDCProvider", open_id_connect_provider_arn=oidc_provider_arn
    )

    # useful to debug sdk lookup calls
    CfnOutput(scope, "EksClusterSecurityGroupId", value=sg_id)
    CfnOutput(scope, "EksClusterOidcProviderArn", value=oidc_provider_arn)

    return Cluster.from_cluster_attributes(
        scope,
        cluster_name,
        kubectl_role_arn=kubectl_role_arn,
        open_id_connect_provider=oidc_provider,
        cluster_name=cluster_name,
        kubectl_private_subnet_ids=private_subnets,
        kubectl_security_group_id=sg_id,
        vpc=vpc,
    )
