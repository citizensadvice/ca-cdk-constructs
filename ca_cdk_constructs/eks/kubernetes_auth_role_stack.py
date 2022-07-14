from aws_cdk import CfnOutput, Stack
from aws_cdk.aws_iam import AccountRootPrincipal, Role
from constructs import Construct


class KubernetesAuthRoleStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, role_name: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.role = Role(
            self,
            "KubernetesAuthRole",
            assumed_by=AccountRootPrincipal(),
            role_name=role_name,
            description="Role used by the AWS CDK project to authenticate with Kubernetes",
        )

        CfnOutput(self, "K8sAuthRoleName", description="Role name", value=self.role.role_name)
        CfnOutput(self, "K8sAuthRoleArn", description="Role ARN", value=self.role.role_arn)
