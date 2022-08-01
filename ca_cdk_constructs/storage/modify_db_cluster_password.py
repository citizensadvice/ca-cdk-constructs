from os import path
from aws_cdk import Duration, Stack
from constructs import Construct
from aws_cdk.custom_resources import (
    AwsCustomResourcePolicy,
    AwsSdkCall,
    PhysicalResourceId,
    AwsCustomResource,
)
from aws_cdk.aws_iam import PolicyStatement, Effect
from aws_cdk.aws_lambda import Function, Runtime, Code
from aws_cdk.aws_secretsmanager import ISecret


class ModifyDBClusterPassword(Construct):
    """Modifies the master password of an Aurora cluster"""

    LAMBDA_SOURCE_DIR = path.join(
        path.dirname(path.realpath(__file__)), "modify_cluster_password_lambda"
    )

    def __init__(
        self, scope: Construct, id: str, cluster_identifier: str, secret: ISecret
    ) -> None:
        """

        Args:
            scope (Construct): scope
            id (str): id
            cluster_identifier (str): the source RDS cluster identifier
            secret (ISecret): the new Secret to be used with the cloned cluster
        """
        super().__init__(scope, id)

        reset_pass_lambda = Function(
            self,
            "ModifyDBClusterPasswordLambda",
            runtime=Runtime.PYTHON_3_9,
            code=Code.from_asset(path=self.LAMBDA_SOURCE_DIR),
            handler="modify_db_cluster_password.handler",
            environment={
                "secret_name": secret.secret_name,
                "region_name": Stack.of(secret).region,
                "cluster_identifier": cluster_identifier,
            },
        )

        reset_pass_lambda.add_to_role_policy(
            PolicyStatement(
                effect=Effect.ALLOW,
                actions=["rds:ModifyDBCluster"],
                resources=[
                    f"arn:aws:rds:{Stack.of(self).region}:{Stack.of(self).account}:cluster:{cluster_identifier}"
                ],
            )
        )
        secret.grant_read(reset_pass_lambda)

        # trigger the lambda
        AwsCustomResource(
            self,
            "InvokeModifyDBCLusterPasswordLambda",
            resource_type="Custom::ModifyDBClusterPassword",
            policy=(
                AwsCustomResourcePolicy.from_statements(
                    statements=[
                        PolicyStatement(
                            actions=["lambda:InvokeFunction"],
                            effect=Effect.ALLOW,
                            resources=[reset_pass_lambda.function_arn],
                        )
                    ]
                )
            ),
            timeout=Duration.minutes(15),
            on_create=AwsSdkCall(
                service="Lambda",
                action="invoke",
                parameters={
                    "FunctionName": reset_pass_lambda.function_name,
                    "InvocationType": "Event",
                },
                physical_resource_id=PhysicalResourceId.of("ModifyDBCLusterPasswordTrigger"),
            ),
            on_update=AwsSdkCall(
                service="Lambda",
                action="invoke",
                parameters={
                    "FunctionName": reset_pass_lambda.function_name,
                    "InvocationType": "Event",
                },
                physical_resource_id=PhysicalResourceId.of("ModifyDBCLusterPasswordTrigger"),
            ),
        )

        self.lambda_func = reset_pass_lambda
