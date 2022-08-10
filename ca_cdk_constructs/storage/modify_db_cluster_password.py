import json
import os
from os import path

from aws_cdk import Duration, Stack
from aws_cdk.aws_iam import PolicyStatement, Effect
from aws_cdk.aws_lambda import Runtime
from aws_cdk.aws_lambda_python_alpha import PythonLayerVersion, PythonFunction
from aws_cdk.aws_secretsmanager import ISecret
from aws_cdk.custom_resources import (
    AwsCustomResourcePolicy,
    AwsSdkCall,
    PhysicalResourceId,
    AwsCustomResource,
)
from constructs import Construct

from ca_cdk_constructs.aws_lambda.layers.boto3 import Boto3LambdaLayer


class ModifyDBClusterPassword(Construct):
    """Creates a lambda that modifies the master password of an Aurora cluster.
    The cluster identifier and SSM secret name must be passed to the lambda at invocation time.
    It expects the event to contain:
    ```
    {
      "cluster_id",
      "secret_name"
    }
    ```

    Invoking the lambda can be done by calling `trigger_on_create_update()` which would invoke the lambda when the lambda stack is created or updated:

    ``
    cluster_id = ....
    new_db_secret = ...

    modify_cluster_password = ModifyDBClusterPassword(self, "ModifyClusterPassword", cluster_id=cluster_id, secret=new_db_secret)
    modify_cluster_password.trigger_on_create_update()

    ```

    To use the lambda in Step Functions:

    ```
    cluster_id = ....
    new_db_secret = ...

    modify_cluster_password = ModifyDBClusterPassword(self, "ModifyClusterPassword", cluster_id=cluster_id, secret: new_db_secret)

    reset_clone_password_task = LambdaInvoke(
        self,
        "ModifyClusterPasswordLambdaInvocation",
        lambda_function=modify_cluster_password.lambda_funct,
        payload=TaskInput.from_object(
            {
                "secret_name": new_db_secret.secret_name,
                "cluster_identifier": cluster_id,
            }
        ),
    )

    # add reset_clone_password_task to the state machine definition
    ```
    """

    LAMBDA_SOURCE_DIR = path.join(
        path.dirname(path.realpath(__file__)), "modify_cluster_password_lambda"
    )

    def __init__(self, scope: Construct, id: str, cluster_id: str, secret: ISecret) -> None:
        super().__init__(scope, id)

        self.cluster_id = cluster_id
        self.secret_name = secret.secret_name

        boto3_lambda_layer = Boto3LambdaLayer(self, "BotoLayer").layer

        self.lambda_funct = PythonFunction(
            self,
            "ModifyDBClusterPasswordLambda",
            runtime=Runtime.PYTHON_3_9,
            layers=[boto3_lambda_layer],
            entry=self.LAMBDA_SOURCE_DIR,
            index="modify_db_cluster_password.py",
            handler="handler",
        )

        secret.grant_read(self.lambda_funct)
        secret.grant_write(self.lambda_funct)

        self.lambda_funct.add_to_role_policy(
            PolicyStatement(
                effect=Effect.ALLOW,
                actions=["rds:ModifyDBCluster"],
                resources=[
                    f"arn:aws:rds:{Stack.of(self).region}:{Stack.of(self).account}:cluster:{cluster_id}"
                ],
            )
        )

    def trigger_on_create_update(self):
        aws_call = AwsSdkCall(
            service="Lambda",
            action="invoke",
            parameters={
                "FunctionName": self.reset_pass_lambda.function_name,
                "InvocationType": "Event",
                "Payload": json.dumps(
                    {
                        "Payload": {
                            "secret_name": self.secret_name,
                            "cluster_identifier": self.cluster_id,
                        },
                        "FunctionName": self.reset_pass_lambda.function_name,
                        "InvocationType": "Event",
                    }
                ),
            },
            physical_resource_id=PhysicalResourceId.of("ModifyDBCLusterPasswordTrigger"),
        )

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
                            resources=[self.reset_pass_lambda.function_arn],
                        )
                    ]
                )
            ),
            timeout=Duration.minutes(15),
            on_create=aws_call,
            on_update=aws_call,
        )
