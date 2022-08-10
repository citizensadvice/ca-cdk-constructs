import os

from aws_cdk.aws_lambda import Runtime
from aws_cdk.aws_lambda_python_alpha import PythonLayerVersion
from constructs import Construct
from ca_cdk_constructs.aws_lambda.layers import LAMBDA_LAYER_DIR

class Boto3LambdaLayer(Construct):
    def __init__(self, scope: Construct, id: str):
        super().__init__(scope, id)
        self.layer = PythonLayerVersion(
            self,
            "Layer",
            entry=os.path.join(LAMBDA_LAYER_DIR, "boto3"),
            compatible_runtimes=[Runtime.PYTHON_3_9],
        )
