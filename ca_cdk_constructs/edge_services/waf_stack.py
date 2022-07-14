import os.path

from aws_cdk import CfnOutput, Stack
from aws_cdk.cloudformation_include import CfnInclude
from constructs import Construct


class WafStack(Stack):
    # deploys the WAF automations solution stack using the template in the assets/ folder
    def __init__(self, scope: Construct, id: str, params: dict, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        dirname = os.path.dirname(__file__)

        self.waf_stack = CfnInclude(
            self,
            "WafAutomationsTemplate",
            template_file=os.path.join(dirname, "assets/aws-waf-security-automations.json"),
            parameters=params,
        )

    @property
    def acl(self) -> CfnOutput:
        return self.waf_stack.get_output(logical_id="WAFWebACL")

    @property
    def acl_arn(self) -> str:
        return self.waf_stack.get_output(logical_id="WAFWebACLArn").value
