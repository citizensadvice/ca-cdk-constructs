import os.path

from aws_cdk import CfnOutput, Stack, PhysicalName, RemovalPolicy, Duration
from aws_cdk.cloudformation_include import CfnInclude, CfnIncludeProps
from aws_cdk import aws_wafv2 as wafv2
from constructs import Construct
from typing import Optional

from ca_cdk_constructs.edge_services.waf_assets.known_bad_inputs_rule import (
    known_bad_inputs_rule,
)

# Priority order set here: manually added rules...
# 5: custom_casebook_whitelist
# 6: aws known bad inputs rule

# ... and from aws solution (leave 2-9 for custom rules)
# 0: whitelist
# 1: blacklist
# 10: aws core managed rule
# 11: flood rule
# 12: flood rule
# 13: scanners & probes
# 14: reputation list
#
# 20: sql injection - set to COUNT
# 30: cross-site scripting (xss) - set to COUNT


class WafStack(Stack):
    # deploys the WAF automations solution stack using the template in the assets/ folder
    def __init__(
        self,
        scope: Construct,
        id: str,
        params: dict,
        custom_rules: Optional[wafv2.CfnWebACL.RuleProperty] = [],
        **kwargs,
    ) -> None:
        super().__init__(scope, id, **kwargs)

        dirname = os.path.dirname(__file__)

        self.waf_stack = CfnInclude(
            self,
            "WafAutomationsTemplate",
            template_file=os.path.join(
                dirname, "waf_assets/aws-waf-security-automations.json"
            ),
            load_nested_stacks={
                "WebACLStack": CfnIncludeProps(
                    template_file=os.path.join(dirname, "waf_assets/nested_template.yaml"),
                )
            },
            parameters=params,
        )

        # retrieve the nested waf stack
        nested_waf_stack = self.waf_stack.get_nested_stack("WebACLStack")
        # retrieve the waf web acl resource, and access its rules attribute
        web_acl = nested_waf_stack.included_template.get_resource(logical_id="WAFWebACL")
        rules = web_acl.rules
        # need to add aws managed known bad inputs rule
        web_acl.rules += list(known_bad_inputs_rule())
        # need to add any user-supplied custom rules
        web_acl.rules += custom_rules

    @property
    def acl(self) -> CfnOutput:
        return self.waf_stack.get_output(logical_id="WAFWebACL")
