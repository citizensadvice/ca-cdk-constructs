import os.path

import aws_cdk as core
import aws_cdk.assertions as assertions
from aws_cdk.aws_route53 import HostedZone
from ca_cdk_constructs.edge_services.protected_cloudfront import ProtectedCloudfront
from aws_cdk.cloudformation_include import CfnInclude, CfnIncludeProps

from ca_cdk_constructs.edge_services.waf_stack import WafStack


def test_waf_created():
    app = core.App()
    env = core.Environment(account="12345678901", region="us-east-1")
    zone_stack = core.Stack(app, "ZoneStack", env=env)
    hosted_zone = HostedZone(zone_stack, "Hz", zone_name="test.acme.org.uk")
    cloudfront = ProtectedCloudfront(
        zone_stack,
        "Cdn",
        hosted_zone=hosted_zone,
        origin_domain="foo-lb.some.domain",
        sub_domain="refer",
    )

    waf_stack = WafStack(
            cloudfront,
            "TestWafStack",
            params={
                "ActivateAWSManagedRulesParam": "yes",
                "ActivateSqlInjectionProtectionParam": "yes",
                "ActivateCrossSiteScriptingProtectionParam": "yes",
                "ActivateHttpFloodProtectionParam": "yes - AWS WAF rate based rule",
                "ActivateScannersProbesProtectionParam": "no",
                "ActivateReputationListsProtectionParam": "yes",
                "ActivateBadBotProtectionParam": "no",
            },
            env=env,
            custom_rules=[],
    )
    template = assertions.Template.from_stack(waf_stack)

    # not much we can test for, except that the waf stack has as one of its resource the nested
    # WebACLStack stack from the AWS solution, and that this is using the same params as passed
    # so users of the template will need to do their own testing/checks on the deployed waf
    template.has_resource_properties(
        "AWS::CloudFormation::Stack",
            {"Parameters":
                {
                    "ActivateAWSManagedRulesParam": "yes",
                    "ActivateSqlInjectionProtectionParam": "yes",
                    "ActivateCrossSiteScriptingProtectionParam": "yes",
                    "ActivateHttpFloodProtectionParam": "yes - AWS WAF rate based rule",
                    "ActivateScannersProbesProtectionParam": "no",
                    "ActivateReputationListsProtectionParam": "yes",
                    "ActivateBadBotProtectionParam": "no",
                },
            }
    )

    dirname = os.path.dirname(__file__)

    # TODO - don't think there's much we can test for in the WebACLStack itself, as you can't use
    # Template.from_stack on a stack imported using CfnInclude - you get an error
    # "...  Object of type 'aws-cdk-lib.cloudformation_include.CfnInclude' is not convertible to aws-cdk-lib.Stack"
    # but just in case anyone else can find a way to do it, this is how you'd generate the stack
    nested_waf_stack = CfnInclude(
        waf_stack,
        "TestWafAutomationsTemplate",
        template_file=os.path.join(
            dirname, "waf_assets/aws-waf-security-automations.json"
        ),
        load_nested_stacks={
            "WebACLStack": CfnIncludeProps(
                template_file=os.path.join(dirname, "waf_assets/nested_template.yaml"),
            )
        },
        parameters={
            "ActivateAWSManagedRulesParam": "yes",
            "ActivateSqlInjectionProtectionParam": "yes",
            "ActivateCrossSiteScriptingProtectionParam": "yes",
            "ActivateHttpFloodProtectionParam": "yes - AWS WAF rate based rule",
            "ActivateScannersProbesProtectionParam": "no",
            "ActivateReputationListsProtectionParam": "yes",
            "ActivateBadBotProtectionParam": "no",
        },
    )

    # nested_template = assertions.Template.from_stack(nested_waf_stack)