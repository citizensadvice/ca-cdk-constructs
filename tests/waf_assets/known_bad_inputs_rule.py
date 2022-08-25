import aws_cdk.aws_wafv2 as wafv2

# this is the AWS Managed Rule: AWSManagedRulesKnownBadInputsRuleSet which we include
# in all our WAFs to guard against the log4j vulnerability


def known_bad_inputs_rule():
    return [
        ### AWS managed rule - needed to protect against log4j vulnerability
        wafv2.CfnWebACL.RuleProperty(
            name="AWS-AWSManagedRulesKnownBadInputsRuleSet",
            priority=6,
            statement=wafv2.CfnWebACL.StatementProperty(
                managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                    name="AWSManagedRulesKnownBadInputsRuleSet",
                    vendor_name="AWS",
                )
            ),
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name="AWSManagedRulesKnownBadInputsRuleSet",
                sampled_requests_enabled=True,
            ),
            override_action=wafv2.CfnWebACL.OverrideActionProperty(
                # assigning to none means it will take the default action rather than count.
                none=wafv2.CfnWebACL.CountActionProperty()
            ),
        ),
    ]
