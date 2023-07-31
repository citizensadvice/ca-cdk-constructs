from constructs import Construct
from aws_cdk import aws_wafv2 as waf, aws_logs as cf_logs, Tags

from ca_cdk_constructs.edge_services.waf_rule_templates import (
    managed_rule_group_property,
    ip_rule_property,
)


class WafV2Builder:
    """
    A builder class that generates a WAFv2 WebACL.

    :param scope: The scope of the construct, i.e the parent stack or construct.
    :param stage: The stage of the construct, i.e dev, test, prod.
    :param name: The name of the WAF ACL.
    :param description: The description of the WAF ACL.
    :param tags: The tags of the WAF ACL. Defaults to {"Component": "WAF", "Stage": stage}.
    :param waf_scope: The scope of the WAF ACL. Defaults to CLOUDFRONT.
    :param log_group: The CloudWatch log group to use for logging. If not included logging will be disabled.
    :param default_action: The default action of the WAF ACL. Defaults to Allow.

    Functions:
    add_custom_rule: Adds a custom rule to the WAFv2 WebACL.
    add_managed_rule: Adds a managed rule to the WAFv2 WebACL.
    build: Builds the WAFv2 WebACL.

    Example:
    ```python

    waf_builder = WafV2Builder(
      Stack(stack),
      stage="test",
      name="TestWaf",
      description="A dummy WAF for testing",
      tags={"Foo": "Bar"},
    )

    waf_builder.add_ip_rule(
        name="TestIp",
        priority=1,
        addresses={"IPV4": ["17.0.0.0.1/24"]},
        allow=True,
        count_only=False,
        cloud_watch_metrics_enabled=False,
    )

    waf = waf_builder.build()
    """

    def __init__(
        self,
        scope: Construct,
        stage: str,
        name: str,
        description: str,
        tags: dict = dict(),
        waf_scope: str = "CLOUDFRONT",
        log_group: cf_logs.LogGroup = None,
        default_action: waf.CfnWebACL.DefaultActionProperty = None,
    ) -> None:
        self.rules = list()
        self.scope = scope
        self.stage = stage
        self.name = name
        self.waf_scope = waf_scope
        self.description = description
        self.log_group = log_group

        if not default_action:
            self.default_action = waf.CfnWebACL.DefaultActionProperty(
                allow=waf.CfnWebACL.AllowActionProperty()
            )

        if log_group:
            self.visibility_config = waf.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name=self.name,
                sampled_requests_enabled=True,
            )
        else:
            self.visibility_config = waf.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=False,
                metric_name=self.name,
                sampled_requests_enabled=False,
            )

        self.tags = tags | {"Component": "WAF", "Stage": stage}

    def add_custom_rule(self, rule: waf.CfnWebACL.RuleProperty) -> None:
        self.rules.append(rule)

    def add_managed_rule(
        self,
        name: str,
        priority: int,
        managed_rule_name: str,
        managed_rule_vendor: str,
        count_only: bool = False,
        rules_to_exclude: list[str] = [],
        cloud_watch_metrics_enabled: bool = False,
    ) -> None:
        """
        Adds a managed rule to the WAFv2 WebACL.

        :param name: The name of the rule.
        :param priority: The priority of the rule.
        :param managed_rule_name: The managed rule name.
        :param managed_rule_vendor: The managed rule vendor.
        :param count_only: Whether to only count the requests. Defaulse to False
        :param rules_to_exclude: A list of rules to exclude. Defaults to an empty list.
        :param cloud_watch_metrics_enabled: Whether to enable CloudWatch metrics. Defaults to False.
        """
        self.rules.append(
            managed_rule_group_property(
                name,
                priority,
                managed_rule_name,
                managed_rule_vendor,
                count_only,
                rules_to_exclude,
                cloud_watch_metrics_enabled,
            )
        )

    def add_ip_rule(
        self,
        name: str,
        priority: int,
        addresses: dict[str, list[str]],
        allow: bool = False,
        count_only: bool = False,
        cloud_watch_metrics_enabled: bool = False,
    ) -> None:
        """
        Adds an IP rule to the WAFv2 WebACL.

        :param name: The name of the rule.
        :param priority: The priority of the rule.
        :param addresses: The addresses to use. A dictionary of address types to addresses.
        :param allow: Whether to allow or block the addresses. Defaults to False.
        :param count_only: Whether to only count the requests. Defaulse to False
        :param cloud_watch_metrics_enabled: Whether to enable CloudWatch metrics. Defaults to False.
        """
        self.rules.append(
            ip_rule_property(
                self.scope,
                name,
                priority,
                addresses,
                allow,
                count_only,
                cloud_watch_metrics_enabled,
            )
        )

    def build(self) -> waf.CfnWebACL:
        """
        Builds the WAFv2 WebACL.
        """

        web_acl = waf.CfnWebACL(
            self.scope,
            self.name,
            name=self.name,
            description=self.description,
            default_action=self.default_action,
            scope=self.waf_scope,
            visibility_config=self.visibility_config,
            rules=self.rules,
        )
        for key, value in self.tags.items():
            Tags.of(web_acl).add(key, value)

        if self.log_group:
            self.logging_config = waf.CfnLoggingConfiguration(
                self.scope,
                f"{self.name}LogConfig",
                log_destination_configs=[web_acl.attr_arn],
                resource_arn=web_acl.attr_arn,
            )

        return web_acl
