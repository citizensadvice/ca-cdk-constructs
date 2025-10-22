import typing
from typing import Any, Dict, Optional, Sequence

from aws_cdk import IResolvable, aws_logs as cf_logs, aws_wafv2 as waf
from constructs import Construct

from ca_cdk_constructs.edge_services.waf_rule_templates import (
    ip_rule_property,
    managed_rule_group_property,
    restricted_uri_string_property,
)


class WafV2Builder:
    """
    A builder class that generates a WAFv2 WebACL.

    :param scope: The scope of the construct, i.e the parent stack or construct.
    :param name: The name of the WAF ACL.
    :param description: The description of the WAF ACL.
    :param waf_scope: The scope of the WAF ACL. Defaults to CLOUDFRONT.
    :param log_group: The CloudWatch log group to use for logging. Log group name MUST start with 'aws-waf-logs-'. If not included logging will be disabled.
    :param default_action: The default action of the WAF ACL. Defaults to Allow.

    Functions:
    add_custom_rule: Adds a custom rule to the WAFv2 WebACL.
    add_managed_rule: Adds a managed rule to the WAFv2 WebACL.
    add_ip_rule: Adds an IP rule to the WAFv2 WebACL.
    add_restricted_uri_string_rule: Adds a rule to the WAFv2 WebACL that restricts access to specific URIs to specific IP addresses
    get_rules: Returns the list of rules added to the WAFv2 WebACL.
    build: Builds the WAFv2 WebACL.

    Example:
    ```python

    waf_builder = WafV2Builder(
      self,
      name="TestWaf",
      description="A dummy WAF for testing",
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
        name: str,
        description: str,
        waf_scope: str = "CLOUDFRONT",
        log_group: Optional[cf_logs.LogGroup] = None,
        default_action: Optional[waf.CfnWebACL.DefaultActionProperty] = None,
    ) -> None:
        self.rules: typing.List[waf.CfnWebACL.RuleProperty] = []
        self.scope = scope
        self.waf_scope = waf_scope
        self.name = name
        self.description = description
        self.log_group = log_group

        if not default_action:
            self.default_action = waf.CfnWebACL.DefaultActionProperty(
                allow=waf.CfnWebACL.AllowActionProperty()
            )

        if self.log_group:
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

    def add_custom_rule(self, rule: waf.CfnWebACL.RuleProperty) -> None:
        """
        Adds a custom rule to the WAFv2 WebACL.

        :param rule: The rule to add.
        """
        self.rules.append(rule)

    def add_managed_rule(
        self,
        name: str,
        priority: int,
        managed_rule_name: str,
        managed_rule_vendor: str,
        count_only: Optional[bool] = False,
        rules_to_exclude: Optional[list[str]] = [],
        cloud_watch_metrics_enabled: Optional[bool] = False,
        managed_rule_group_configs: IResolvable
        | Sequence[IResolvable | waf.CfnWebACL.ManagedRuleGroupConfigProperty | Dict[str, Any]]
        | None = None,
    ) -> None:
        """
        Adds a managed rule to the WAFv2 WebACL.

        :param name: The name of the rule.
        :param priority: The priority of the rule.
        :param managed_rule_name: The managed rule name.
        :param managed_rule_vendor: The managed rule vendor.
        :param count_only: Whether to only count the requests. Defaults to False
        :param rules_to_exclude: A list of rules to exclude. Defaults to an empty list.
        :param cloud_watch_metrics_enabled: Whether to enable CloudWatch metrics. Defaults to False.
        :param managed_rule_group_configs: Additional information that's used by a managed rule group. Many managed rule groups don't require this. The rule groups used for intelligent threat mitigation require additional configuration.
        """
        self.rules.append(
            managed_rule_group_property(
                name,
                priority,
                managed_rule_name,
                managed_rule_vendor,
                count_only or False,
                rules_to_exclude or [],
                cloud_watch_metrics_enabled or False,
                managed_rule_group_configs,
            )
        )

    def add_ip_rule(
        self,
        name: str,
        priority: int,
        addresses: dict[str, list[str]],
        allow: Optional[bool] = False,
        count_only: Optional[bool] = False,
        cloud_watch_metrics_enabled: Optional[bool] = False,
    ) -> None:
        """
        Adds an IP rule to the WAFv2 WebACL.

        :param name: The name of the rule.
        :param priority: The priority of the rule.
        :param addresses: The addresses to use. A dictionary of address types to addresses.
        :param allow: Whether to allow or block the addresses. Defaults to False.
        :param count_only: Whether to only count the requests. Defaults to False
        :param cloud_watch_metrics_enabled: Whether to enable CloudWatch metrics. Defaults to False.
        """
        self.rules.append(
            ip_rule_property(
                self.scope,
                name,
                priority,
                addresses,
                allow or False,
                count_only or False,
                cloud_watch_metrics_enabled or False,
                waf_scope=self.waf_scope,
            )
        )

    def add_restricted_uri_string_rule(
        self,
        name: str,
        priority: int,
        restricted_uri_string: str,
        allowed_addresses: dict[str, list[str]] = {},
        count_only: Optional[bool] = False,
        cloud_watch_metrics_enabled: Optional[bool] = False,
    ) -> None:
        """
        Adds an IP rule to the WAFv2 WebACL.

        :param name: The name of the rule.
        :param priority: The priority of the rule.
        :param restricted_uri_string: Any URI containing this string will be blocked except to allowed_addresses
        :param allowed_addresses: The addresses to use. A dictionary of address types to addresses.
        :param count_only: Whether to only count the requests. Defaults to False
        :param cloud_watch_metrics_enabled: Whether to enable CloudWatch metrics. Defaults to False.
        """
        self.rules.append(
            restricted_uri_string_property(
                self.scope,
                name,
                priority,
                restricted_uri_string,
                allowed_addresses,
                count_only or False,
                cloud_watch_metrics_enabled or False,
            )
        )

    def get_rules(self) -> list[waf.CfnWebACL.RuleProperty]:
        """
        Returns the list of rules that have been added to the builder.
        """
        return self.rules

    def build(self) -> waf.CfnWebACL:
        """
        Builds the WAFv2 WebACL.
        """

        web_acl = waf.CfnWebACL(
            self.scope,
            "Default",
            name=self.name,
            description=self.description,
            default_action=self.default_action,
            scope=self.waf_scope,
            visibility_config=self.visibility_config,
            rules=self.rules,
        )

        if self.log_group:
            self.logging_config = waf.CfnLoggingConfiguration(
                self.scope,
                f"{self.name}LogConfig",
                log_destination_configs=[self.log_group.log_group_arn],
                resource_arn=web_acl.attr_arn,
            )

        return web_acl
