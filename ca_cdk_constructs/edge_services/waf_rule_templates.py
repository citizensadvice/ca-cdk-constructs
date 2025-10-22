from typing import Any, Dict, Optional, Sequence

from aws_cdk import IResolvable, aws_wafv2 as waf

###################################################################
# A COLLECTION OF HELPER FUNCTIONS FOR GENERATING AWS WAFV2 RULES #
###################################################################

# Note for developers: These rule builder functions are used within
# the WAF builder class. If you change any interfaces or make any
# major changes to these functions, please update the WAF builder
# class to match, including the docstrings.


def managed_rule_group_property(
    name: str,
    priority: int,
    managed_rule_name: str,
    managed_rule_vendor: str,
    count_only: bool = False,
    rules_to_exclude: list[str] = [],
    cloud_watch_metrics_enabled: bool = False,
    managed_rule_group_configs: IResolvable
    | Sequence[IResolvable | waf.CfnWebACL.ManagedRuleGroupConfigProperty | Dict[str, Any]]
    | None = None,
) -> waf.CfnWebACL.RuleProperty:
    """A wrapper that returns an `aws_wafv2.CfnWebACL.RuleProperty` object to be used in a list and passed to the CfnWebACL instance

    :param name: The name of the rule. You can't change the name of a Rule after you create it.
    :param priority: If you define more than one Rule in a WebACL , AWS WAF evaluates each request against the Rules in order based on the value of Priority . AWS WAF processes rules with lower priority first. The priorities don't need to be consecutive, but they must all be different.
    :param managed_rule_name: The name of the managed rule group. You use this, along with the vendor name, to identify the rule group.
    :param managed_rule_vendor: The name of the managed rule group vendor. You use this, along with the rule group name, to identify a rule group.
    :param count_only: Set to True to only count and not take action on matching requests, defaults to False.
    :param rules_to_exclude: A list of str names of individual rules to ignore (set to COUNT) within the managed rule group, defaults to [].
    :param cloudwatch_metrics_enabled: Set to True to enable logging via Cloudwatch, defaults to False.
    :param managed_rule_group_configs: Additional information that's used by a managed rule group. Many managed rule groups don't require this. The rule groups used for intelligent threat mitigation require additional configuration.
    :return: aws_cdk.aws_wafv2.CfnWebACL.RuleProperty.

    :example:
    ```
    managed_rule_reference(
        name=f"{scope.stack_name}CommonRuleSet",
        priority=2,
        managed_rule_name="AWSManagedRulesCommonRuleSet",
        managed_rule_vendor="AWS",
        rules_to_exclude=[
            "NoUserAgent_HEADER",
            "SizeRestrictions_BODY"
        ],
        count_only=True,
    ),
    """

    if count_only:
        override = waf.CfnWebACL.OverrideActionProperty(count={})
    else:
        override = waf.CfnWebACL.OverrideActionProperty(none={})

    # any specific rules to be excluded (set to COUNT) in the rulegroup
    rule_action_overrides = []
    for rule_name in rules_to_exclude:
        rule_action_overrides += [
            waf.CfnWebACL.RuleActionOverrideProperty(
                action_to_use=waf.CfnWebACL.RuleActionProperty(
                    count=waf.CfnWebACL.CountActionProperty()
                ),
                name=rule_name,
            )
        ]

    return waf.CfnWebACL.RuleProperty(
        name=f"{name}Rule",
        priority=priority,
        visibility_config=waf.CfnWebACL.VisibilityConfigProperty(
            cloud_watch_metrics_enabled=cloud_watch_metrics_enabled,
            metric_name=f"{name}Metric",
            sampled_requests_enabled=True,
        ),
        action=None,
        override_action=override,
        statement=waf.CfnWebACL.StatementProperty(
            managed_rule_group_statement=waf.CfnWebACL.ManagedRuleGroupStatementProperty(
                name=managed_rule_name,
                vendor_name=managed_rule_vendor,
                # overrides for individual rules within the group
                rule_action_overrides=rule_action_overrides,
                managed_rule_group_configs=managed_rule_group_configs,
            )
        ),
    )


def ip_rule_property(
    scope,
    name: str,
    priority: int,
    addresses: dict[str, list[str]] = {},
    allow: bool = False,
    count_only: bool = False,
    cloud_watch_metrics_enabled: bool = False,
    waf_scope: str = "CLOUDFRONT",
) -> waf.CfnWebACL.RuleProperty:
    """A wrapper that returns an `aws_wafv2.CfnWebACL.RuleProperty` object to be used in a list and passed to the CfnWebACL instance.

    :param scope: `self`, scope in which this resource is defined.
    :param name: The name of the rule. You can't change the name of a Rule after you create it.
    :param priority: If you define more than one Rule in a WebACL , AWS WAF evaluates each request against the Rules in order based on the value of Priority . AWS WAF processes rules with lower priority first. The priorities don't need to be consecutive, but they must all be different.
    :param addresses: A dictionary of strings that specifies zero or more IP addresses or blocks of IP addresses for "IPV4" and "IPV6". Defaults to {}. All addresses must be specified using Classless Inter-Domain Routing (CIDR) notation.
    :param allow: Set to True to allow the IP addresses, False to block, defaults to False.
    :param count_only: Set to True to only count and not take action on matching requests, defaults to False.
    :param cloud_watch_metrics_enabled: Set to True to enable logging via Cloudwatch, defaults to Fasle.
    :param waf_scope: The scope of the WAF ACL. Defaults to CLOUDFRONT.
    :return: aws_cdk.aws_wafv2.CfnWebACL.RuleProperty.

    :example:
    ```
    ip_rule(
        scope,
        name=f"{scope.stack_name}Allow",
        priority=0,
        addresses={"IPV4": ["1.1.1.1/32"], "IPV6": ["2a00:1d40:11a5::111"]},
        allow=True,
    )
    """

    count_property: Optional[dict[Any, Any]] = None

    # Count must be set to {} or None.
    if count_only:
        count_property = {}
    else:
        count_property = None

    if allow:
        action = waf.CfnWebACL.RuleActionProperty(
            count=count_property, allow=waf.CfnWebACL.AllowActionProperty()
        )
    else:
        action = waf.CfnWebACL.RuleActionProperty(
            count=count_property, block=waf.CfnWebACL.BlockActionProperty()
        )

    # keys of addresses dict can only be "IPV4" or "IPV6" - easiest way to
    # check is by using set differences
    if set(addresses.keys()) - {"IPV4", "IPV6"} != set():
        raise AttributeError("keys for addresses dict must only be 'IPV4' or 'IPV6'!")

    # Need IPv4 and IPv6 IP sets
    ipv4_arn = waf.CfnIPSet(
        scope,
        f"{name}IpSetIPV4",
        addresses=addresses.get("IPV4", []),
        description=f"{name}IpSetIPV4",
        ip_address_version="IPV4",
        scope=waf_scope,
    ).attr_arn

    ipv6_arn = waf.CfnIPSet(
        scope,
        f"{name}IpSetIPV6",
        addresses=addresses.get("IPV6", []),
        description=f"{name}IpSetIPV6",
        ip_address_version="IPV6",
        scope=waf_scope,
    ).attr_arn

    return waf.CfnWebACL.RuleProperty(
        name=f"{name}Rule",
        priority=priority,
        visibility_config=waf.CfnWebACL.VisibilityConfigProperty(
            cloud_watch_metrics_enabled=cloud_watch_metrics_enabled,
            metric_name=f"{name}Metric",
            sampled_requests_enabled=True,
        ),
        action=action,
        statement=waf.CfnWebACL.StatementProperty(
            or_statement=waf.CfnWebACL.OrStatementProperty(
                statements=[
                    waf.CfnWebACL.StatementProperty(
                        ip_set_reference_statement=waf.CfnWebACL.IPSetReferenceStatementProperty(
                            arn=ipv4_arn
                        ),
                    ),
                    waf.CfnWebACL.StatementProperty(
                        ip_set_reference_statement=waf.CfnWebACL.IPSetReferenceStatementProperty(
                            arn=ipv6_arn
                        ),
                    ),
                ]
            )
        ),
    )


def restricted_uri_string_property(
    scope,
    name: str,
    priority: int,
    restricted_uri_string: str,
    allowed_addresses: dict[str, list[str]] = {},
    count_only: bool = False,
    cloud_watch_metrics_enabled: bool = False,
    waf_scope: str = "CLOUDFRONT",
) -> waf.CfnWebACL.RuleProperty:
    """A wrapper that returns an `aws_wafv2.CfnWebACL.RuleProperty` object to be used in a list and passed to the CfnWebACL instance.

    :param scope: `self`, scope in which this resource is defined.
    :param name: The name of the rule. You can't change the name of a Rule after you create it.
    :param priority: If you define more than one Rule in a WebACL , AWS WAF evaluates each request against the Rules in order based on the value of Priority . AWS WAF processes rules with lower priority first. The priorities don't need to be consecutive, but they must all be different.
    :param restricted_uri_string: Access to any URL containing this string will be restricted to the IP addresses in allowed_addresses
    :param allowed_addresses: A dictionary of strings that specifies zero or more IP addresses or blocks of IP addresses for "IPV4" and "IPV6". Defaults to {}. All addresses must be specified using Classless Inter-Domain Routing (CIDR) notation.
    :param count_only: Set to True to only count and not BLOCK on matching requests, defaults to False.
    :param cloud_watch_metrics_enabled: Set to True to enable logging via Cloudwatch, defaults to Fasle.
    :param waf_scope: The scope of the WAF ACL. Defaults to CLOUDFRONT.
    :return: aws_cdk.aws_wafv2.CfnWebACL.RuleProperty.

    :example:
    ```
     restricted_uri_string_property(
        scope,
        name=f"{scope.stack_name}AllowToAccessUriString-helptoclaim",
        priority=0,
        restricted_uri_string="helptoclaim"
        allowed_addresses={"IPV4": ["1.1.1.1/32"], "IPV6": ["2a00:1d40:11a5::111"]},
        count_only=True,
    )
    """

    count_property: Optional[dict[Any, Any]] = None

    # Count must be set to {} or None.
    if count_only:
        count_property = {}
    else:
        count_property = None

    # block unless counting
    action = waf.CfnWebACL.RuleActionProperty(
        count=count_property, block=waf.CfnWebACL.BlockActionProperty()
    )

    # keys of addresses dict can only be "IPV4" or "IPV6" - easiest way to
    # check is by using set differences
    if set(allowed_addresses.keys()) - {"IPV4", "IPV6"} != set():
        raise AttributeError("keys for addresses dict must only be 'IPV4' or 'IPV6'!")

    # Need IPv4 and IPv6 IP sets
    ipv4_arn = waf.CfnIPSet(
        scope,
        f"{name}IpSetIPV4",
        addresses=allowed_addresses.get("IPV4", []),
        description=f"{name}IpSetIPV4",
        ip_address_version="IPV4",
        scope=waf_scope,
    ).attr_arn

    ipv6_arn = waf.CfnIPSet(
        scope,
        f"{name}IpSetIPV6",
        addresses=allowed_addresses.get("IPV6", []),
        description=f"{name}IpSetIPV6",
        ip_address_version="IPV6",
        scope=waf_scope,
    ).attr_arn

    return waf.CfnWebACL.RuleProperty(
        name=f"{name}Rule",
        priority=priority,
        visibility_config=waf.CfnWebACL.VisibilityConfigProperty(
            cloud_watch_metrics_enabled=cloud_watch_metrics_enabled,
            metric_name=f"{name}Metric",
            sampled_requests_enabled=True,
        ),
        action=action,
        statement=waf.CfnWebACL.StatementProperty(
            and_statement=waf.CfnWebACL.AndStatementProperty(
                # Block if uri contains our string AND ip address NOT in IPv4 OR IPv6 allowed lists.
                statements=[
                    waf.CfnWebACL.StatementProperty(
                        byte_match_statement=waf.CfnWebACL.ByteMatchStatementProperty(
                            field_to_match=waf.CfnWebACL.FieldToMatchProperty(uri_path={}),
                            positional_constraint="CONTAINS",
                            text_transformations=[
                                waf.CfnWebACL.TextTransformationProperty(
                                    priority=0, type="URL_DECODE"
                                )
                            ],
                            search_string=restricted_uri_string,
                        ),
                    ),
                    waf.CfnWebACL.StatementProperty(
                        not_statement=waf.CfnWebACL.NotStatementProperty(
                            statement=waf.CfnWebACL.StatementProperty(
                                or_statement=waf.CfnWebACL.OrStatementProperty(
                                    statements=[
                                        waf.CfnWebACL.StatementProperty(
                                            ip_set_reference_statement=waf.CfnWebACL.IPSetReferenceStatementProperty(
                                                arn=ipv4_arn
                                            ),
                                        ),
                                        waf.CfnWebACL.StatementProperty(
                                            ip_set_reference_statement=waf.CfnWebACL.IPSetReferenceStatementProperty(
                                                arn=ipv6_arn
                                            ),
                                        ),
                                    ]
                                )
                            )
                        )
                    ),
                ]
            )
        ),
    )
