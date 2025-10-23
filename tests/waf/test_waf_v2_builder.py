import pytest
from aws_cdk import App, Stack, aws_logs, aws_wafv2

from ca_cdk_constructs.edge_services.waf_v2_builder import WafV2Builder


@pytest.fixture(scope="function")
def waf_builder():
    waf_builder = WafV2Builder(
        Stack(App(), "TestStack"),
        name="TestWaf",
        description="A dummy WAF for testing",
    )
    yield waf_builder


def test_waf_v2_builder_type(waf_builder):
    waf = waf_builder.build()
    assert type(waf) is aws_wafv2.CfnWebACL


def test_waf_v2_builder_name(waf_builder):
    waf = waf_builder.build()
    assert waf.name == "TestWaf"


def test_waf_v2_builder_description(waf_builder):
    waf = waf_builder.build()
    assert waf.description == "A dummy WAF for testing"


def test_waf_v2_ip_rule(waf_builder):
    waf_builder.add_ip_rule(
        name="TestIp",
        priority=1,
        addresses={"IPV4": ["17.0.0.0.1/24"], "IPV6": ["::"]},
        allow=True,
        count_only=False,
        cloud_watch_metrics_enabled=False,
    )
    waf = waf_builder.build()
    assert len(waf.rules) == 1
    assert type(waf.rules[0]) is aws_wafv2.CfnWebACL.RuleProperty
    assert waf.rules[0].name == "TestIpRule"


def test_waf_v2_ip_rule_error(waf_builder):
    with pytest.raises(Exception):
        waf_builder.add_ip_rule(
            name="TestIp",
            priority=1,
            addresses={"IPV5": ["17.0.0.0.1/24"], "IPV7": ["::"]},
            allow=True,
            count_only=False,
            cloud_watch_metrics_enabled=False,
        )
        waf_builder.build()


def test_waf_v2_empty_ip_rule(waf_builder):
    waf_builder.add_ip_rule(
        name="TestIp",
        priority=1,
        addresses={},
        allow=True,
        count_only=False,
        cloud_watch_metrics_enabled=False,
    )
    waf = waf_builder.build()
    assert len(waf.rules) == 1


def test_waf_v2_managed_rule(waf_builder):
    waf_builder.add_managed_rule(
        name="TestManaged",
        priority=1,
        managed_rule_name="AWSManagedRulesCommonRuleSet",
        managed_rule_vendor="AWS",
        count_only=True,
    )
    waf = waf_builder.build()
    assert len(waf.rules) == 1
    assert type(waf.rules[0]) is aws_wafv2.CfnWebACL.RuleProperty
    assert waf.rules[0].name == "TestManagedRule"


def test_waf_v2_logging_disabled(waf_builder):
    waf = waf_builder.build()
    assert waf.visibility_config.cloud_watch_metrics_enabled is False


def test_waf_v2_logging_enabled():
    stack = Stack(App(), "TestStack")
    test_log_group = aws_logs.LogGroup(
        stack, "TestLogGroup", log_group_name="aws-waf-logs-test-group"
    )
    waf_builder = WafV2Builder(
        stack,
        name="TestWaf",
        description="A dummy WAF for testing",
        log_group=test_log_group,
    )
    waf = waf_builder.build()
    assert waf.visibility_config.cloud_watch_metrics_enabled is True


def test_waf_v2_get_rules(waf_builder):
    waf_builder.add_managed_rule(
        name="TestManaged",
        priority=1,
        managed_rule_name="AWSManagedRulesCommonRuleSet",
        managed_rule_vendor="AWS",
        count_only=True,
    )
    rules = waf_builder.get_rules()
    assert len(rules) == 1
    assert type(rules[0]) is aws_wafv2.CfnWebACL.RuleProperty


def test_waf_v2_restricted_uri_string_rule(waf_builder):
    waf_builder.add_restricted_uri_string_rule(
        name="RestrictAccessToURIFoo",
        priority=0,
        restricted_uri_string="Foo",
        allowed_addresses={"IPV4": ["1.1.1.1/32"], "IPV6": []},
    )
    waf_builder.build()
    rules = waf_builder.get_rules()
    # basically testing that we block with AND (check for path, NOT ( OR ( in allowed ipv4 or allowed ipv6 sets)))
    assert type(rules[0]) is aws_wafv2.CfnWebACL.RuleProperty
    assert (
        type(rules[0].statement.and_statement.statements[0].byte_match_statement)
        is aws_wafv2.CfnWebACL.ByteMatchStatementProperty
    )
    assert (
        type(
            rules[0]
            .statement.and_statement.statements[1]
            .not_statement.statement.or_statement.statements[0]
            .ip_set_reference_statement
        )
        is aws_wafv2.CfnWebACL.IPSetReferenceStatementProperty
    )
    assert (
        type(
            rules[0]
            .statement.and_statement.statements[1]
            .not_statement.statement.or_statement.statements[1]
            .ip_set_reference_statement
        )
        is aws_wafv2.CfnWebACL.IPSetReferenceStatementProperty
    )
