import pytest
from aws_cdk import App, Stack
from aws_cdk import aws_wafv2
from aws_cdk import aws_logs
from ca_cdk_constructs.edge_services.waf_v2_builder import WafV2Builder


@pytest.fixture(scope="function")
def waf_builder():
    waf_builder = WafV2Builder(
        Stack(App(), "TestStack"),
        stage="test",
        name="TestWaf",
        description="A dummy WAF for testing",
        tags={"Foo": "Bar"},
    )

    yield waf_builder


def test_waf_v2_builder_type(waf_builder):
    waf = waf_builder.build()
    assert type(waf) == aws_wafv2.CfnWebACL


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
        addresses={"IPV4": ["17.0.0.0.1/24"]},
        allow=True,
        count_only=False,
        cloud_watch_metrics_enabled=False,
    )
    waf = waf_builder.build()
    assert len(waf.rules) == 1
    assert type(waf.rules[0]) == aws_wafv2.CfnWebACL.RuleProperty
    assert waf.rules[0].name == "TestIpRule"


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
    assert type(waf.rules[0]) == aws_wafv2.CfnWebACL.RuleProperty
    assert waf.rules[0].name == "TestManagedRule"


def test_waf_v2_logging_disabled(waf_builder):
    waf = waf_builder.build()
    assert waf.visibility_config.cloud_watch_metrics_enabled == False


def test_waf_v2_logging_enabled():
    stack = Stack(App(), "TestStack")
    test_log_group = aws_logs.LogGroup(stack, "TestLogGroup")
    waf_builder = WafV2Builder(
        stack,
        stage="test",
        name="TestWaf",
        description="A dummy WAF for testing",
        tags={"Foo": "Bar"},
        log_group=test_log_group,
    )
    waf = waf_builder.build()
    assert waf.visibility_config.cloud_watch_metrics_enabled == True
