import pytest
from aws_cdk import App, Stack, Environment

from ca_cdk_constructs import DomainConfiguration


@pytest.fixture(autouse=True)
def stack():
    app = App()
    stack = Stack(app, "Stack", env=Environment(account="111111111111", region="eu-west-1"))
    yield stack


def test_non_prod_domain_properties(stack):
    domain_config = DomainConfiguration(
        stack,
        "DomainConfig",
        record_name="foo",
        hosted_zone_domain="qa.somedomain.org.uk",
        is_domain_apdex=False,
    )
    assert domain_config.domain == "foo.qa.somedomain.org.uk"
    assert domain_config.ingress_domain == "ingress.foo.qa.somedomain.org.uk"
    assert domain_config.hosted_zone_domain == "qa.somedomain.org.uk"


def test_apdex_domain_properties(stack):
    domain_config = DomainConfiguration(
        stack,
        "DomainConfig",
        record_name="myapp",
        hosted_zone_domain="somedomain.org.uk",
        is_domain_apdex=True,
    )

    assert domain_config.domain == "myapp.somedomain.org.uk"
    assert domain_config.ingress_domain == "ingress.myapp.somedomain.org.uk"
    assert domain_config.hosted_zone_domain == "myapp.somedomain.org.uk"
