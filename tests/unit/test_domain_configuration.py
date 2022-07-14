from ca_cdk_constructs import DomainConfiguration


def test_non_prod_domain_properties():

    domain_props = DomainConfiguration(
        record_name="foo", env_name="qa", apex_domain="somedomain.org.uk"
    )

    assert domain_props.domain == "foo.qa.somedomain.org.uk"
    assert domain_props.ingress_domain == "foo-ingress.qa.somedomain.org.uk"
    assert domain_props.hosted_zone_domain == "qa.somedomain.org.uk"


def test_prod_domain_properties():

    domain_props = DomainConfiguration(
        record_name="foo", env_name="prod", apex_domain="somedomain.org.uk"
    )

    assert domain_props.domain == "foo.somedomain.org.uk"
    assert domain_props.ingress_domain == "ingress.foo.somedomain.org.uk"
    assert domain_props.hosted_zone_domain == "foo.somedomain.org.uk"
