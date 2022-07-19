from ca_cdk_constructs import DomainProperties


def test_non_apdex_domain_properties():
    domain_props = DomainProperties(
        sub_domain="foo",
        zone_domain="qa.somedomain.org.uk"
    )
    assert domain_props.domain == "foo.qa.somedomain.org.uk"
    assert domain_props.ingress_domain == "foo-ingress.qa.somedomain.org.uk"
    assert domain_props.zone_domain == "qa.somedomain.org.uk"


def test_apdex_domain_properties():
    domain_props = DomainProperties(
        sub_domain="foo",
        zone_domain="somedomain.org.uk"
    )
    assert domain_props.domain == "foo.somedomain.org.uk"
    assert domain_props.ingress_domain == "foo-ingress.somedomain.org.uk"
    assert domain_props.zone_domain == "somedomain.org.uk"

def test_apdex_domain_properties_without_subdomain():
    domain_props = DomainProperties(
        sub_domain="",
        zone_domain="foo.somedomain.org.uk"
    )
    assert domain_props.domain == "foo.somedomain.org.uk"
    assert domain_props.ingress_domain == "foo-ingress.somedomain.org.uk"
    assert domain_props.zone_domain == "foo.somedomain.org.uk"

def test_repeated_subdomain():
    domain_props = DomainProperties(
        sub_domain="foo",
        zone_domain="foo.somedomain.org.uk"
    )
    assert domain_props.domain == "foo.foo.somedomain.org.uk"
    assert domain_props.ingress_domain == "foo-ingress.foo.somedomain.org.uk"
    assert domain_props.zone_domain == "foo.somedomain.org.uk"
