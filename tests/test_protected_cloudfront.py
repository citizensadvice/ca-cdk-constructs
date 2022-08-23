import aws_cdk as core
import aws_cdk.assertions as assertions
from aws_cdk.aws_route53 import HostedZone

from ca_cdk_constructs.edge_services.protected_cloudfront import ProtectedCloudfront


def test_cloudfront_record_created():
    app = core.App()
    env = core.Environment(account="12345678901", region="eu-west-1")
    zone_stack = core.Stack(app, "HostedZoneStack", env=env)
    hosted_zone = HostedZone(zone_stack, "Hz", zone_name="test.acme.org.uk")

    ProtectedCloudfront(
        zone_stack,
        "Cdn",
        hosted_zone=hosted_zone,
        origin_domain="foo-lb.some.domain",
        sub_domain="refer",
    )
    template = assertions.Template.from_stack(zone_stack)

    template.has_resource_properties(
        "AWS::Route53::RecordSet", {"Name": "refer.test.acme.org.uk."}
    )
