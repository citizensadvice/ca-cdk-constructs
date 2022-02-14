import aws_cdk as core
import aws_cdk.assertions as assertions
from aws_cdk.aws_route53 import HostedZone

from cdk_constructs.protected_cloudfront import ProtectedCloudfrontStack


def test_cloudfront_record_created():
    app = core.App()
    env = core.Environment(account="12345678901", region="eu-west-1")
    zone_stack = core.Stack(app, "HostedZoneStack", env=env)
    hosted_zone = HostedZone(zone_stack, "Hz", zone_name="test.citizensadvice.org.uk")

    stack = ProtectedCloudfrontStack(app, "ca-referrals",
                                     hosted_zone=hosted_zone,
                                     origin_domain="foo-lb.some.domain",
                                     sub_domain="refer",
                                     env=env)
    template = assertions.Template.from_stack(stack)

    template.has_resource_properties("AWS::Route53::RecordSet", {
        "Name": "refer.test.citizensadvice.org.uk."
    })
