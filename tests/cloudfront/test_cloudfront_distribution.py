"""Tests for CloudFrontDistribution.

These assert against the synthesised CloudFormation template, using
`aws_cdk.assertions.Template`, rather than against CDK objects as the rest of this repo's
tests do. Settings such as the minimum TLS version and the custom resource call parameters
are not exposed as attributes on the CDK objects, and only exists when the template is rendered.
"""

import pytest
from aws_cdk import App, Environment, Stack
from aws_cdk.assertions import Match, Template
from aws_cdk.aws_certificatemanager import Certificate
from aws_cdk.aws_cloudfront import (
    BehaviorOptions,
    SecurityPolicyProtocol,
)
from aws_cdk.aws_cloudfront_origins import HttpOrigin
from aws_cdk.aws_ec2 import SubnetSelection, SubnetType, Vpc
from aws_cdk.aws_route53 import HostedZone, IHostedZone

from ca_cdk_constructs.cloudfront import AlbOriginProps, CloudFrontDistribution

ACCOUNT = "123456789012"
REGION = "eu-west-2"
DOMAIN_NAME = "service.example.org"
VIEWER_CERT_ARN = (
    f"arn:aws:acm:us-east-1:{ACCOUNT}:certificate/11111111-2222-3333-4444-555555555555"
)
ORIGIN_CERT_ARN = (
    f"arn:aws:acm:{REGION}:{ACCOUNT}:certificate/66666666-7777-8888-9999-000000000000"
)


def build_stack() -> Stack:
    """An environment-specific stack in eu-west-2, which the construct requires."""
    return Stack(App(), "TestStack", env=Environment(account=ACCOUNT, region=REGION))


def build_hosted_zone(stack: Stack, id: str = "Zone") -> IHostedZone:
    """The zone ALB mode uses to DNS-validate the certificate it issues."""
    return HostedZone.from_hosted_zone_attributes(
        stack, id, hosted_zone_id="Z0123456789ABCDEFGHIJ", zone_name="example.org"
    )


def build_distribution(stack: Stack, **kwargs) -> CloudFrontDistribution:
    """A standalone-mode distribution, with any keyword overriding the defaults.

    The defaults include a `default_behavior`, so anything exercising ALB mode has to clear
    it explicitly rather than just leaving it out.
    """
    defaults = {
        "env": "dev",
        "namespace": "test-svc",
        "certificate": Certificate.from_certificate_arn(stack, "ViewerCert", VIEWER_CERT_ARN),
        "domain_name": DOMAIN_NAME,
        "default_behavior": BehaviorOptions(origin=HttpOrigin("origin.example.org")),
    }
    return CloudFrontDistribution(stack, "Dist", **{**defaults, **kwargs})


@pytest.fixture
def standalone() -> Template:
    stack = build_stack()
    build_distribution(stack)
    return Template.from_stack(stack)


@pytest.fixture
def alb_mode() -> Template:
    stack = build_stack()
    vpc = Vpc(stack, "Vpc", max_azs=2, nat_gateways=0)
    build_distribution(
        stack,
        default_behavior=None,
        alb_origin=AlbOriginProps(
            vpc=vpc,
            vpc_subnets=SubnetSelection(subnet_type=SubnetType.PUBLIC),
            hosted_zone=build_hosted_zone(stack),
        ),
    )
    return Template.from_stack(stack)


# --- Hardened defaults -------------------------------------------------------------


def test_minimum_protocol_version_defaults_to_tls_1_2(standalone):
    """The AWS recommended policy, and what Security Hub CloudFront.15 accepts.

    Asserts the viewer certificate's minimum protocol version renders as TLSv1.2_2021.
    """
    standalone.has_resource_properties(
        "AWS::CloudFront::Distribution",
        {
            "DistributionConfig": Match.object_like(
                {
                    "ViewerCertificate": Match.object_like(
                        {"MinimumProtocolVersion": "TLSv1.2_2021"}
                    )
                }
            )
        },
    )


def test_minimum_protocol_version_can_be_raised():
    """Services that control their clients can refuse anything below TLS 1.3.

    Asserts the supplied policy reaches the template.
    """
    stack = build_stack()
    build_distribution(stack, minimum_protocol_version=SecurityPolicyProtocol.TLS_V1_3_2025)

    Template.from_stack(stack).has_resource_properties(
        "AWS::CloudFront::Distribution",
        {
            "DistributionConfig": Match.object_like(
                {
                    "ViewerCertificate": Match.object_like(
                        {"MinimumProtocolVersion": "TLSv1.3_2025"}
                    )
                }
            )
        },
    )


def test_geo_restriction_allowlists_the_british_isles_and_ireland(standalone):
    """Distributions should serve the British Isles and Ireland only unless told otherwise.

    Asserts the geo restriction is a whitelist of exactly GB, JE, GG, IM and IE.
    """
    standalone.has_resource_properties(
        "AWS::CloudFront::Distribution",
        {
            "DistributionConfig": Match.object_like(
                {
                    "Restrictions": {
                        "GeoRestriction": {
                            "RestrictionType": "whitelist",
                            "Locations": ["GB", "JE", "GG", "IM", "IE"],
                        }
                    }
                }
            )
        },
    )


def test_geo_restriction_allowlists_the_countries_given():
    """Services outside the default footprint must be able to choose their own countries.

    Asserts that allowed_countries replaces the default allowlist rather than adding to it.
    """
    stack = build_stack()
    build_distribution(stack, allowed_countries=["FR", "DE"])
    Template.from_stack(stack).has_resource_properties(
        "AWS::CloudFront::Distribution",
        {
            "DistributionConfig": Match.object_like(
                {
                    "Restrictions": {
                        "GeoRestriction": {
                            "RestrictionType": "whitelist",
                            "Locations": ["FR", "DE"],
                        }
                    }
                }
            )
        },
    )


def test_geo_restriction_can_be_turned_off():
    """Public content has to be reachable from anywhere, so the allowlist must be escapable.

    Asserts that with allowed_countries None, no Restrictions block is emitted at all.
    """
    stack = build_stack()
    build_distribution(stack, allowed_countries=None)
    Template.from_stack(stack).has_resource_properties(
        "AWS::CloudFront::Distribution",
        {
            "DistributionConfig": Match.object_like(
                {"Restrictions": Match.absent()},
            )
        },
    )


def test_comment_leads_with_the_resource_name(standalone):
    """Distributions have no name, so the console's description is the only way to tell
    one from another.

    Asserts that with no comment supplied, the description is the resource name alone.
    """
    standalone.has_resource_properties(
        "AWS::CloudFront::Distribution",
        {"DistributionConfig": Match.object_like({"Comment": "dev-euw2-cf-test-svc"})},
    )


def test_caller_comment_is_appended_to_the_resource_name():
    """A caller's own description should add to that identifier rather than replace it.

    Asserts the description is the resource name, a colon, then the caller's text.
    """
    stack = build_stack()
    build_distribution(stack, comment="public website")
    Template.from_stack(stack).has_resource_properties(
        "AWS::CloudFront::Distribution",
        {
            "DistributionConfig": Match.object_like(
                {"Comment": "dev-euw2-cf-test-svc: public website"}
            )
        },
    )


# --- ALB mode ----------------------------------------------------------------------


def test_alb_security_group_admits_the_cloudfront_prefix_list(alb_mode):
    """CloudFront's origin-facing ranges change over time, so the load balancer has to
    admit them by prefix list rather than by fixed CIDR.

    Asserts a standalone ingress resource opens TCP 443 from a source prefix list.
    """
    alb_mode.has_resource_properties(
        "AWS::EC2::SecurityGroupIngress",
        Match.object_like(
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "SourcePrefixListId": Match.any_value(),
                "Description": "CloudFront origin-facing ranges",
            }
        ),
    )


def test_alb_security_group_has_no_open_ingress(alb_mode):
    """CloudFront must be the only thing that can reach the load balancer. Anything wider
    defeats the point of keeping it internal.

    Asserts the security group carries no inline ingress rules, which is where an open
    CIDR would appear.
    """
    alb_mode.has_resource_properties(
        "AWS::EC2::SecurityGroup",
        {"GroupName": "dev-euw2-sg-test-svc", "SecurityGroupIngress": Match.absent()},
    )


def test_vpc_origin_presents_the_public_alias_not_the_alb_dns_name(alb_mode):
    """The origin handshake checks the certificate against the name CloudFront presents,
    and a load balancer's own DNS name can never hold a public certificate.

    Asserts the VPC origin entry uses the public alias as its domain name.
    """
    alb_mode.has_resource_properties(
        "AWS::CloudFront::Distribution",
        {
            "DistributionConfig": Match.object_like(
                {
                    "Origins": Match.array_with(
                        [
                            Match.object_like(
                                {
                                    "DomainName": DOMAIN_NAME,
                                    "VpcOriginConfig": Match.any_value(),
                                }
                            )
                        ]
                    )
                }
            )
        },
    )


def test_resources_follow_the_naming_convention(alb_mode):
    """Resources need to be identifiable by environment, region and service from the name
    alone, without opening them.

    Asserts the load balancer, target group and security group are all named
    <env>-<region-short>-<type>-<namespace>, and that the load balancer is internal.
    """
    alb_mode.has_resource_properties(
        "AWS::ElasticLoadBalancingV2::LoadBalancer",
        Match.object_like({"Name": "dev-euw2-alb-test-svc", "Scheme": "internal"}),
    )
    alb_mode.has_resource_properties(
        "AWS::ElasticLoadBalancingV2::TargetGroup",
        Match.object_like({"Name": "dev-euw2-tg-test-svc"}),
    )
    alb_mode.has_resource_properties(
        "AWS::EC2::SecurityGroup", Match.object_like({"GroupName": "dev-euw2-sg-test-svc"})
    )


def test_alb_origin_is_exposed_for_extra_cache_behaviours():
    """ALB mode caches nothing by default, so callers need a way to opt a path in. The
    origin has to be reachable for that, and reusing it must not build a second one.

    Asserts a behaviour added afterwards against `origin` shares the single VPC origin.
    """
    stack = build_stack()
    vpc = Vpc(stack, "Vpc", max_azs=2, nat_gateways=0)
    dist = build_distribution(
        stack,
        default_behavior=None,
        alb_origin=AlbOriginProps(vpc=vpc, hosted_zone=build_hosted_zone(stack)),
    )
    assert dist.origin is not None
    dist.distribution.add_behavior("/assets/*", dist.origin)

    template = Template.from_stack(stack)
    template.resource_count_is("AWS::CloudFront::VpcOrigin", 1)
    template.has_resource_properties(
        "AWS::CloudFront::Distribution",
        {
            "DistributionConfig": Match.object_like(
                {"CacheBehaviors": [Match.object_like({"PathPattern": "/assets/*"})]}
            )
        },
    )


# --- Access logging ----------------------------------------------------------------


def test_log_delivery_uses_three_custom_resources_in_us_east_1(standalone):
    """Log delivery has to be configured in us-east-1 whatever region the consumer deploys
    into, and through the CloudWatch Logs client rather than the "logs" of its IAM prefix.
    Neither is the default and both fail only at deploy time.

    Asserts there are exactly three Custom::AWS resources, and that their SDK calls name
    that client and that region.
    """
    standalone.resource_count_is("Custom::AWS", 3)

    rendered = str(standalone.find_resources("Custom::AWS"))
    assert '"service":"@aws-sdk/client-cloudwatch-logs"' in rendered
    assert '"region":"us-east-1"' in rendered


def test_delivery_destination_name_carries_the_log_format(standalone):
    """AWS cannot change a delivery destination's output format in place, so a format
    change has to force a new destination rather than silently keep the old one.

    Asserts the destination the custom resources create is named with the format suffixed.
    """
    rendered = str(standalone.find_resources("Custom::AWS"))
    assert '"name":"dev-euw2-logs-test-svc-w3c"' in rendered


def test_log_bucket_policy_grants_the_delivery_principal(standalone):
    """The log delivery service writes to the bucket itself, so the bucket has to grant it,
    and narrowly enough that nothing else can use the same route.

    Asserts the policy lets delivery.logs.amazonaws.com put objects, scoped by source
    account and to delivery source ARNs in us-east-1.
    """
    standalone.has_resource_properties(
        "AWS::S3::BucketPolicy",
        {
            "PolicyDocument": Match.object_like(
                {
                    "Statement": Match.array_with(
                        [
                            Match.object_like(
                                {
                                    "Sid": "AWSLogsDeliveryWrite",
                                    "Action": "s3:PutObject",
                                    "Principal": {"Service": "delivery.logs.amazonaws.com"},
                                    "Condition": {
                                        "StringEquals": {"aws:SourceAccount": ACCOUNT},
                                        "ArnLike": {
                                            "aws:SourceArn": {
                                                "Fn::Join": [
                                                    "",
                                                    [
                                                        "arn:",
                                                        {"Ref": "AWS::Partition"},
                                                        f":logs:us-east-1:{ACCOUNT}:delivery-source:*",
                                                    ],
                                                ]
                                            }
                                        },
                                    },
                                }
                            )
                        ]
                    )
                }
            )
        },
    )


def test_log_format_change_replaces_the_delivery():
    """A delivery's destination is fixed once created, so a format change has to produce a
    new delivery rather than send the old one an Update it would silently ignore, leaving
    it attached to a destination CloudFormation is about to delete.

    Asserts the custom resource logical IDs differ between the two formats.
    """
    w3c, parquet = build_stack(), build_stack()
    build_distribution(w3c, log_format="w3c")
    build_distribution(parquet, log_format="parquet")

    w3c_ids = set(Template.from_stack(w3c).find_resources("Custom::AWS"))
    parquet_ids = set(Template.from_stack(parquet).find_resources("Custom::AWS"))

    assert w3c_ids != parquet_ids


def test_log_bucket_is_hardened_and_expires_objects():
    """Access logs record what people requested, and CloudFront never deletes them, so the
    bucket has to stay private and must not grow forever.

    Asserts the bucket is versioned, ownership-enforced, blocks all public access, and
    expires objects after the retention period it was given.
    """
    stack = build_stack()
    build_distribution(stack, log_retention_days=30)
    Template.from_stack(stack).has_resource_properties(
        "AWS::S3::Bucket",
        Match.object_like(
            {
                "VersioningConfiguration": {"Status": "Enabled"},
                "OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]},
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "BlockPublicPolicy": True,
                    "IgnorePublicAcls": True,
                    "RestrictPublicBuckets": True,
                },
                "LifecycleConfiguration": {
                    "Rules": Match.array_with(
                        [Match.object_like({"ExpirationInDays": 30, "Status": "Enabled"})]
                    )
                },
            }
        ),
    )


def test_access_logs_can_be_turned_off():
    """Not every consumer wants a log bucket, and opting out should leave nothing behind.

    Asserts log_bucket is None and the template contains no bucket and no custom resources.
    """
    stack = build_stack()
    dist = build_distribution(stack, access_logs=False)
    template = Template.from_stack(stack)

    assert dist.log_bucket is None
    template.resource_count_is("AWS::S3::Bucket", 0)
    template.resource_count_is("Custom::AWS", 0)


# --- Migration mode ----------------------------------------------------------------


def test_domain_name_is_served_as_an_alias_by_default(standalone):
    """The common case is unchanged by migration support.

    Asserts the domain name renders as an alternate domain name.
    """
    standalone.has_resource_properties(
        "AWS::CloudFront::Distribution",
        {"DistributionConfig": Match.object_like({"Aliases": [DOMAIN_NAME]})},
    )


def test_migration_mode_omits_the_alias_but_keeps_the_certificate():
    """CloudFront refuses to let two distributions hold one alias, so a replacement has to
    be built without it. The certificate still has to be attached, because AWS requires that
    on the target of an `update-domain-association` move and the move is what adds the alias.

    Asserts no Aliases key at all, while the ACM certificate and the TLS policy stay put.
    """
    stack = build_stack()
    build_distribution(stack, associate_domain_name=False)

    Template.from_stack(stack).has_resource_properties(
        "AWS::CloudFront::Distribution",
        {
            "DistributionConfig": Match.object_like(
                {
                    # Absent, not empty: an empty list still renders the key.
                    "Aliases": Match.absent(),
                    "ViewerCertificate": Match.object_like(
                        {
                            "AcmCertificateArn": VIEWER_CERT_ARN,
                            "MinimumProtocolVersion": "TLSv1.2_2021",
                        }
                    ),
                }
            )
        },
    )


def test_supplied_origin_certificate_is_used_instead_of_vending_one():
    """A team migrating already holds a certificate for the domain. Vending a second leaves
    both sharing one ACM validation record, so deleting either stack breaks the survivor's
    renewal.

    Asserts nothing is vended, and that the supplied certificate reaches the listener.
    """
    stack = build_stack()
    vpc = Vpc(stack, "Vpc", max_azs=2, nat_gateways=0)
    origin_cert = Certificate.from_certificate_arn(stack, "OriginCert", ORIGIN_CERT_ARN)
    dist = build_distribution(
        stack,
        default_behavior=None,
        alb_origin=AlbOriginProps(vpc=vpc, certificate=origin_cert),
    )

    assert dist.origin_certificate is origin_cert
    template = Template.from_stack(stack)
    template.resource_count_is("AWS::CertificateManager::Certificate", 0)
    template.has_resource_properties(
        "AWS::ElasticLoadBalancingV2::Listener",
        Match.object_like({"Certificates": [{"CertificateArn": ORIGIN_CERT_ARN}]}),
    )


def test_origin_certificate_is_vended_when_none_is_supplied(alb_mode):
    """The original behaviour, which nothing asserted before.

    Asserts exactly one certificate is issued for the domain and lands on the listener.
    """
    alb_mode.resource_count_is("AWS::CertificateManager::Certificate", 1)
    alb_mode.has_resource_properties(
        "AWS::CertificateManager::Certificate",
        Match.object_like({"DomainName": DOMAIN_NAME, "ValidationMethod": "DNS"}),
    )
    alb_mode.has_resource_properties(
        "AWS::ElasticLoadBalancingV2::Listener",
        Match.object_like({"Certificates": [Match.any_value()]}),
    )


# --- Validation --------------------------------------------------------------------


@pytest.mark.parametrize(
    "namespace", ["Test-Svc", "-test", "test-", "test_svc", "a" * 19, "test-svc\n"]
)
def test_invalid_namespace_is_rejected(namespace):
    """The namespace becomes part of physical resource names, where a bad value fails
    several minutes into a deploy rather than immediately.

    Asserts construction raises for values that break the pattern or the length cap.
    """
    stack = build_stack()
    # Matched on the message: without it, CDK's own name validation further downstream
    # would satisfy a bare raises() and the construct's check could rot unnoticed.
    with pytest.raises(Exception, match="namespace must be"):
        build_distribution(stack, namespace=namespace)


def test_certificate_outside_us_east_1_is_rejected():
    """CloudFront only accepts viewer certificates issued in us-east-1, and a certificate
    from anywhere else is a deploy-time failure.

    Asserts construction raises, and that the message names us-east-1.
    """
    stack = build_stack()
    with pytest.raises(Exception, match="us-east-1"):
        build_distribution(
            stack,
            certificate=Certificate.from_certificate_arn(
                stack, "WrongRegionCert", f"arn:aws:acm:{REGION}:{ACCOUNT}:certificate/abc"
            ),
        )


def test_region_agnostic_stack_is_rejected():
    """Resource names embed a region short code, which cannot be derived from a token.

    Asserts construction raises for a stack created without an env.
    """
    with pytest.raises(Exception, match="environment-specific"):
        build_distribution(Stack(App(), "NoEnvStack"))


def test_default_behavior_and_alb_origin_are_mutually_exclusive():
    """Each argument picks a mode, and the two modes configure the same origin, so
    accepting both would silently discard one of them.

    Asserts that passing both raises, reporting them as mutually exclusive.
    """
    stack = build_stack()
    with pytest.raises(Exception, match="mutually exclusive"):
        build_distribution(
            stack,
            default_behavior=BehaviorOptions(origin=HttpOrigin("origin.example.org")),
            alb_origin=AlbOriginProps(vpc=Vpc(stack, "Vpc")),
        )


def test_one_of_default_behavior_or_alb_origin_is_required():
    """A distribution with no origin is not a useful thing to deploy.

    Asserts that passing neither raises, asking for one of the two.
    """
    stack = build_stack()
    with pytest.raises(Exception, match="Either default_behavior or alb_origin"):
        build_distribution(stack, default_behavior=None, alb_origin=None)


def test_alb_origin_requires_a_certificate_or_a_hosted_zone():
    """The load balancer's listener needs a certificate, which is either one the caller
    supplies or one the construct issues, and issuing needs a zone to validate against.

    Asserts that choosing ALB mode with neither raises.
    """
    stack = build_stack()
    with pytest.raises(Exception, match="alb_origin needs either certificate"):
        build_distribution(
            stack,
            default_behavior=None,
            alb_origin=AlbOriginProps(vpc=Vpc(stack, "Vpc")),
        )


def test_origin_certificate_outside_the_stack_region_is_rejected():
    """The viewer certificate must be in us-east-1 and the load balancer's must be regional,
    so passing the same certificate to both is an easy mistake that otherwise surfaces
    several minutes into a deploy as a CertificateNotFound from ELB.

    Asserts construction raises, and that the message names the stack's region.
    """
    stack = build_stack()
    with pytest.raises(Exception, match=f"must be issued in {REGION}"):
        build_distribution(
            stack,
            default_behavior=None,
            alb_origin=AlbOriginProps(
                vpc=Vpc(stack, "Vpc"),
                certificate=Certificate.from_certificate_arn(
                    stack, "WrongRegionOriginCert", VIEWER_CERT_ARN
                ),
            ),
        )
