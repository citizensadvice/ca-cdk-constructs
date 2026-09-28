import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal

from aws_cdk import (
    Arn,
    ArnFormat,
    CfnOutput,
    Duration,
    RemovalPolicy,
    Stack,
    Tags,
    Token,
)
from aws_cdk.aws_certificatemanager import Certificate, CertificateValidation, ICertificate
from aws_cdk.aws_cloudfront import (
    AllowedMethods,
    BehaviorOptions,
    CachePolicy,
    Distribution,
    GeoRestriction,
    HttpVersion,
    IOrigin,
    OriginProtocolPolicy,
    OriginRequestPolicy,
    OriginSslPolicy,
    PriceClass,
    SecurityPolicyProtocol,
    SSLMethod,
    ViewerProtocolPolicy,
)
from aws_cdk.aws_cloudfront_origins import VpcOrigin
from aws_cdk.aws_ec2 import IVpc, Port, PrefixList, SecurityGroup, SubnetSelection
from aws_cdk.aws_elasticloadbalancingv2 import (
    ApplicationListener,
    ApplicationLoadBalancer,
    ApplicationProtocol,
    ApplicationTargetGroup,
    HealthCheck,
    IApplicationLoadBalancerTarget,
    SslPolicy,
)
from aws_cdk.aws_iam import PolicyStatement, ServicePrincipal
from aws_cdk.aws_route53 import IHostedZone
from aws_cdk.aws_s3 import (
    BlockPublicAccess,
    Bucket,
    BucketEncryption,
    BucketNamespace,
    LifecycleRule,
    ObjectOwnership,
)
from aws_cdk.custom_resources import (
    AwsCustomResource,
    AwsCustomResourcePolicy,
    AwsSdkCall,
    PhysicalResourceId,
    PhysicalResourceIdReference,
)
from constructs import Construct

# CloudFront is a global service homed in us-east-1: viewer certificates must be issued
# there, and its log delivery configuration must be created there.
CLOUDFRONT_HOME_REGION = "us-east-1"
CLOUDFRONT_ORIGIN_PREFIX_LIST = "com.amazonaws.global.cloudfront.origin-facing"

LOGS_SDK_CLIENT = "@aws-sdk/client-cloudwatch-logs"

LogFormat = Literal["w3c", "parquet"]
EnvName = Literal["dev", "pre", "prod"]

# 2 to 18 characters. The cap comes from the 32 character limit on load balancer names.
NAMESPACE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,16}[a-z0-9]$")

ALLOWED_COUNTRIES = (
    "GB",  # United Kingdom
    "JE",  # Jersey
    "GG",  # Guernsey
    "IM",  # Isle of Man
    "IE",  # Ireland
)


@dataclass
class AlbOriginProps:
    """What the construct needs in order to build an internal ALB for you.

    :param vpc: The VPC to place the load balancer in.
    :param targets: What the load balancer should forward to, for example an ECS service
        or a list of IPs.
    :param target_port: The port the targets listen on. Defaults to 80.
    :param target_protocol: The protocol used between the load balancer and the targets.
        Defaults to HTTP, which is the usual choice inside a VPC. The CloudFront to load
        balancer hop is always HTTPS regardless of this setting.
    :param health_check_path: Path the load balancer polls for target health.
        Defaults to "/".
    :param vpc_subnets: Where to place the load balancer. Defaults to the VPC's private
        subnets.
    :param certificate: An existing regional certificate to put on the load balancer's
        listener. Must cover the construct's `domain_name`, because that is the name
        CloudFront presents to the load balancer, and must be issued in the stack's own
        region. Supply this when migrating a service that already has a certificate for
        the domain: vending a second one leaves both sharing a single ACM validation
        record, and deleting either stack takes that record away and breaks renewal of the
        survivor. Leave it unset and the construct issues one, which needs `hosted_zone`.
    :param hosted_zone: Zone used to DNS-validate the certificate the construct issues for
        the load balancer. Required unless `certificate` is supplied, unused when it is.
        No records are created in it; ACM adds its own validation record and the caller
        owns everything else.
    """

    vpc: IVpc
    targets: list[IApplicationLoadBalancerTarget] = field(default_factory=list)
    target_port: int = 80
    target_protocol: ApplicationProtocol = ApplicationProtocol.HTTP
    health_check_path: str = "/"
    vpc_subnets: SubnetSelection | None = None
    certificate: ICertificate | None = None
    hosted_zone: IHostedZone | None = None


class CloudFrontDistribution(Construct):
    """
    A CloudFront distribution with CA's default hardening applied.

    The defaults are as follows:
    - TLSv1.2_2021 minimum viewer protocol version, SNI only
    - HTTP/2 and HTTP/3, IPv6 enabled
    - PriceClass 100 (Europe and North America edge locations)

    It works in one of two modes.

    Pass `default_behavior` to front an origin you already have. The construct stays out of
    the way and only applies the certificate, aliases and hardened settings around it.

    Pass `alb_origin` instead and the construct builds an internal Application Load Balancer,
    puts a certificate on it, locks its security group down to CloudFront, and wires it up
    as a VPC origin. The certificate is one you supply or, failing that, one the construct
    issues. The load balancer is never publicly reachable; CloudFront reaches it over the
    VPC origin service rather than the internet.

    Every resource is named `<env>-<region-short>-<type>-<namespace>`, for example
    `prod-euw2-alb-casebook`. The log bucket is the one exception: it uses S3's
    account-regional namespace, so CloudFormation appends the account and region itself
    and the name reads `prod-s3-casebook-<account>-<region>-an`.

    :param scope: The scope of the construct, usually self.
    :param id: The id of the construct.
    :param env: Deployment environment, used as the first segment of every resource name.
    :param namespace: Service identifier, used as the last segment of every resource name.
        Lowercase alphanumeric and hyphens, 2 to 18 characters. The cap comes from the
        32 character limit on load balancer names. Must be unique per account and region.
    :param certificate: The viewer certificate, which must be issued in us-east-1 because
        CloudFront accepts no other region. Either create it in a us-east-1 stack, or pass
        one that already exists with `Certificate.from_certificate_arn`.
    :param domain_name: The service's hostname. Normally served as the distribution's
        alternate domain name, in which case `certificate` must cover it. In `alb_origin`
        mode it is also the name on the load balancer's certificate and the name CloudFront
        presents to it, and it keeps that job even when `associate_domain_name` is False.
    :param associate_domain_name: Serve `domain_name` as the distribution's alternate
        domain name. Defaults to True. Set it False to stand a distribution up beside one
        that already holds the domain, which CloudFront would otherwise reject, then move
        the domain across with `aws cloudfront update-domain-association`. The certificate
        stays attached either way, because AWS requires that on the target of a move. See
        the README's migration section for the full sequence.
    :param default_behavior: The default behaviour, including the origin. Mutually
        exclusive with `alb_origin`.
    :param alb_origin: Details of an internal load balancer for the construct to build and
        serve from. Mutually exclusive with `default_behavior`, and needs either its own
        `certificate` or its own `hosted_zone`. Resolving the CloudFront prefix list is a
        context lookup, so this mode only works in a stack created with an explicit
        `env=Environment(account=..., region=...)`.
    :param additional_behaviors: Path pattern to behaviour mappings. Defaults to none.
    :param web_acl_id: Unique identifier that specifies the AWS WAF web ACL to associate
        with this CloudFront distribution. To specify a web ACL created using the latest
        version of AWS WAF, use the ACL ARN, for example
        `arn:aws:wafv2:us-east-1:123456789012:global/webacl/ExampleWebACL/473e64fd-f30b-4765-81a0-62ad96dd167a`.
        To specify a web ACL created using AWS WAF Classic, use the ACL ID, for example
        `473e64fd-f30b-4765-81a0-62ad96dd167a`. Defaults to no WAF.
    :param allowed_countries: ISO 3166-1 alpha-2 codes of the countries to serve, for
        example `["GB", "IE"]`. Viewers anywhere else are blocked. Defaults to the British
        Isles and Ireland (GB, JE, GG, IM, IE). Pass None to serve everywhere. Three things
        to know before leaving this on for public content:
        - It covers the whole distribution. You cannot restrict one path and not another.
        - Search engines crawl from outside these countries, notably Googlebot from the
          US, so an allowlist will deindex a public site.
        - It fails open. CloudFront serves the content when it cannot place the viewer,
          so treat this as a distribution control rather than a security one.
        Blocked viewers get a bare 403 unless you supply `error_responses`.
    :param access_logs: Deliver access logs using CloudFront standard logging (v2).
        Defaults to True.
    :param log_retention_days: How long to keep access logs. Defaults to 90. CloudFront
        never deletes log files itself. The bucket is created here and exposed as
        `log_bucket`; supplying your own is not supported, because CDK cannot attach the
        required delivery policy to an imported bucket and the failure would be silent.
    :param log_format: Access log output format. Defaults to "w3c", which matches the
        legacy CloudFront log layout and costs nothing extra. "parquet" is far cheaper to
        query in Athena but incurs CloudWatch conversion charges. Changing it after
        deployment replaces the delivery destination and the delivery.
    :param price_class: The edge locations to serve from. Defaults to PRICE_CLASS_100.
    :param minimum_protocol_version: Lowest TLS version a viewer may negotiate. Defaults to
        TLS_V1_2_2021, which is the AWS recommended policy and what Security Hub control
        CloudFront.15 accepts.
    :param comment: Appended to the resource name in the CloudFront console's Description
        column, as ``<name>: <comment>``. Defaults to the resource name alone.
    """

    def __init__(
        self,
        scope: Construct,
        id: str,
        env: EnvName,
        namespace: str,
        certificate: ICertificate,
        domain_name: str,
        associate_domain_name: bool = True,
        default_behavior: BehaviorOptions | None = None,
        alb_origin: AlbOriginProps | None = None,
        additional_behaviors: dict[str, BehaviorOptions] | None = None,
        web_acl_id: str | None = None,
        allowed_countries: Sequence[str] | None = ALLOWED_COUNTRIES,
        access_logs: bool = True,
        log_retention_days: int = 90,
        log_format: LogFormat = "w3c",
        price_class: PriceClass = PriceClass.PRICE_CLASS_100,
        minimum_protocol_version: SecurityPolicyProtocol = (
            SecurityPolicyProtocol.TLS_V1_2_2021
        ),
        comment: str | None = None,
    ) -> None:
        super().__init__(scope, id)

        self._env = env
        self._namespace = namespace
        self._region_short = self._resolve_region_short()
        self._validate_namespace()
        self._validate_certificate_region(
            certificate, CLOUDFRONT_HOME_REGION, "CloudFront certificates"
        )

        self.alb: ApplicationLoadBalancer | None = None
        self.alb_security_group: SecurityGroup | None = None
        self.listener: ApplicationListener | None = None
        self.target_group: ApplicationTargetGroup | None = None
        self.origin_certificate: ICertificate | None = None
        self.origin: IOrigin | None = None

        if alb_origin is not None and default_behavior is not None:
            raise Exception("default_behavior and alb_origin are mutually exclusive")

        if alb_origin is not None:
            if alb_origin.certificate is not None:
                self._validate_certificate_region(
                    alb_origin.certificate,
                    Stack.of(self).region,
                    "Load balancer certificates",
                )
            default_behavior = self._build_alb_origin(alb_origin, domain_name)

        if default_behavior is None:
            raise Exception("Either default_behavior or alb_origin must be set")

        cf_name = self._resource_name("cf")

        self.distribution = Distribution(
            self,
            "Default",
            domain_names=[domain_name] if associate_domain_name else None,
            certificate=certificate,
            default_behavior=default_behavior,
            additional_behaviors=additional_behaviors or {},
            web_acl_id=web_acl_id,
            geo_restriction=(
                GeoRestriction.allowlist(*allowed_countries)
                if allowed_countries is not None
                else None
            ),
            comment=f"{cf_name}: {comment}" if comment else cf_name,
            price_class=price_class,
            enabled=True,
            enable_ipv6=True,
            http_version=HttpVersion.HTTP2_AND_3,
            minimum_protocol_version=minimum_protocol_version,
            ssl_support_method=SSLMethod.SNI,
        )

        Tags.of(self.distribution).add("Name", cf_name)

        self.log_bucket: Bucket | None = None
        if access_logs:
            self.log_bucket = self._build_access_logs(log_format, log_retention_days)

        CfnOutput(
            self,
            "DistributionId",
            description="ID of the CloudFront distribution",
            value=self.distribution.distribution_id,
        )
        CfnOutput(
            self,
            "DistributionDomainName",
            description="CloudFront domain name to point your DNS records at",
            value=self.distribution.distribution_domain_name,
        )

    def _resource_name(self, resource_type: str) -> str:
        """Build a name following `<env>-<region-short>-<type>-<namespace>`."""
        return f"{self._env}-{self._region_short}-{resource_type}-{self._namespace}"

    def _resolve_region_short(self) -> str:
        """Abbreviate the stack's region: first segment, the initial of each middle
        segment, then the last: eu-west-2 -> euw2, ap-southeast-1 -> aps1.
        """
        region = Stack.of(self).region
        if Token.is_unresolved(region):
            raise Exception(
                "Resource names include a region short code, so this construct needs an "
                "environment-specific stack. Pass env=Environment(account=..., region=...) "
                "when creating the stack."
            )
        head, *middle, number = region.split("-")
        return head + "".join(part[0] for part in middle) + number

    def _validate_namespace(self) -> None:
        """Fail at synth rather than several minutes into a deploy."""
        if not NAMESPACE_PATTERN.fullmatch(self._namespace):
            raise Exception(
                f"namespace must be 2 to 18 characters of lowercase alphanumeric and "
                f"hyphens, and must not start or end with a hyphen, but was "
                f"'{self._namespace}' ({len(self._namespace)} characters)"
            )

    def _build_access_logs(
        self,
        log_format: LogFormat,
        log_retention_days: int,
    ) -> Bucket:
        """Wire up CloudFront standard logging (v2).

        v2 is not a property of the distribution. It is three CloudWatch Logs objects that
        reference the distribution by ARN, and AWS requires them in us-east-1 because
        CloudFront delivers its logs from there. Rather than push a second stack onto every
        consumer, they are created through SDK calls targeted at that region, so a team
        still deploys one stack. The destination bucket itself has no region constraint and
        stays alongside everything else.
        """
        stack = Stack.of(self)

        logs_arn_prefix = (
            f"arn:{stack.partition}:logs:{CLOUDFRONT_HOME_REGION}:{stack.account}"
        )

        bucket = Bucket(
            self,
            "AccessLogs",
            bucket_name_prefix=f"{self._env}-s3-{self._namespace}",
            bucket_namespace=BucketNamespace.ACCOUNT_REGIONAL,
            object_ownership=ObjectOwnership.BUCKET_OWNER_ENFORCED,
            encryption=BucketEncryption.S3_MANAGED,
            block_public_access=BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            versioned=True,
            lifecycle_rules=[
                LifecycleRule(
                    expiration=Duration.days(log_retention_days),
                    noncurrent_version_expiration=Duration.days(5),
                    abort_incomplete_multipart_upload_after=Duration.days(2),
                )
            ],
            removal_policy=RemovalPolicy.RETAIN,
        )

        bucket.add_to_resource_policy(
            PolicyStatement(
                sid="AWSLogsDeliveryWrite",
                principals=[ServicePrincipal("delivery.logs.amazonaws.com")],
                actions=["s3:PutObject"],
                resources=[bucket.arn_for_objects("*")],
                conditions={
                    "StringEquals": {"aws:SourceAccount": stack.account},
                    "ArnLike": {"aws:SourceArn": f"{logs_arn_prefix}:delivery-source:*"},
                },
            )
        )

        base_name = self._resource_name("logs")
        destination_name = f"{base_name}-{log_format}"

        policy = AwsCustomResourcePolicy.from_statements(
            [
                PolicyStatement(
                    actions=[
                        "logs:PutDeliverySource",
                        "logs:GetDeliverySource",
                        "logs:DeleteDeliverySource",
                        "logs:PutDeliveryDestination",
                        "logs:GetDeliveryDestination",
                        "logs:DeleteDeliveryDestination",
                        "logs:CreateDelivery",
                        "logs:GetDelivery",
                        "logs:UpdateDeliveryConfiguration",
                        "logs:DeleteDelivery",
                    ],
                    resources=[
                        f"{logs_arn_prefix}:delivery-source:*",
                        f"{logs_arn_prefix}:delivery-destination:*",
                        f"{logs_arn_prefix}:delivery:*",
                    ],
                ),
                PolicyStatement(
                    actions=["cloudfront:AllowVendedLogDeliveryForResource"],
                    resources=[self.distribution.distribution_arn],
                ),
            ]
        )

        source_call = AwsSdkCall(
            service=LOGS_SDK_CLIENT,
            action="PutDeliverySource",
            region=CLOUDFRONT_HOME_REGION,
            parameters={
                "name": base_name,
                "resourceArn": self.distribution.distribution_arn,
                "logType": "ACCESS_LOGS",
            },
            physical_resource_id=PhysicalResourceId.of(base_name),
        )
        source = AwsCustomResource(
            self,
            "LogDeliverySource",
            on_create=source_call,
            on_update=source_call,
            on_delete=AwsSdkCall(
                service=LOGS_SDK_CLIENT,
                action="DeleteDeliverySource",
                region=CLOUDFRONT_HOME_REGION,
                parameters={"name": base_name},
                ignore_error_codes_matching="ResourceNotFoundException",
            ),
            policy=policy,
            install_latest_aws_sdk=False,
        )

        destination_call = AwsSdkCall(
            service=LOGS_SDK_CLIENT,
            action="PutDeliveryDestination",
            region=CLOUDFRONT_HOME_REGION,
            parameters={
                "name": destination_name,
                "deliveryDestinationConfiguration": {
                    "destinationResourceArn": bucket.bucket_arn
                },
                "outputFormat": log_format,
            },
            physical_resource_id=PhysicalResourceId.of(destination_name),
        )
        destination = AwsCustomResource(
            self,
            "LogDeliveryDestination",
            on_create=destination_call,
            on_update=destination_call,
            on_delete=AwsSdkCall(
                service=LOGS_SDK_CLIENT,
                action="DeleteDeliveryDestination",
                region=CLOUDFRONT_HOME_REGION,
                parameters={"name": destination_name},
                ignore_error_codes_matching="ResourceNotFoundException",
            ),
            policy=policy,
            install_latest_aws_sdk=False,
        )

        s3_delivery_configuration = {
            "suffixPath": "{DistributionId}/{yyyy}/{MM}/{dd}",
            "enableHiveCompatiblePath": True,
        }
        delivery = AwsCustomResource(
            self,
            f"LogDelivery-{destination_name}",
            on_create=AwsSdkCall(
                service=LOGS_SDK_CLIENT,
                action="CreateDelivery",
                region=CLOUDFRONT_HOME_REGION,
                parameters={
                    "deliverySourceName": base_name,
                    "deliveryDestinationArn": destination.get_response_field(
                        "deliveryDestination.arn"
                    ),
                    "s3DeliveryConfiguration": s3_delivery_configuration,
                },
                physical_resource_id=PhysicalResourceId.from_response("delivery.id"),
            ),
            on_update=AwsSdkCall(
                service=LOGS_SDK_CLIENT,
                action="UpdateDeliveryConfiguration",
                region=CLOUDFRONT_HOME_REGION,
                parameters={
                    "id": PhysicalResourceIdReference(),
                    "s3DeliveryConfiguration": s3_delivery_configuration,
                },
            ),
            on_delete=AwsSdkCall(
                service=LOGS_SDK_CLIENT,
                action="DeleteDelivery",
                region=CLOUDFRONT_HOME_REGION,
                parameters={"id": PhysicalResourceIdReference()},
                ignore_error_codes_matching="ResourceNotFoundException",
            ),
            policy=policy,
            install_latest_aws_sdk=False,
        )
        delivery.node.add_dependency(source, bucket.policy)

        return bucket

    def _build_alb_origin(
        self,
        props: AlbOriginProps,
        domain_name: str,
    ) -> BehaviorOptions:

        if props.certificate is not None:
            self.origin_certificate = props.certificate
        elif props.hosted_zone is not None:
            self.origin_certificate = Certificate(
                self,
                "OriginCertificate",
                domain_name=domain_name,
                certificate_name=self._resource_name("acm"),
                validation=CertificateValidation.from_dns(props.hosted_zone),
            )
        else:
            raise Exception(
                "alb_origin needs either certificate, an existing regional certificate "
                "covering domain_name, or hosted_zone, to DNS-validate one the construct "
                "issues"
            )

        self.alb_security_group = SecurityGroup(
            self,
            "AlbSecurityGroup",
            vpc=props.vpc,
            security_group_name=self._resource_name("sg"),
            description="Allows CloudFront VPC origin traffic to reach the internal ALB",
        )
        self.alb_security_group.connections.allow_from(
            PrefixList.from_lookup(
                self,
                "CloudFrontOriginFacing",
                prefix_list_name=CLOUDFRONT_ORIGIN_PREFIX_LIST,
            ),
            Port.HTTPS,
            "CloudFront origin-facing ranges",
        )

        self.alb = ApplicationLoadBalancer(
            self,
            "Alb",
            vpc=props.vpc,
            load_balancer_name=self._resource_name("alb"),
            internet_facing=False,
            security_group=self.alb_security_group,
            vpc_subnets=props.vpc_subnets,
        )
        self.listener = self.alb.add_listener(
            "Https",
            port=443,
            protocol=ApplicationProtocol.HTTPS,
            certificates=[self.origin_certificate],
            ssl_policy=SslPolicy.RECOMMENDED_TLS,
            open=False,
        )
        self.target_group = self.listener.add_targets(
            "Default",
            target_group_name=self._resource_name("tg"),
            port=props.target_port,
            protocol=props.target_protocol,
            targets=props.targets,
            health_check=HealthCheck(path=props.health_check_path),
        )

        self.origin = VpcOrigin.with_application_load_balancer(
            self.alb,
            domain_name=domain_name,
            vpc_origin_name=self._resource_name("vpco"),
            protocol_policy=OriginProtocolPolicy.HTTPS_ONLY,
            https_port=443,
            origin_ssl_protocols=[OriginSslPolicy.TLS_V1_2],
            read_timeout=Duration.seconds(30),
        )

        return BehaviorOptions(
            origin=self.origin,
            viewer_protocol_policy=ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
            allowed_methods=AllowedMethods.ALLOW_ALL,
            origin_request_policy=OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
            # Caching is off because the construct cannot know whether what sits behind the
            # load balancer is safe to cache. Opt in per path with additional_behaviors.
            cache_policy=CachePolicy.CACHING_DISABLED,
            compress=True,
        )

    @staticmethod
    def _validate_certificate_region(
        certificate: ICertificate, expected_region: str, what: str
    ) -> None:
        """Fail at synth rather than at deploy when given a certificate from the wrong region.

        Imported certificates can carry a token ARN, in which case the region is
        unknowable until deploy time and CloudFormation has to be the one to complain.
        Whether the certificate covers the domain is not knowable here at all, because
        ICertificate exposes nothing but the ARN.
        """
        arn = certificate.certificate_arn
        if Token.is_unresolved(arn):
            return

        region = Arn.split(arn, ArnFormat.SLASH_RESOURCE_NAME).region
        if region != expected_region:
            raise Exception(
                f"{what} must be issued in {expected_region}, but {arn} is in {region}"
            )
