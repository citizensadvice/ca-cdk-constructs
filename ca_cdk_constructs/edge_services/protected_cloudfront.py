from aws_cdk import CfnOutput, Duration, Environment, PhysicalName, RemovalPolicy, Stack
from aws_cdk import aws_certificatemanager as acm
from aws_cdk import aws_cloudfront as cloudfront
from aws_cdk import aws_cloudfront_origins as origins
from aws_cdk import aws_route53 as r53
from aws_cdk import aws_route53_targets as r53_targets
from aws_cdk import aws_s3 as s3
from cdk_remote_stack import RemoteOutputs
from constructs import Construct

from ca_cdk_constructs.edge_services.waf_stack import WafStack


class ProtectedCloudfrontStack(Construct):
    # A WAF protected cloudfront that also sets a "secret" header that can be checked by upstream load balancers to prevent requests bypassing cloudfront
    SECRET_HEADER_NAME = "X-Secret-CF-ALB-Header"

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        hosted_zone: r53.HostedZone,
        sub_domain: str,
        origin_domain: str,
    ) -> None:
        super().__init__(scope, construct_id)
        self.domain_name = f"{sub_domain}.{hosted_zone.zone_name}"

        # the cloudfront log bucket - doesn't need to be us-east-1
        # as no scanners & probes rule
        self._access_logs_bucket = s3.Bucket(
            self,
            "CloudfrontLogsBucket",
            bucket_name=PhysicalName.GENERATE_IF_NEEDED,
            removal_policy=RemovalPolicy.DESTROY,
            lifecycle_rules=[s3.LifecycleRule(enabled=True, expiration=Duration.days(31 * 6))],
        )

        # and waf automations solution stack deployed from the template in the waf_assets/ folder
        self.waf = WafStack(
            self,
            "WafStack",
            params={
                #### CARE!!!!
                # At the moment, in order to be able to add the AWS known bad
                # inputs rule, I've had to effectively hard-code the rule
                # configurations in the *nested* waf template (ie comment out the
                # conditions where the parameter value is "yes" and comment out
                # resources where the parameter value is "no"). If you change the
                # yes/no values here, you MUST make the corresponding changes in
                # waf_assets/nested_template.yaml for them to take effect.
                # See https://citizensadvice.atlassian.net/browse/OPS-4803
                # Priority order set here - leave 2-9 for any custom rules added in
                # addition to this template
                # 0: whitelist rule
                # 1: blacklist rule
                # 10: aws core managed rule - condition commented out
                # NO flood log-parser rule - rule commented out
                # 11: flood rate-based rule - condition commented out
                # NO scanners & probes rule - rule commented out
                # 12: reputation list rule - condition commented out
                # NO bad bot rule - rule commented out
                # 20: sql injection - condition commented out
                # 30: cross-site scripting (xss) - condition commented out
                "ActivateAWSManagedRulesParam": "yes",
                "ActivateSqlInjectionProtectionParam": "yes",
                "ActivateCrossSiteScriptingProtectionParam": "yes",
                "ActivateHttpFloodProtectionParam": "yes - AWS WAF rate based rule",
                "ActivateScannersProbesProtectionParam": "no",
                "ActivateReputationListsProtectionParam": "yes",
                "ActivateBadBotProtectionParam": "no",
                "RequestThreshold": "100",  # default and min for rate based flood protection = 100
            },
            env=Environment(region="us-east-1"),
        )

        # need to get the web acl but can't pass it directly:
        #   "Stack "example/cloudfront" cannot consume a cross reference from stack "example/cloudfront/WafStack.
        #   Cross stack references are only supported for stacks deployed to the same environment or between nested stacks and their parent stack"
        # so this is a workaround - the waf template outputs (in us-east-1) are retrieved by a lambda in eu-west-1
        # RemoteOutputs is provided by the cdk-remote-stack library
        waf_outputs = RemoteOutputs(self, "Outputs", stack=self.waf)

        self._secret_header = Stack.of(self).stack_name

        certificate = acm.DnsValidatedCertificate(
            self,
            "CloudfrontCertificate",
            domain_name=self.domain_name,
            region="us-east-1",
            hosted_zone=hosted_zone,
        )
        http_origin = origins.HttpOrigin(
            domain_name=origin_domain, custom_headers=self.secret_header
        )

        assets_origin_request_policy = cloudfront.OriginRequestPolicy(
            self,
            "StaticAssetsOriginRequestPolicy",
            comment="Forward the Host header for assets",
            header_behavior=cloudfront.OriginRequestHeaderBehavior.allow_list("Host"),
            cookie_behavior=cloudfront.OriginRequestCookieBehavior.none(),
            query_string_behavior=cloudfront.OriginRequestQueryStringBehavior.none(),
        )

        cdn = cloudfront.Distribution(
            self,
            "CdnDistribution",
            domain_names=[self.domain_name],
            enable_logging=True,
            log_bucket=self._access_logs_bucket,
            certificate=certificate,
            web_acl_id=waf_outputs.get("WAFWebACLArn"),
            comment=f"CDN for {Stack.of(self).stack_name}",
            geo_restriction=cloudfront.GeoRestriction.allowlist(
                "GB", "JE", "GG"
            ),  # UK, Jersey and Guernsey
            default_behavior=cloudfront.BehaviorOptions(
                origin=http_origin,
                compress=True,
                cache_policy=cloudfront.CachePolicy.CACHING_DISABLED,
                origin_request_policy=cloudfront.OriginRequestPolicy.ALL_VIEWER,
                allowed_methods=cloudfront.AllowedMethods.ALLOW_ALL,
                cached_methods=cloudfront.CachedMethods.CACHE_GET_HEAD,
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
            ),
        )

        cdn.add_behavior(
            path_pattern="/assets/*",
            origin=http_origin,
            compress=True,
            allowed_methods=cloudfront.AllowedMethods.ALLOW_GET_HEAD,
            cached_methods=cloudfront.CachedMethods.CACHE_GET_HEAD,
            cache_policy=cloudfront.CachePolicy.CACHING_OPTIMIZED,
            origin_request_policy=assets_origin_request_policy,
            viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        )

        cdn.node.add_dependency(self.waf)

        self._cdn = cdn

        CfnOutput(self, "CloudfrontDistributionId", value=cdn.distribution_id)
        CfnOutput(self, "CloudfrontDistributionDomain", value=cdn.distribution_domain_name)
        CfnOutput(self, "SecretHeaderArn", value=self._secret_header)

        alias = r53_targets.CloudFrontTarget(cdn)
        r53.ARecord(
            self,
            "CloudfrontDNS",
            zone=hosted_zone,
            record_name=sub_domain,
            target=r53.RecordTarget.from_alias(alias),
        )

    @property
    def access_logs_bucket(self) -> s3.Bucket:
        return self._access_logs_bucket

    @property
    def cdn(self) -> cloudfront.Distribution:
        return self._cdn

    @property
    def waf_stack(self) -> Stack:
        return self.waf

    @property
    def secret_header_value(self) -> str:
        return self._secret_header

    @property
    def secret_header(self) -> dict:
        return {self.SECRET_HEADER_NAME: self._secret_header}

    @property
    def alb_ingress_header_config_annotation(self) -> dict:
        return {
            "field": "http-header",
            "httpHeaderConfig": {
                "httpHeaderName": self.SECRET_HEADER_NAME,
                "values": [self.secret_header_value],
            },
        }
