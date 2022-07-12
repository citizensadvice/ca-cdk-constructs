from aws_cdk import (CfnOutput, Duration, Environment, PhysicalName,
                     RemovalPolicy, Stack)
from aws_cdk import aws_certificatemanager as acm
from aws_cdk import aws_cloudfront as cloudfront
from aws_cdk import aws_cloudfront_origins as origins
from aws_cdk import aws_route53 as r53
from aws_cdk import aws_route53_targets as r53_targets
from aws_cdk import aws_s3 as s3
from cdk_remote_stack import RemoteOutputs
from constructs import Construct

from cdk_constructs.waf import WafStack


class ProtectedCloudfrontStack(Stack):
    # A WAF protected cloudfront that also sets a "secret" header that can be checked by upstream load balancers to prevent requests bypassing cloudfront
    SECRET_HEADER_NAME = "X-Secret-CF-ALB-Header"

    def __init__(self, scope: Construct, construct_id: str, hosted_zone: r53.HostedZone, sub_domain: str, origin_domain: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        # waf and the cloudfront log bucket must be deployed to us-east-1
        us_east_environment = Environment(region="us-east-1")
        self.domain_name = f"{sub_domain}.{hosted_zone.zone_name}"
        # cloudfront log bucket
        self._access_logs_bucket = s3.Bucket(
            self,
            "CloudfrontLogBucket",
            bucket_name=PhysicalName.GENERATE_IF_NEEDED,
            removal_policy=RemovalPolicy.DESTROY,
            lifecycle_rules=[s3.LifecycleRule(enabled=True, expiration=Duration.days(31 * 6))]
        )

        # the waf automations solution stack deployed from the template in the assets/ folder
        self._waf = WafStack(
            self,
            "WafStack",
            log_requests=False,  # todo
            params={
                "ActivateAWSManagedRulesParam": "no",
                "ActivateSqlInjectionProtectionParam": "yes",
                "ActivateCrossSiteScriptingProtectionParam": "yes",
                "ActivateHttpFloodProtectionParam": "yes",
                "ActivateScannersProbesProtectionParam": "yes",
                "ActivateReputationListsProtectionParam": "yes",
                "ActivateBadBotProtectionParam": "no",
                "AppAccessLogBucket": self._access_logs_bucket.bucket_name
            },
            env=us_east_environment
        )

        # need to get the web acl but can't pass it directly:
        #   "Stack "example/cloudfront" cannot consume a cross reference from stack "example/cloudfront/WafStack.
        #   Cross stack references are only supported for stacks deployed to the same environment or between nested stacks and their parent stack"
        # so this is a workaround - the waf template outputs (in us-east-1) are retrieved by a lambda in eu-west-1
        # RemoteOutputs is provided by the cdk-remote-stack library
        waf_outputs = RemoteOutputs(self, "Outputs", stack=self._waf)

        self._secret_header = self.stack_name

        certificate = acm.DnsValidatedCertificate(self,
                                                  "CloudfrontCertificate",
                                                  domain_name=self.domain_name,
                                                  region="us-east-1",
                                                  hosted_zone=hosted_zone)
        http_origin = origins.HttpOrigin(domain_name=origin_domain,
                                         custom_headers=self.secret_header)

        assets_origin_request_policy = cloudfront.OriginRequestPolicy(
                self,
                "StaticAssetsOriginRequestPolicy",
                comment="Forward the Host header for assets",
                header_behavior=cloudfront.OriginRequestHeaderBehavior.allow_list("Host"),
                cookie_behavior=cloudfront.OriginRequestCookieBehavior.none(),
                query_string_behavior=cloudfront.OriginRequestQueryStringBehavior.none())

        cdn = cloudfront.Distribution(
            self,
            "CdnDistribution",
            domain_names=[self.domain_name],
            enable_logging=True,
            log_bucket=self._access_logs_bucket,
            certificate=certificate,
            web_acl_id=waf_outputs.get("WAFWebACLArn"),
            comment=f"CDN for {self.stack_name}",
            geo_restriction=cloudfront.GeoRestriction.allowlist("GB", "JE", "GG"),  # UK, Jersey and Guernsey
            default_behavior=cloudfront.BehaviorOptions(
                origin=http_origin,
                compress=True,
                cache_policy=cloudfront.CachePolicy.CACHING_DISABLED,
                origin_request_policy=cloudfront.OriginRequestPolicy.ALL_VIEWER,
                allowed_methods=cloudfront.AllowedMethods.ALLOW_ALL,
                cached_methods=cloudfront.CachedMethods.CACHE_GET_HEAD,
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS))

        cdn.add_behavior(path_pattern="/assets/*",
                         origin=http_origin,
                         compress=True,
                         allowed_methods=cloudfront.AllowedMethods.ALLOW_GET_HEAD,
                         cached_methods=cloudfront.CachedMethods.CACHE_GET_HEAD,
                         cache_policy=cloudfront.CachePolicy.CACHING_OPTIMIZED,
                         origin_request_policy=assets_origin_request_policy,
                         viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS)

        cdn.node.add_dependency(self._waf)

        self._cdn = cdn

        CfnOutput(self, "CloudfrontDistributionId", value=cdn.distribution_id)
        CfnOutput(self, "CloudfrontDistributionDomain", value=cdn.distribution_domain_name)
        CfnOutput(self, "SecretHeaderArn", value=self._secret_header)

        alias = r53_targets.CloudFrontTarget(cdn)
        r53.ARecord(self,
                    "CloudfrontDNS",
                    zone=hosted_zone,
                    record_name=sub_domain,
                    target=r53.RecordTarget.from_alias(alias))

    @property
    def access_logs_bucket(self) -> s3.Bucket:
        return self._access_logs_bucket

    @property
    def cdn(self) -> cloudfront.Distribution:
        return self._cdn

    @property
    def waf_stack(self) ->Stack:
        return self._waf

    @property
    def secret_header_value(self) -> str:
        return self._secret_header

    @property
    def secret_header(self) -> dict:
        return {self.SECRET_HEADER_NAME: self._secret_header}
