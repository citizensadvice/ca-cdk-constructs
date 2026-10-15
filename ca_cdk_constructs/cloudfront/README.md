# CloudFrontDistribution

A CloudFront distribution with CA's default hardening applied: TLSv1.2_2021 minimum, SNI,
HTTP/2 and HTTP/3, IPv6, price class 100, and access logging on by default.

It works in one of two modes: pass `default_behavior` to front an origin you already have,
or `alb_origin` to have the construct build an internal load balancer and serve from that.

## Reference

### `CloudFrontDistribution`

| Argument | Type | Default | Description | Validation |
| --- | --- | --- | --- | --- |
| `scope` | `Construct` | required | Usually `self`. | The stack must be environment-specific. A token region raises at synth. |
| `id` | `str` | required | Construct id. | — |
| `env` | `"dev" \| "pre" \| "prod"` | required | First segment of every resource name. | Type checker only. |
| `namespace` | `str` | required | Last segment of every resource name. Must be unique per account and region. | `^[a-z0-9][a-z0-9-]{0,16}[a-z0-9]$`, i.e. 2 to 18 characters. Raises at synth. |
| `certificate` | `ICertificate` | required | The viewer certificate. | Must be issued in us-east-1. Raises at synth, unless the ARN is an unresolved token. |
| `domain_name` | `str` | required | The service's hostname. Served as the alias unless `associate_domain_name` is `False`. In ALB mode also the name CloudFront presents to the load balancer, which it stays either way. | Not checked here. CloudFront rejects it at deploy if `certificate` does not cover it. |
| `associate_domain_name` | `bool` | `True` | Serve `domain_name` as the distribution's alternate domain name. Set `False` for a side-by-side migration. See [Migration](#migrating-an-existing-distribution). | — |
| `default_behavior` | `BehaviorOptions \| None` | `None` | The default behaviour, including the origin. | Mutually exclusive with `alb_origin`, and one of the two is required. Raises at synth. |
| `alb_origin` | `AlbOriginProps \| None` | `None` | Build an internal ALB and serve from it. | As above, and needs either its `certificate` or its `hosted_zone`. Raises at synth. |
| `additional_behaviors` | `dict[str, BehaviorOptions] \| None` | `None` | Path pattern to behaviour. Matched in insertion order, first match wins. | — |
| `web_acl_id` | `str \| None` | `None` | Unique identifier that specifies the AWS WAF web ACL to associate with this distribution. The ACL ARN for AWS WAFv2, or the ACL ID for AWS WAF Classic. | Not checked here. Must be `CLOUDFRONT` scoped or CloudFormation fails at deploy. |
| `allowed_countries` | `Sequence[str] \| None` | GB, JE, GG, IM, IE | ISO 3166-1 alpha-2 codes of the countries to serve. `None` serves everywhere. | Country code format checked by CDK at synth. |
| `access_logs` | `bool` | `True` | Deliver access logs using standard logging v2. | — |
| `log_retention_days` | `int` | `90` | Lifecycle expiry on the log bucket. | — |
| `log_format` | `"w3c" \| "parquet"` | `"w3c"` | Output format for delivered logs. | Type checker only. Changing it replaces the log delivery. |
| `price_class` | `PriceClass` | `PRICE_CLASS_100` | The edge locations to serve from. | — |
| `minimum_protocol_version` | `SecurityPolicyProtocol` | `TLS_V1_2_2021` | Lowest TLS version a viewer may negotiate. | — |
| `comment` | `str \| None` | `None` | Appended to the resource name in the console's Description column. | CDK silently truncates the combined string at 128 characters. |

### `AlbOriginProps`

Only used in ALB mode.

| Argument | Type | Default | Description | Validation |
| --- | --- | --- | --- | --- |
| `vpc` | `IVpc` | required | The VPC to place the load balancer in. | — |
| `targets` | `list[IApplicationLoadBalancerTarget]` | `[]` | What the load balancer forwards to, for example an ECS service. | — |
| `target_port` | `int` | `80` | The port the targets listen on. | — |
| `target_protocol` | `ApplicationProtocol` | `HTTP` | Protocol between load balancer and targets. The CloudFront hop is always HTTPS regardless. | — |
| `health_check_path` | `str` | `"/"` | Path the load balancer polls for target health. | — |
| `vpc_subnets` | `SubnetSelection \| None` | `None` | Where to place the load balancer. Defaults to the VPC's private subnets. | — |
| `certificate` | `ICertificate \| None` | `None` | An existing regional certificate for the listener. Supply this rather than vending a second one for a domain that already has one. | Must be in the stack's own region. Raises at synth, unless the ARN is an unresolved token. Whether it covers `domain_name` cannot be checked. |
| `hosted_zone` | `IHostedZone \| None` | `None` | Used to DNS-validate the certificate the construct issues for the load balancer. | Required unless `certificate` is supplied. Raises at synth. |

### Attributes

| Attribute | Type | Notes |
| --- | --- | --- |
| `distribution` | `Distribution` | Always set. |
| `log_bucket` | `Bucket \| None` | `None` when `access_logs=False`. |
| `alb` | `ApplicationLoadBalancer \| None` | ALB mode only. |
| `listener` | `ApplicationListener \| None` | ALB mode only. The HTTPS listener, for adding rules. |
| `target_group` | `ApplicationTargetGroup \| None` | ALB mode only. |
| `alb_security_group` | `SecurityGroup \| None` | ALB mode only. Locked to the CloudFront prefix list. |
| `origin_certificate` | `ICertificate \| None` | ALB mode only. Whichever certificate ended up on the listener, yours or the one the construct issued. |
| `origin` | `IOrigin \| None` | ALB mode only. Pass to `add_behavior` to cache a path. See [Caching](#caching). |

The construct also emits `DistributionId` and `DistributionDomainName` as stack outputs.

## Standalone mode

Pass `default_behavior` to front an origin you already have. The construct stays out of the
way and applies the certificate, alias and hardened settings around it.

```python
from aws_cdk import Environment, Stack
from aws_cdk.aws_certificatemanager import Certificate
from aws_cdk.aws_cloudfront import BehaviorOptions
from aws_cdk.aws_cloudfront_origins import S3BucketOrigin

from ca_cdk_constructs.cloudfront import CloudFrontDistribution

dist = CloudFrontDistribution(
    self,
    "Cdn",
    env="prod",
    namespace="casebook",
    # Must be issued in us-east-1. See "Certificates" below.
    certificate=Certificate.from_certificate_arn(self, "ViewerCert", cert_arn),
    domain_name="casebook.citizensadvice.org.uk",
    default_behavior=BehaviorOptions(origin=S3BucketOrigin.with_origin_access_control(bucket)),
)

dist.distribution  # the underlying aws_cloudfront.Distribution
dist.log_bucket  # the access log bucket, or None when access_logs=False
```

## ALB mode

Pass `alb_origin` instead and the construct builds an internal Application Load Balancer,
issues a regional certificate for it, locks its security group to the CloudFront
origin-facing prefix list, and wires it up as a VPC origin. The load balancer is never
publicly reachable. CloudFront reaches it over the VPC origin service rather than the
internet.

```python
from ca_cdk_constructs.cloudfront import AlbOriginProps, CloudFrontDistribution

dist = CloudFrontDistribution(
    self,
    "Cdn",
    env="prod",
    namespace="casebook",
    certificate=Certificate.from_certificate_arn(self, "ViewerCert", cert_arn),
    domain_name="casebook.citizensadvice.org.uk",
    alb_origin=AlbOriginProps(
        vpc=vpc,
        targets=[ecs_service],
        target_port=8080,
        # Needed to DNS-validate the certificate the construct issues for the load
        # balancer. Pass `certificate=...` instead if you already have one.
        hosted_zone=hosted_zone,
    ),
)

dist.alb  # ApplicationLoadBalancer
dist.listener  # ApplicationListener, for adding rules
dist.target_group  # ApplicationTargetGroup
dist.alb_security_group  # SecurityGroup
dist.origin  # the VPC origin, for attaching extra cache behaviours
```

## Caching

In ALB mode the default behaviour caches nothing. Every request reaches your application.
You then opt individual paths into caching.

That is the deliberate direction, and it is worth understanding before you change it. If the
default cached and one route turned out to be user-specific, CloudFront would serve one
person's page to another. Getting it wrong in the other direction only makes the site slow.
The construct cannot know what sits behind your load balancer, so it takes the option whose
failure mode is a performance problem rather than a data leak.

### Adding a cached path

Use `add_behavior` on the underlying distribution, passing the origin the construct built:

```python
from aws_cdk.aws_cloudfront import AllowedMethods, CachePolicy, ViewerProtocolPolicy

dist = CloudFrontDistribution(
    self,
    "Cdn",
    ...,
    alb_origin=AlbOriginProps(vpc=vpc, targets=[service], hosted_zone=hosted_zone),
)

# Rails fingerprints these filenames, so a given URL's content can never change.
for pattern in ("/assets/*", "/packs/*"):
    dist.distribution.add_behavior(
        pattern,
        dist.origin,
        cache_policy=CachePolicy.CACHING_OPTIMIZED,
        allowed_methods=AllowedMethods.ALLOW_GET_HEAD,
        viewer_protocol_policy=ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        compress=True,
    )
```

Dynamic pages still reach the application. The two static prefixes are served from the edge,
which on a typical page is most of the requests.

`add_behavior` is used rather than the `additional_behaviors` argument because every
behaviour needs an origin, and in ALB mode the construct builds that origin itself, so it
does not exist until after the constructor has run. `additional_behaviors` is still the
right choice when the extra behaviour points somewhere else, an S3 bucket of precompiled
assets for example, since you already hold that origin.

## Certificates

The viewer certificate is supplied by the caller and must be in us-east-1. The construct
does not vend it, because one CloudFormation stack is one region, so vending would mean
silently adding a second stack to your app. Either create it in a us-east-1 stack, or pass
one that already exists with `Certificate.from_certificate_arn`. A certificate from any
other region is rejected at synth.

In ALB mode the load balancer needs its own certificate, which is regional and therefore not
subject to that constraint. Supply one with `AlbOriginProps(certificate=...)`, or leave it
unset and pass `hosted_zone` instead and the construct issues one.


## Migrating an existing distribution

To replace a distribution you already have, stand the new one up beside it and move the
domain across. CloudFront will not let two distributions hold the same alternate domain
name, so the new one is deployed without it.

```python
dist = CloudFrontDistribution(
    self,
    "Cdn",
    env="prod",
    namespace="casebook",
    certificate=Certificate.from_certificate_arn(self, "ViewerCert", cert_arn),
    domain_name="casebook.citizensadvice.org.uk",
    associate_domain_name=False,
    alb_origin=AlbOriginProps(
        vpc=vpc,
        targets=[ecs_service],
        # The certificate this service already has. See "Certificates".
        certificate=existing_regional_certificate,
    ),
)
```

The certificate stays attached even with no alias. That is not an oversight: AWS requires a
covering certificate on the target of a domain move, and the move is what adds the alias.
CDK warns about the empty domain names, which is a useful reminder rather than a problem.

### The sequence

The order matters, and getting it wrong takes the site down.

1. **Deploy.** Test on the `DistributionDomainName` output, which is the
   `d111....cloudfront.net` name.
2. **Move the domain**, in two commands.

   **2a. Get the ETag of the new distribution**, the one with no alias.

   ```sh
   NEW_ID=<new distribution id>
   aws cloudfront get-distribution --id "$NEW_ID" --query ETag --output text
   ```

   **2b. Move it.** This removes the alias from the old distribution and adds it to the new
   one:

   ```sh
   aws cloudfront update-domain-association \
     --domain casebook.citizensadvice.org.uk \
     --target-resource DistributionId="$NEW_ID" \
     --if-match <the ETag from 2a>
   ```

   Traffic follows immediately, before you touch DNS, because CloudFront matches a request
   to a distribution by `Host` header rather than by which distribution domain was resolved.
3. **Reconcile both stacks, straight away.** Set `associate_domain_name=True` here and
   deploy, and remove the alias from the old stack and deploy that. Both are no-ops against
   live state. They exist only to stop CloudFormation undoing step 2.

   Leave this and the next deploy of the new stack strips the alias and takes the site down,
   while the next deploy of the old stack fails with `CNAMEAlreadyExists`. Nobody should
   touch either stack until this step is done.
4. **Update DNS** to the new distribution domain name. Both A and AAAA, per [DNS](#dns).


## DNS

The construct creates no DNS records, and it enables IPv6. You need **both** an A and an
AAAA alias pointing at the distribution.

An A-only setup looks completely fine from a desk and fails silently for anyone on an
IPv6-only mobile network. Route 53's default negative-cache TTL is 86400, so a missing AAAA
record can stay cached for a day after you add it.

## Geographic restriction

Geographic restriction is on by default. It allowlists GB, JE, GG, IM and IE, so viewers
located anywhere else get a 403 instead of your content.

Pass `allowed_countries` to serve a different set of countries:

```python
CloudFrontDistribution(
    self,
    "Distribution",
    ...,
    allowed_countries=["GB", "IE", "FR"],
)
```

It applies to the whole distribution. There is no way to restrict one path and not another.

To disable geo restriction and serve everywhere, set `allowed_countries=None` explicitly.

## Access logging

On by default, using CloudFront standard logging v2. Legacy logging is not an option at CA,
because it requires S3 ACLs and those are blocked org-wide.

Logs are delivered to a bucket the construct creates and exposes as `log_bucket`, versioned,
SSE-S3 encrypted, public access blocked, and expiring after `log_retention_days` (90 by
default). CloudFront never deletes log files itself, so without that expiry the bucket grows
forever. The bucket is retained when the stack is deleted.

Supplying your own bucket is not supported, because CDK cannot attach the required delivery
policy to an imported bucket and the failure would be silent.

Two things worth knowing:

- `log_format` defaults to `"w3c"`, which matches the legacy CloudFront layout and costs
  nothing extra. `"parquet"` is far cheaper to query in Athena but incurs CloudWatch
  conversion charges. Changing it later creates a new delivery before removing the old
  one, so both formats may land in the bucket briefly during the deploy.
- Logs can take up to an hour to appear. That is normal, not a broken configuration.

## Naming

Every resource is named `<env>-<region-short>-<type>-<namespace>`, for example
`prod-euw2-alb-casebook`. `namespace` is capped at 18 characters by the 32 character
limit on load balancer names, and must be unique per account and region.

The log bucket is the exception. It uses S3's account-regional namespace, so CloudFormation
appends the account and region and the name reads `prod-s3-casebook-<account>-<region>-an`.

Because the load balancer, target group and security group have explicit physical names,
CloudFormation cannot replace them in place. Any update that requires a replacement is
delete-then-create, which means downtime.

## Requirements

The stack must be environment-specific, i.e. created with
`env=Environment(account=..., region=...)`. Resource names embed a region short code, so the
construct cannot work with a region-agnostic stack and will raise at synth if given one.
