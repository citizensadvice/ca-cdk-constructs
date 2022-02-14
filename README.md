# CDK constructs

To be used with Python AWS CDK

## Available packages

### [protected_cloudfront](cdk_constructs/protected_cloudfront.py)

Creates a Cloudfront distribution protected by AWS WAF

Usage:

```python
import aws_cdk as cdk
from cdk_constructs.protected_cloudfront import ProtectedCloudfrontStack

app = cdk.App()

hosted_zone =  # create or import a hosted zone

# creates Cloudfront protected by WAF at myapp.<hosted_zone_domain>
cdn = ProtectedCloudfrontStack(app, "ca-referrals",
                               hosted_zone=hosted_zone,
                               subdomain="myapp",
                               origin_domain="my-loadbalancer-url")

# retrieve the secret header which must be added to the load balancer in order
# to prevent users bypassing the CDN ( and the WAF )
cdn.secret_header
# or
cdn.SECRET_HEADER_NAME
# and 
cdn.secret_header_value

# To add the header to a Kubernetes ALB ingress configuration use e.g:

chart_overrides =  # set all other required values
# add the header to the ALB ingress
chart_overrides = [{
    "web": {
        "ingress": {
            "annotations": {
                "alb.ingress.kubernetes.io/conditions.main": json.dumps(
                    [
                        {
                            "field": "http-header",
                            "httpHeaderConfig": {
                                "httpHeaderName": cdn.SECRET_HEADER_NAME,
                                "values": [cdn.secret_header_value]
                            }
                        }
                    ]
                )
            }
        }
    }
}]

eks.HelmChart(self, "myapp", values=chart_overrides)
```

## Tests

```shell
pip install cdk-constructs && pip install -r requirements-dev.txt

python -m pytest 
```

