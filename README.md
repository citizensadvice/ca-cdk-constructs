# CDK constructs

To be used with the AWS CDK for Python

### Core

<details>
  <summary>DomainProperties (Plain object)</summary>

A conventional way to generate DNS names

```python
from ca_cdk_constructs import DomainProperties

domain_props = DomainProperties(sub_domain="myapp", zone_domain="qa.acme.org")
domain_props.zone_domain  # qa.acme.org
domain_props.domain  # returns myapp.qa.acme.org
domain_props.ingress_domain  # returns myapp-ingress.qa.acme.org

# indicating a top level domain
domain_props = DomainProperties(sub_domain="", zone_domain="myapp.acme.org")

domain_props.zone_domain  # myapp.acme.org
domain_props.domain  # returns myapp.acme.org
domain_props.ingress_domain  # returns myapp-ingress.myapp.acme.org
```

</details>

### Edge services

<details>
    <summary>Web Application Firewall</summary>

Deploys AWS WAF using a
vendored [AWS WAF Security Automations v3.2.0](https://github.com/awslabs/aws-waf-security-automations/tree/v3.2.0)
template.
For the available WAF configuration options see the "Parameters" section in
the [original template](ca_cdk_constructs/edge_services/assets/aws-waf-security-automations.json)

```python
from ca_cdk_constructs.edge_services.waf_stack import WafStack

WafStack(app, "Waf", params={
    "ActivateCrossSiteScriptingProtectionParam": "no",
    "ActivateSqlInjectionProtectionParam": "no",
    # ....
})

```

</details>

<details>
  <summary>ProtectedCloudfront</summary>

[protected_cloudfront](ca_cdk_constructs/edge_services/protected_cloudfront.py)

Creates a Cloudfront distribution protected by AWS WAF. The distribution forwards a custom header
that can be requested by downstream load balancers in order to prevent traffic from hitting them directly.

Usage:

```python
from aws_cdk import App, Stack
from aws_cdk.aws_eks import HelmChart
from ca_cdk_constructs.edge_services.protected_cloudfront import ProtectedCloudfrontStack
import json

app = App()

hosted_zone =  # create or import a hosted zone

# creates Cloudfront protected by WAF at myapp.<hosted_zone_domain>
cdn = ProtectedCloudfrontStack(app, "ca-referrals",
                               hosted_zone=hosted_zone,
                               sub_domain="myapp",
                               origin_domain="my-loadbalancer-url")

# retrieve the secret header which must be added to the load balancer in order
# to prevent users bypassing the CDN ( and the WAF )
cdn.secret_header
# or
cdn.SECRET_HEADER_NAME
# and
cdn.secret_header_value

# To add the header to e.g. Kubernetes ALB ingress use:

k8s_deployment_stack = Stack(app, "K8sDeployment")
# add the header to the ALB ingress
chart_overrides = {
    "web": {
        "ingress": {
            "annotations": {
                "alb.ingress.kubernetes.io/conditions.main": json.dumps(
                    [
                        # other config can go here
                        cdn.alb_ingress_header_config_annotation
                    ]
                )
            }
        }
    }
}

HelmChart(k8s_deployment_stack, "myapp", cluster=cluster, namespace="myapp-namespace", values=chart_overrides)
```

</details>

### Kubernetes / AWS EKS

`ca_cdk_constructs` includes a vendored cdk8s library which can be imported with:

```python
import ca_cdk_constructs.eks.imports.k8s as k8s

k8s.KubeDeployment(.....)
```

The library is compatible with
the [current CA Kubernetes platform version](https://citizensadvice.atlassian.net/wiki/spaces/OPS/pages/2874441735/Current+version)

<details>
  <summary>EksClusterIntegration</summary>

Makes it possible to deploy to imported EKS clusters.

```python
from ca_cdk_constructs.eks import EksClusterIntegration

# in an existing stack
eks_integration = EksClusterIntegration(self, "EksIntegration", vpc=vpc, cluster_name="mycluster")

# for imported clusters the kubectl role must be manually added to aws-auth
# The role ARN will also be available in the K8sAuthRoleArn output
eks_integration.role
# the EKS cluster
eks_integration.cluster
```

</details>

<details>
  <summary>ExternalSecrets</summary>

Deploys K8s [External Secrets](https://external-secrets.io/v0.5.8/)

See [external_secrets](./ca_cdk_constructs/eks/external_secrets/external_secrets.py)

</details>

## Tests

```shell
poetry install

poetry run pytest
```
