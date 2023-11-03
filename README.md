# CDK constructs

To be used with the AWS CDK for Python

### Core

### DNS/Edge services

<details>
  <summary>CrossAccountDomainDelegation</summary>

Creates delegated domains

```python
from ca_cdk_constructs import CrossAccountDomainDelegation, R53ParentZoneConfig

zone = PublicHostedZone(self, "Zone", zone_name="my-subdomain.acme.org")

# creates delegation records in for my-subdomain.acme.org in acme.org
CrossAccountDomainDelegation(
    subdomain_stack,
    "MySubdomainDnsDelegation",
    parent_zone_config=R53ParentZoneConfig(
        account_id="1234566789012",
        zone_name="acme.org",
        role_name="R53UpdateRole" # existing role in the parent zone account
    ),
    hosted_zone=zone
)

```

</details>

### Edge services

<details>
    <summary>WAF Rule Templates</summary>

TODO TODO TODO

</details>

### Kubernetes / AWS EKS

`ca_cdk_constructs` includes a vendored cdk8s library that is compatible with the [currently supported CA Kubernetes platform version](https://citizensadvice.atlassian.net/wiki/spaces/OPS/pages/2874441735/Current+version).

You need to update the version of `ca_cdk_constructs` in your project if both of these are correct:

- your project deploys k8s resources using the vendored cdk8s library
- the CA platform was updated to a new version

To vendor the libraries for the [K8s version currently supported by the CA Kubernetes platform](https://citizensadvice.atlassian.net/wiki/spaces/OPS/pages/2874441735/Current+version):

- update the k8s / crd versions in `cdk8s.yaml`
- run `cdk8s import --output ca_cdk_constructs/eks/imports`

The library can be then used as follows:

```python
import ca_cdk_constructs.eks.imports.k8s as k8s

k8s.KubeDeployment(.....)
```

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
  <summary>ExternalAwsSecretsChart</summary>

cdk8s Chart to deploy [External Secrets](https://external-secrets.io/) referencing one or more AWS SecretsManager or ParameterStore secrets.

See [the tests](./tests/eks/external_secrets/test_external_secrets_chart.py)

</details>

### Storage

<details>
  <summary>ModifyDBClusterPassword</summary>

Modifies the password of an Aurora cluster

```python
modify_cluster_password = ModifyDBClusterPassword(self, "ModifyClusterPassword", cluster_id=cluster_id, secret=db_secret)
modify_cluster_password.trigger_on_stack_create_update()
# access the udnerlaying lambda to e.g. add it to a state machine
modify_cluster_password.lambda_funct
```

</details>

<details>
  <summary>AuroraFastClone</summary>

Clones an Aurora cluster.

```python
from ca_cdk_constructs.storage.aurora_clone_refresh import AuroraCloneRefresh

source_cluster = DatabaseCluster(self, "AuroraCluster", ....) # or lookup one
vpc = source_cluster.vpc # or look it up

cluster_pg = CfnDBClusterParameterGroup(
    self,
    "DBClusterParameterGroup",
    description=f"Cluster parameter group for test clone",
    family=source_cluster.engine.parameter_group_family,
    parameters={"log_hostname": 1},
)
cluster_instance_pg = rds.CfnDBParameterGroup(
    self,
    "DBParameterGroup",
    description=f"DB parameter group for test clone instance",
    family=source_cluster.engine.parameter_group_family,
    parameters={"log_hostname": 1},
)

# periodically clone the source cluster
cloned_cluster = AuroraCloneRefresh(self, "TestClone",
                              source_cluster=source_cluster,
                              source_cluster_vpc=vpc,
                              source_cluster_master_username=username,
                              db_instance_class="db.t3.medium",
                              cluster_parameter_group=cluster_pg,
                              instance_parameter_group=cluster_instance_pg,
                                    tags={
                                        "Tag": "Value"
                                    },
                              clone_schedule=Schedule.cron(minute="0", hour="8"),
                              notifications_topic=topic)

# allow access to the clone from certain ranges
cloned_cluster.allow_from(ec2.Peer.ipv4(vpc.vpc_cidr_block))
# or
clone.cluster_sg.allow_....

# access the cloned cluster credentials
cloned_cluster.clone_secret # DatabaseSecret
# the clone SNS topic
cloned_cluster.notifications_topic # Topic

# the event rule
cloned_cluster.event_rule

```

</details>

## Tests

```shell
poetry install

poetry run pytest
```

To run tests against a particular version of python (e.g. 3.10), run `poetry env use 3.10` before `poetry install`. You do need to have that version installed on your system through `brew install python@3.10` first.

## Versioning and deployments

Versioning and depoyments are done via Github releases. Information on creating releases can be found [here](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository#creating-a-release). Please follow the existing convention for version names and use automatic patch notes for consistence unless a major change is being made.

When making a new release, please ensure that the **package version in `pyproject.toml` is updated** with the version matching the tag name.
