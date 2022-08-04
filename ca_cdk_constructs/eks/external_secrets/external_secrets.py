from typing import List
from aws_cdk import Stack

from cdk8s import Chart
from aws_cdk.aws_eks import KubernetesPatch, ICluster
import cdk8s_plus_21
from constructs import Construct

from ca_cdk_constructs.eks.external_secrets.external_secret import ExternalSecret
from ca_cdk_constructs.eks.external_secrets.external_secret_source import (
    ExternalSecretSource,
)


class ExternalSecrets(Construct):
    """Collect external secret from AWS Secrets Manager or Vault.

    Requires existing external secrets SecretStore(s), possibly created by a different workflow as explained in https://external-secrets.io/v0.5.8/api-overview/#secretstore

    ## Example

    ```
    from ca_cdk_constructs.eks.external_secrets import ExternalSecrets, ExternalVaultSecretSource, ExternalAWSSMSecretSource

    app = k8s.App()
    chart = Chart(app, "Myservice")

    # a SSM secret that needs passing to the pods
    secr = Secret(...)
    role = Role(...)
    secr.grant_read(role)
    # IRSA to access the secret
    ServiceAccount(
            self,
            "ExternalSecretsKubernetesServiceAccount",
            namespace="myapp-namespace",
            name="external-secrets-aws", # match the name in the SecretStore, see above
            cluster=cluster
    )


    # define the external secrets
    secrets=ExternalSecrets(self, "ExternalSecrets",
        chart=chart,
        secret_sources=[
            ExternalVaultSecret(
                k8s_secret_name="vault",
                secret="devops/newrelic",
                secret_mappings={"key": "NEW_RELIC_KEY"},
            ),
            ExternalAWSSMSecret(
                k8s_secret_name="secretsmanager-secret",
                secret=secr,
                secret_mappings={"key": "NEW_RELIC_KEY", "BLAH": ""},
            ),
        ],
    )
    ```

    ###  Using with cdk8s

    ```
    deployment = Deployment(chart, ........)

    ## add to cdk8s containers
    secrets.add_to_containers(containers=deployment.containers)
    ```

    ## Using with helm, requires that the chart exposes overrides for the generated secrets
    ```
    helm_overrides = {
        "secrets" : secrets.k8s_secret_names
    }
    ```

    ## finally, deploy the chart
    ```
    cluster.add_cdk8s_chart("ExternalSecretsDeployment", secrets.chart)

    ```
    """

    def __init__(
        self,
        scope: Construct,
        id: str,
        chart: Chart,
        secret_sources: List[ExternalSecretSource],
    ) -> None:
        super().__init__(scope, id)
        self.chart = chart
        self.secret_sources = secret_sources
        for secret_source in self.secret_sources:
            self.create_external_secret(secret_source)

    def add_to_containers(self, containers: list[cdk8s_plus_21.Container]):
        for container in containers:
            for secret_source in self.secret_sources:
                self.add_secret_to_container(container, secret_source)

    def create_external_secret(self, secret_source: ExternalSecretSource) -> ExternalSecret:
        return ExternalSecret(
            self.chart,
            f"{secret_source.k8s_secret_name}ExternalSecret",
            k8s_secret_name=secret_source.k8s_secret_name,
            secret_store=secret_source.secret_store(),
            secret_mappings={secret_source.secret_source_id(): secret_source.secret_mappings},
        )

    def add_secret_to_container(
        self, container: cdk8s_plus_21.Container, secret_source: ExternalSecretSource
    ):
        container.env.copy_from(
            cdk8s_plus_21.Env.from_secret(
                cdk8s_plus_21.Secret.from_secret_name(name=secret_source.k8s_secret_name)
            )
        )

    @property
    def k8s_secret_names(self) -> list[str]:
        """
        Returns:
            list[str]: a list containing the names of the k8s secrets that would be created by ExternalSecrets
        """
        return [s.k8s_secret_name for s in self.secret_sources]

    @property
    def container_secret_refs(self) -> list[dict[str, str]]:
        """
        Returns:
            list[dict[str,str]]: a list of container `envFrom` references to all k8s secrets created by ExternalSecrets
        """
        return [{"secretRef": s.k8s_secret_name} for s in self.secret_sources]
