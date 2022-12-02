import cdk8s_plus_23 as cdk8s_plus
from constructs import Construct

from ca_cdk_constructs.eks.external_secrets.external_secret import (
    ExternalSecret,
    ExternalSecretSource,
)


class ExternalSecrets(Construct):
    """Collects external secret from AWS Secrets Manager, Parameter Store or Vault.
    Acts as a container for ExternalSecret.

    ## Example

        from ca_cdk_constructs.eks.external_secrets import ExternalSecrets, ExternalSecretSource

        app = k8s.App()
        chart = Chart(app, "MyService")

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
        secrets=ExternalSecrets(chart, "ExternalSecrets",
            secret_sources=[
                ExternalSecretSource(
                    store=ExternalSecretStore.VAULT,
                    k8s_secret_name="vault",
                    source_secret="devops/newrelic",
                    secret_mappings={"key": "NEW_RELIC_KEY"},
                ),
                ExternalSecretSource(
                    store=ExternalSecretStore.AWS_SSM,
                    k8s_secret_name="secretsmanager-secret",
                    source_secret=secr.secret_name,
                    secret_mappings={"key": "NEW_RELIC_KEY", "BLAH": ""},
                ),
            ],
        )

        secrets.add_external_secret(ExternalSecretSource(
                    store=ExternalSecretStore.VAULT,
                    k8s_secret_name="secretsmanager-secret",
                    source_secret=secr.secret_name,
                    secret_mappings={"key": "NEW_RELIC_KEY", "BLAH": ""},
                )
        )


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
        secret_sources: list[ExternalSecretSource],
    ) -> None:
        super().__init__(scope, id)
        for secret_source in secret_sources:
            self.add_external_secret(secret_source)

    def add_to_containers(self, containers: list[cdk8s_plus.Container]):
        for container in containers:
            for secret_name in self.k8s_secret_names:
                self.add_secret_to_container(container, secret_name)

    def add_external_secret(self, secret_source: ExternalSecretSource) -> ExternalSecret:
        return ExternalSecret.from_external_secret_source(
            self, f"{secret_source.k8s_secret_name}ExternalSecret", secret_source
        )

    def add_secret_to_container(self, container: cdk8s_plus.Container, secret_name: str):
        container.env.copy_from(
            cdk8s_plus.Env.from_secret(
                cdk8s_plus.Secret.from_secret_name(
                    self, f"{secret_name}SecretRef", name=secret_name
                )
            )
        )

    @property
    def k8s_secret_names(self) -> list[str]:
        """
        Returns:
            list[str]: returns the names of all k8s secrets created by ExternalSecrets
        """
        return [
            child.k8s_secret_name
            for child in self.node.children
            if isinstance(child, ExternalSecret)
        ]

    @property
    def container_secret_refs(self) -> list[dict[str, str]]:
        """
        Returns:
            list[dict[str,str]]: a list of container `envFrom` references to all k8s secrets created by ExternalSecrets
        """
        return [{"secretRef": name} for name in self.k8s_secret_names]
