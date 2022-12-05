from cdk8s import App, Chart

from ca_cdk_constructs.eks.external_secrets import (
    ExternalSecretSource,
    ExternalSecretStore,
    ExternalSecret,
)


# to update the snapshot, run:
#   poetry run pytest tests/eks/external_secrets/test_external_secrets.py --snapshot-update
def test_external_secret(snapshot):
    ssm_secret_name = "ssm-secret"

    app = App()
    chart = Chart(app, "ExternSecretsChart")

    ExternalSecret(
        chart,
        "secret1",
        secret_source=ExternalSecretSource(
            store=ExternalSecretStore.VAULT,
            k8s_secret_name="app-vault-secret",
            source_secret="path/to/secret",
            secret_mappings={"key": "ENV_VAR", "key.two": ""},
        ),
        metadata={
            "name": "app-vault-secret",
            "annotations": {"hello": "world"},
            "labels": {"foo": "bar"},
        },
    )

    source2 = ExternalSecretSource(
        store=ExternalSecretStore.AWS_SSM,
        k8s_secret_name="app-db-secret",
        source_secret=ssm_secret_name,
        secret_mappings={"username": "DB_USER"},
    )

    ExternalSecret(chart, "secret2", source2, {"name": "app-db-secret"})

    assert app.synth_yaml() == snapshot
