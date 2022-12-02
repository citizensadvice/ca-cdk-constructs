from cdk8s import App, Chart

from ca_cdk_constructs.eks.external_secrets import (
    ExternalSecrets,
    ExternalSecretSource,
    ExternalSecretStore, ExternalSecret,
)


# to update the snapshot, run:
#   poetry run pytest tests/eks/external_secrets/test_external_secrets.py --snapshot-update
def test_external_secrets(snapshot):
    ssm_secret_name = "ssm-secret"

    app = App()
    chart = Chart(app, "ExternSecretsChart")

    ext_secrets = ExternalSecrets(
        chart,
        "ExternalSecrets",
        secret_sources=[
            ExternalSecretSource(
                store=ExternalSecretStore.VAULT,
                k8s_secret_name="app-vault-secret",
                source_secret="path/to/secret",
                secret_mappings={"key": "ENV_VAR", "key.two": ""},
                external_secret_name="app-vault-secret",
            )
        ],
    )

    ext_secrets.add_external_secret(
        secret_source=ExternalSecretSource(
            store=ExternalSecretStore.AWS_SSM,
            k8s_secret_name="app-db-secret",
            source_secret=ssm_secret_name,
            secret_mappings={"username": "DB_USER"},
            external_secret_name="app-db-secret",
        ),
    )
    assert app.synth_yaml() == snapshot


def test_external_secrets_direct_usage(snapshot):
    ssm_secret_name = "ssm-secret"

    app = App()
    chart = Chart(app, "ExternSecretsChart")

    ExternalSecret(chart, "secret1",
                   secret_store=ExternalSecretStore.VAULT,
                   k8s_secret_name="app-vault-secret",
                   source_secret="path/to/secret",
                   secret_mappings={"key": "ENV_VAR", "key.two": ""},
                   metadata={"name": "app-vault-secret"},
                   )

    source2 = ExternalSecretSource(
        store=ExternalSecretStore.AWS_SSM,
        k8s_secret_name="app-db-secret",
        source_secret=ssm_secret_name,
        secret_mappings={"username": "DB_USER"},
        external_secret_name="app-db-secret",
    )

    ExternalSecret.from_external_secret_source(chart, "secret2", source2)

    assert app.synth_yaml() == snapshot


def test_external_secrets_k8s_secrets():
    app = App()
    chart = Chart(app, "ExternSecretsChart")

    ext_secrets = ExternalSecrets(
        chart,
        "ExternalSecrets",
        secret_sources=[
            ExternalSecretSource(
                store=ExternalSecretStore.VAULT,
                k8s_secret_name="app-vault-secret",
                source_secret="path/to/secret",
                secret_mappings={"key": "ENV_VAR", "key.two": ""},
            )
        ],
    )

    ext_secrets.add_external_secret(
        secret_source=ExternalSecretSource(
            store=ExternalSecretStore.VAULT,
            k8s_secret_name="app-api-secret",
            source_secret="another/path",
            secret_mappings={"username": "FOO"},
        ),
    )

    assert ext_secrets.k8s_secret_names == ["app-vault-secret", "app-api-secret"]
