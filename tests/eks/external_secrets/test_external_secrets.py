from aws_cdk import App as CdkApp, Stack
from aws_cdk.aws_ec2 import Vpc
from aws_cdk.aws_eks import Cluster, KubernetesVersion
from aws_cdk.aws_secretsmanager import Secret
from cdk8s import App, Chart

from ca_cdk_constructs.eks.external_secrets import (
    ExternalSecrets,
    ExternalAWSSMSecret,
    ExternalVaultSecret,
)


# to update the snapshot, run:
#   poetry run pytest tests/eks/external_secrets/test_external_secrets.py --snapshot-update
def test_external_secrets(snapshot):
    cdkApp = CdkApp()
    s = Stack(cdkApp, "Stack")
    cluster = Cluster(s, "EksCluster", vpc=Vpc(s, "vpc"), version=KubernetesVersion.V1_23)
    ssm_secret = Secret(s, "Secret")

    app = App()
    chart = Chart(app, "ExternSecretsChart")

    ext_secrets = ExternalSecrets(
        chart,
        "ExternalSecrets",
        secret_sources=[
            ExternalVaultSecret(
                k8s_secret_name="app-vault-secret",
                source_secret="path/to/secret",
                secret_mappings={"key": "ENV_VAR", "key.two": ""},
                external_secret_name="app-vault-secret"
            )
        ],
    )

    ext_secrets.add_external_secret(
        secret_source=ExternalAWSSMSecret(
            k8s_secret_name="app-db-secret",
            source_secret=ssm_secret,
            secret_mappings={"username": "DB_USER"},
            external_secret_name="app-db-secret"
        ),
    )
    cluster.add_cdk8s_chart("ExternalSecretsDeployment", chart)
    assert app.synth_yaml() == snapshot


def test_external_secrets_k8s_secrets():
    app = App()
    chart = Chart(app, "ExternSecretsChart")

    ext_secrets = ExternalSecrets(
        chart,
        "ExternalSecrets",
        secret_sources=[
            ExternalVaultSecret(
                k8s_secret_name="app-vault-secret",
                source_secret="path/to/secret",
                secret_mappings={"key": "ENV_VAR", "key.two": ""},
            )
        ],
    )

    ext_secrets.add_external_secret(
        secret_source=ExternalVaultSecret(
            k8s_secret_name="app-api-secret",
            source_secret="another/path",
            secret_mappings={"username": "FOO"},
        ),
    )

    assert ext_secrets.k8s_secret_names == ["app-vault-secret", "app-api-secret"]
