from cdk8s import App

from ca_cdk_constructs.eks.external_secrets import (
    ExternalSecretSource,
)
from ca_cdk_constructs.eks.external_secrets.external_aws_secrets_chart import (
    ExternalAwsSecretsChart,
)
from ca_cdk_constructs.eks.imports.io.external_secrets import (
    SecretStoreV1Beta1SpecProviderAwsService as SecretStoreSpecProviderAwsService,
)


# to update the snapshot, run:
#   poetry run pytest tests/cdk8s_lib/external_secrets/test_external_secrets_chart.py --snapshot-update
def test_external_secret_chart(snapshot):
    app = App()

    source = ExternalSecretSource(
        source_secret="db-secret",
        secret_mappings={"username": "DB_USER"},
        k8s_secret_name="db-secret",
    )

    ExternalAwsSecretsChart(
        app,
        "ExternalSecretsDeployment",
        region="eu-west-1",
        service_account_name="SA",  # not in scope
        secret_service=SecretStoreSpecProviderAwsService.SECRETS_MANAGER,
        secret_sources=[source],
        namespace="test-ns",
    )
    assert app.synth_yaml() == snapshot
