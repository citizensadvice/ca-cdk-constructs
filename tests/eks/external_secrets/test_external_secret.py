from cdk8s import App, Chart

from ca_cdk_constructs.eks.external_secrets import (
    ExternalSecret,
    ExternalSecretSource,
)


# to update the snapshot, run:
#   uv run pytest tests/cdk8s_lib/external_secrets/test_external_secret.py --snapshot-update
def test_external_secret(snapshot):
    app = App()
    chart = Chart(app, "ExternSecretsChart")

    source = ExternalSecretSource(
        source_secret="db-secret",
        secret_mappings={"username": "DB_USER"},
        k8s_secret_name="database-secret",
    )

    # store created externally or with e.g
    #
    #   sa = ServiceAccount(........)
    #   ExternalSecretsAwsSecretStore(chart, "AwsSSM", service_account_name=sa.service_account_name)
    ExternalSecret(chart, "ExternalDatabaseSecret", store_name="aws-ssm", secret_source=source)

    assert app.synth_yaml() == snapshot
