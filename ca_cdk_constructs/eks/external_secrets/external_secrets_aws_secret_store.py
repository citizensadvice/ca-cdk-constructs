from constructs import Construct

from ca_cdk_constructs.eks.imports.io.external_secrets import (
    SecretStoreV1Beta1 as SecretStore,
    SecretStoreV1Beta1Spec as SecretStoreSpec,
    SecretStoreV1Beta1SpecProvider as SecretStoreSpecProvider,
    SecretStoreV1Beta1SpecProviderAws as SecretStoreSpecProviderAws,
    SecretStoreV1Beta1SpecProviderAwsAuth as SecretStoreSpecProviderAwsAuth,
    SecretStoreV1Beta1SpecProviderAwsAuthJwt as SecretStoreSpecProviderAwsAuthJwt,
    SecretStoreV1Beta1SpecProviderAwsAuthJwtServiceAccountRef as SecretStoreSpecProviderAwsAuthJwtServiceAccountRef,
    SecretStoreV1Beta1SpecProviderAwsService as SecretStoreSpecProviderAwsService,
)


class ExternalSecretsAwsSecretStore(Construct):
    """
    ExternalSecrets SecretStore for AWS secret services - SecretsManager and Parameter store.
    The store is the gateway to the secret service and authenticates with it using the specified ServiceAccount

    Note that the store ServiceAccount must have read access to the store secret(s).
    """

    def __init__(
        self,
        scope: Construct,
        id: str,
        service_account_name: str,
        region: str,
        secret_service: SecretStoreSpecProviderAwsService = SecretStoreSpecProviderAwsService.SECRETS_MANAGER,
    ):
        super().__init__(scope, id)
        self._service = secret_service

        self._store = SecretStore(
            self,
            "Default",
            spec=SecretStoreSpec(
                provider=SecretStoreSpecProvider(
                    aws=SecretStoreSpecProviderAws(
                        service=secret_service,
                        region=region,
                        auth=SecretStoreSpecProviderAwsAuth(
                            jwt=SecretStoreSpecProviderAwsAuthJwt(
                                service_account_ref=SecretStoreSpecProviderAwsAuthJwtServiceAccountRef(
                                    name=service_account_name
                                )
                            )
                        ),
                    )
                )
            ),
        )

    @property
    def service(self) -> SecretStoreSpecProviderAwsService:
        return self._service

    @property
    def name(self) -> str:
        return self._store.name
