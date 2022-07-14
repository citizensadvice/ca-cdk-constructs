from enum import Enum


class SecretStore(Enum):
    """Known ExternalSecret Stores, created by the cluster admins and having predefined names"""

    VAULT = "vault"
    AWS_SSM = "aws-secrets-manager"
