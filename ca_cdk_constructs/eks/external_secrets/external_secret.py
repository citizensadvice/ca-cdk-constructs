import builtins
from cdk8s import ApiObject, ApiObjectMetadata, JsonPatch
from constructs import Construct

from ca_cdk_constructs.eks.external_secrets.secret_store import SecretStore


class ExternalSecret(ApiObject):
    """
    k8s ExternalSecret object
    """

    API_VERSION = "external-secrets.io/v1beta1"
    KIND = "ExternalSecret"

    def __init__(
        self,
        scope: Construct,
        id: builtins.str,
        *,
        k8s_secret_name: str,
        secret_store: SecretStore,
        secret_mappings: dict[str, dict[str, str]],
    ):
        super().__init__(
            scope,
            id,
            # external secret name = k8s secret name for easier debugging
            metadata=ApiObjectMetadata(name=k8s_secret_name),
            api_version=self.API_VERSION,
            kind=self.KIND,
        )

        self._k8s_secret_name = k8s_secret_name
        # in typescript you can add the spec directly https://github.com/neilkuan/cdk8s-external-dns/blob/fb2723a7081f85a52d56c24102e1c165e1ae3875/src/aws-external-dns.ts#L158
        # but you can't do this in Python
        self.spec = {
            "data": [],
            "refreshInterval": "15s",
            "secretStoreRef": {"kind": "SecretStore", "name": secret_store.value},
            "target": {
                "creationPolicy": "Owner",
                "name": k8s_secret_name,  # the k8s secret name
            },
        }

        # secret_mappings = { secret_name: { source: <env_var or "">  }  }
        for secret_name, secret_associations in secret_mappings.items():
            for secret_key, env_var_name in secret_associations.items():
                # self.__add_secret_data_ref(secr
                #
                # et_name, secret_key, env_var_name)
                self.spec["data"].append(
                    {
                        "remoteRef": {"key": secret_name, "property": secret_key},
                        "secretKey": env_var_name or secret_key,
                    }
                )

        self.add_json_patch(JsonPatch.replace("/spec", self.spec))

    @property
    def k8s_secret_name(self) -> str:
        return self._k8s_secret_name
