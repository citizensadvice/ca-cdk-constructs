from pkgutil import extend_path
__path__ = extend_path(__path__, __name__)

import abc
import builtins
import datetime
import enum
import typing

import jsii
import publication
import typing_extensions

import typeguard
from importlib.metadata import version as _metadata_package_version
TYPEGUARD_MAJOR_VERSION = int(_metadata_package_version('typeguard').split('.')[0])

def check_type(argname: str, value: object, expected_type: typing.Any) -> typing.Any:
    if TYPEGUARD_MAJOR_VERSION <= 2:
        return typeguard.check_type(argname=argname, value=value, expected_type=expected_type) # type:ignore
    else:
        if isinstance(value, jsii._reference_map.InterfaceDynamicProxy): # pyright: ignore [reportAttributeAccessIssue]
           pass
        else:
            if TYPEGUARD_MAJOR_VERSION == 3:
                typeguard.config.collection_check_strategy = typeguard.CollectionCheckStrategy.ALL_ITEMS # type:ignore
                typeguard.check_type(value=value, expected_type=expected_type) # type:ignore
            else:
                typeguard.check_type(value=value, expected_type=expected_type, collection_check_strategy=typeguard.CollectionCheckStrategy.ALL_ITEMS) # type:ignore

from ._jsii import *

import cdk8s as _cdk8s_d3d9af27
import constructs as _constructs_77d1e7e8


class AcrAccessToken(
    _cdk8s_d3d9af27.ApiObject,
    metaclass=jsii.JSIIMeta,
    jsii_type="ioexternal-secretsgenerators.AcrAccessToken",
):
    '''ACRAccessToken returns an Azure Container Registry token that can be used for pushing/pulling images.

    Note: by default it will return an ACR Refresh Token with full access
    (depending on the identity).
    This can be scoped down to the repository level using .spec.scope.
    In case scope is defined it will return an ACR Access Token.

    See docs: https://github.com/Azure/acr/blob/main/docs/AAD-OAuth.md

    :schema: ACRAccessToken
    '''

    def __init__(
        self,
        scope: _constructs_77d1e7e8.Construct,
        id: builtins.str,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["AcrAccessTokenSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Defines a "ACRAccessToken" API object.

        :param scope: the scope in which to define this object.
        :param id: a scope-local name for the object.
        :param metadata: 
        :param spec: ACRAccessTokenSpec defines how to generate the access token e.g. how to authenticate and which registry to use. see: https://github.com/Azure/acr/blob/main/docs/AAD-OAuth.md#overview.
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__b58469b24a4dd77e433bdd0894fb9acf8f428c176df20a9d7a18d63dc8d907f4)
            check_type(argname="argument scope", value=scope, expected_type=type_hints["scope"])
            check_type(argname="argument id", value=id, expected_type=type_hints["id"])
        props = AcrAccessTokenProps(metadata=metadata, spec=spec)

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="manifest")
    @builtins.classmethod
    def manifest(
        cls,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["AcrAccessTokenSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> typing.Any:
        '''Renders a Kubernetes manifest for "ACRAccessToken".

        This can be used to inline resource manifests inside other objects (e.g. as templates).

        :param metadata: 
        :param spec: ACRAccessTokenSpec defines how to generate the access token e.g. how to authenticate and which registry to use. see: https://github.com/Azure/acr/blob/main/docs/AAD-OAuth.md#overview.
        '''
        props = AcrAccessTokenProps(metadata=metadata, spec=spec)

        return typing.cast(typing.Any, jsii.sinvoke(cls, "manifest", [props]))

    @jsii.member(jsii_name="toJson")
    def to_json(self) -> typing.Any:
        '''Renders the object to Kubernetes JSON.'''
        return typing.cast(typing.Any, jsii.invoke(self, "toJson", []))

    @jsii.python.classproperty
    @jsii.member(jsii_name="GVK")
    def GVK(cls) -> _cdk8s_d3d9af27.GroupVersionKind:
        '''Returns the apiVersion and kind for "ACRAccessToken".'''
        return typing.cast(_cdk8s_d3d9af27.GroupVersionKind, jsii.sget(cls, "GVK"))


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.AcrAccessTokenProps",
    jsii_struct_bases=[],
    name_mapping={"metadata": "metadata", "spec": "spec"},
)
class AcrAccessTokenProps:
    def __init__(
        self,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["AcrAccessTokenSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''ACRAccessToken returns an Azure Container Registry token that can be used for pushing/pulling images.

        Note: by default it will return an ACR Refresh Token with full access
        (depending on the identity).
        This can be scoped down to the repository level using .spec.scope.
        In case scope is defined it will return an ACR Access Token.

        See docs: https://github.com/Azure/acr/blob/main/docs/AAD-OAuth.md

        :param metadata: 
        :param spec: ACRAccessTokenSpec defines how to generate the access token e.g. how to authenticate and which registry to use. see: https://github.com/Azure/acr/blob/main/docs/AAD-OAuth.md#overview.

        :schema: ACRAccessToken
        '''
        if isinstance(metadata, dict):
            metadata = _cdk8s_d3d9af27.ApiObjectMetadata(**metadata)
        if isinstance(spec, dict):
            spec = AcrAccessTokenSpec(**spec)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__780b658e8801c2a8877f481fd986fe4cdd0d99fbeb702002190f4aa500cbb559)
            check_type(argname="argument metadata", value=metadata, expected_type=type_hints["metadata"])
            check_type(argname="argument spec", value=spec, expected_type=type_hints["spec"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if metadata is not None:
            self._values["metadata"] = metadata
        if spec is not None:
            self._values["spec"] = spec

    @builtins.property
    def metadata(self) -> typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata]:
        '''
        :schema: ACRAccessToken#metadata
        '''
        result = self._values.get("metadata")
        return typing.cast(typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata], result)

    @builtins.property
    def spec(self) -> typing.Optional["AcrAccessTokenSpec"]:
        '''ACRAccessTokenSpec defines how to generate the access token e.g. how to authenticate and which registry to use. see: https://github.com/Azure/acr/blob/main/docs/AAD-OAuth.md#overview.

        :schema: ACRAccessToken#spec
        '''
        result = self._values.get("spec")
        return typing.cast(typing.Optional["AcrAccessTokenSpec"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AcrAccessTokenProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.AcrAccessTokenSpec",
    jsii_struct_bases=[],
    name_mapping={
        "auth": "auth",
        "registry": "registry",
        "environment_type": "environmentType",
        "scope": "scope",
        "tenant_id": "tenantId",
    },
)
class AcrAccessTokenSpec:
    def __init__(
        self,
        *,
        auth: typing.Union["AcrAccessTokenSpecAuth", typing.Dict[builtins.str, typing.Any]],
        registry: builtins.str,
        environment_type: typing.Optional["AcrAccessTokenSpecEnvironmentType"] = None,
        scope: typing.Optional[builtins.str] = None,
        tenant_id: typing.Optional[builtins.str] = None,
    ) -> None:
        '''ACRAccessTokenSpec defines how to generate the access token e.g. how to authenticate and which registry to use. see: https://github.com/Azure/acr/blob/main/docs/AAD-OAuth.md#overview.

        :param auth: 
        :param registry: the domain name of the ACR registry e.g. foobarexample.azurecr.io.
        :param environment_type: EnvironmentType specifies the Azure cloud environment endpoints to use for connecting and authenticating with Azure. By default it points to the public cloud AAD endpoint. The following endpoints are available, also see here: https://github.com/Azure/go-autorest/blob/main/autorest/azure/environments.go#L152 PublicCloud, USGovernmentCloud, ChinaCloud, GermanCloud
        :param scope: Define the scope for the access token, e.g. pull/push access for a repository. if not provided it will return a refresh token that has full scope. Note: you need to pin it down to the repository level, there is no wildcard available. examples: repository:my-repository:pull,push repository:my-repository:pull see docs for details: https://docs.docker.com/registry/spec/auth/scope/
        :param tenant_id: TenantID configures the Azure Tenant to send requests to. Required for ServicePrincipal auth type.

        :schema: AcrAccessTokenSpec
        '''
        if isinstance(auth, dict):
            auth = AcrAccessTokenSpecAuth(**auth)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__e1188e5929acfbbe541de058d5bdc0c3e6d440a2035d6ce86ae825d2b5970383)
            check_type(argname="argument auth", value=auth, expected_type=type_hints["auth"])
            check_type(argname="argument registry", value=registry, expected_type=type_hints["registry"])
            check_type(argname="argument environment_type", value=environment_type, expected_type=type_hints["environment_type"])
            check_type(argname="argument scope", value=scope, expected_type=type_hints["scope"])
            check_type(argname="argument tenant_id", value=tenant_id, expected_type=type_hints["tenant_id"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "auth": auth,
            "registry": registry,
        }
        if environment_type is not None:
            self._values["environment_type"] = environment_type
        if scope is not None:
            self._values["scope"] = scope
        if tenant_id is not None:
            self._values["tenant_id"] = tenant_id

    @builtins.property
    def auth(self) -> "AcrAccessTokenSpecAuth":
        '''
        :schema: AcrAccessTokenSpec#auth
        '''
        result = self._values.get("auth")
        assert result is not None, "Required property 'auth' is missing"
        return typing.cast("AcrAccessTokenSpecAuth", result)

    @builtins.property
    def registry(self) -> builtins.str:
        '''the domain name of the ACR registry e.g. foobarexample.azurecr.io.

        :schema: AcrAccessTokenSpec#registry
        '''
        result = self._values.get("registry")
        assert result is not None, "Required property 'registry' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def environment_type(self) -> typing.Optional["AcrAccessTokenSpecEnvironmentType"]:
        '''EnvironmentType specifies the Azure cloud environment endpoints to use for connecting and authenticating with Azure.

        By default it points to the public cloud AAD endpoint.
        The following endpoints are available, also see here: https://github.com/Azure/go-autorest/blob/main/autorest/azure/environments.go#L152
        PublicCloud, USGovernmentCloud, ChinaCloud, GermanCloud

        :schema: AcrAccessTokenSpec#environmentType
        '''
        result = self._values.get("environment_type")
        return typing.cast(typing.Optional["AcrAccessTokenSpecEnvironmentType"], result)

    @builtins.property
    def scope(self) -> typing.Optional[builtins.str]:
        '''Define the scope for the access token, e.g. pull/push access for a repository. if not provided it will return a refresh token that has full scope. Note: you need to pin it down to the repository level, there is no wildcard available.

        examples:
        repository:my-repository:pull,push
        repository:my-repository:pull

        see docs for details: https://docs.docker.com/registry/spec/auth/scope/

        :schema: AcrAccessTokenSpec#scope
        '''
        result = self._values.get("scope")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tenant_id(self) -> typing.Optional[builtins.str]:
        '''TenantID configures the Azure Tenant to send requests to.

        Required for ServicePrincipal auth type.

        :schema: AcrAccessTokenSpec#tenantId
        '''
        result = self._values.get("tenant_id")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AcrAccessTokenSpec(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.AcrAccessTokenSpecAuth",
    jsii_struct_bases=[],
    name_mapping={
        "managed_identity": "managedIdentity",
        "service_principal": "servicePrincipal",
        "workload_identity": "workloadIdentity",
    },
)
class AcrAccessTokenSpecAuth:
    def __init__(
        self,
        *,
        managed_identity: typing.Optional[typing.Union["AcrAccessTokenSpecAuthManagedIdentity", typing.Dict[builtins.str, typing.Any]]] = None,
        service_principal: typing.Optional[typing.Union["AcrAccessTokenSpecAuthServicePrincipal", typing.Dict[builtins.str, typing.Any]]] = None,
        workload_identity: typing.Optional[typing.Union["AcrAccessTokenSpecAuthWorkloadIdentity", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''
        :param managed_identity: ManagedIdentity uses Azure Managed Identity to authenticate with Azure.
        :param service_principal: ServicePrincipal uses Azure Service Principal credentials to authenticate with Azure.
        :param workload_identity: WorkloadIdentity uses Azure Workload Identity to authenticate with Azure.

        :schema: AcrAccessTokenSpecAuth
        '''
        if isinstance(managed_identity, dict):
            managed_identity = AcrAccessTokenSpecAuthManagedIdentity(**managed_identity)
        if isinstance(service_principal, dict):
            service_principal = AcrAccessTokenSpecAuthServicePrincipal(**service_principal)
        if isinstance(workload_identity, dict):
            workload_identity = AcrAccessTokenSpecAuthWorkloadIdentity(**workload_identity)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__3a17eab72333c02296dc7f6307c29604ea9a40c1ce436bd269d4191d4709bb1d)
            check_type(argname="argument managed_identity", value=managed_identity, expected_type=type_hints["managed_identity"])
            check_type(argname="argument service_principal", value=service_principal, expected_type=type_hints["service_principal"])
            check_type(argname="argument workload_identity", value=workload_identity, expected_type=type_hints["workload_identity"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if managed_identity is not None:
            self._values["managed_identity"] = managed_identity
        if service_principal is not None:
            self._values["service_principal"] = service_principal
        if workload_identity is not None:
            self._values["workload_identity"] = workload_identity

    @builtins.property
    def managed_identity(
        self,
    ) -> typing.Optional["AcrAccessTokenSpecAuthManagedIdentity"]:
        '''ManagedIdentity uses Azure Managed Identity to authenticate with Azure.

        :schema: AcrAccessTokenSpecAuth#managedIdentity
        '''
        result = self._values.get("managed_identity")
        return typing.cast(typing.Optional["AcrAccessTokenSpecAuthManagedIdentity"], result)

    @builtins.property
    def service_principal(
        self,
    ) -> typing.Optional["AcrAccessTokenSpecAuthServicePrincipal"]:
        '''ServicePrincipal uses Azure Service Principal credentials to authenticate with Azure.

        :schema: AcrAccessTokenSpecAuth#servicePrincipal
        '''
        result = self._values.get("service_principal")
        return typing.cast(typing.Optional["AcrAccessTokenSpecAuthServicePrincipal"], result)

    @builtins.property
    def workload_identity(
        self,
    ) -> typing.Optional["AcrAccessTokenSpecAuthWorkloadIdentity"]:
        '''WorkloadIdentity uses Azure Workload Identity to authenticate with Azure.

        :schema: AcrAccessTokenSpecAuth#workloadIdentity
        '''
        result = self._values.get("workload_identity")
        return typing.cast(typing.Optional["AcrAccessTokenSpecAuthWorkloadIdentity"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AcrAccessTokenSpecAuth(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.AcrAccessTokenSpecAuthManagedIdentity",
    jsii_struct_bases=[],
    name_mapping={"identity_id": "identityId"},
)
class AcrAccessTokenSpecAuthManagedIdentity:
    def __init__(self, *, identity_id: typing.Optional[builtins.str] = None) -> None:
        '''ManagedIdentity uses Azure Managed Identity to authenticate with Azure.

        :param identity_id: If multiple Managed Identity is assigned to the pod, you can select the one to be used.

        :schema: AcrAccessTokenSpecAuthManagedIdentity
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__d3496f91014f90715c72e1d9c0fa20f3cfc6a3f8c9e3ac3235a69b7ccde7fbb8)
            check_type(argname="argument identity_id", value=identity_id, expected_type=type_hints["identity_id"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if identity_id is not None:
            self._values["identity_id"] = identity_id

    @builtins.property
    def identity_id(self) -> typing.Optional[builtins.str]:
        '''If multiple Managed Identity is assigned to the pod, you can select the one to be used.

        :schema: AcrAccessTokenSpecAuthManagedIdentity#identityId
        '''
        result = self._values.get("identity_id")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AcrAccessTokenSpecAuthManagedIdentity(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.AcrAccessTokenSpecAuthServicePrincipal",
    jsii_struct_bases=[],
    name_mapping={"secret_ref": "secretRef"},
)
class AcrAccessTokenSpecAuthServicePrincipal:
    def __init__(
        self,
        *,
        secret_ref: typing.Union["AcrAccessTokenSpecAuthServicePrincipalSecretRef", typing.Dict[builtins.str, typing.Any]],
    ) -> None:
        '''ServicePrincipal uses Azure Service Principal credentials to authenticate with Azure.

        :param secret_ref: Configuration used to authenticate with Azure using static credentials stored in a Kind=Secret.

        :schema: AcrAccessTokenSpecAuthServicePrincipal
        '''
        if isinstance(secret_ref, dict):
            secret_ref = AcrAccessTokenSpecAuthServicePrincipalSecretRef(**secret_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__782de22c9a1e53cf71ef721256c452f555b4a87fa61fa3657699af35b2d4fc9c)
            check_type(argname="argument secret_ref", value=secret_ref, expected_type=type_hints["secret_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "secret_ref": secret_ref,
        }

    @builtins.property
    def secret_ref(self) -> "AcrAccessTokenSpecAuthServicePrincipalSecretRef":
        '''Configuration used to authenticate with Azure using static credentials stored in a Kind=Secret.

        :schema: AcrAccessTokenSpecAuthServicePrincipal#secretRef
        '''
        result = self._values.get("secret_ref")
        assert result is not None, "Required property 'secret_ref' is missing"
        return typing.cast("AcrAccessTokenSpecAuthServicePrincipalSecretRef", result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AcrAccessTokenSpecAuthServicePrincipal(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.AcrAccessTokenSpecAuthServicePrincipalSecretRef",
    jsii_struct_bases=[],
    name_mapping={"client_id": "clientId", "client_secret": "clientSecret"},
)
class AcrAccessTokenSpecAuthServicePrincipalSecretRef:
    def __init__(
        self,
        *,
        client_id: typing.Optional[typing.Union["AcrAccessTokenSpecAuthServicePrincipalSecretRefClientId", typing.Dict[builtins.str, typing.Any]]] = None,
        client_secret: typing.Optional[typing.Union["AcrAccessTokenSpecAuthServicePrincipalSecretRefClientSecret", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Configuration used to authenticate with Azure using static credentials stored in a Kind=Secret.

        :param client_id: The Azure clientId of the service principle used for authentication.
        :param client_secret: The Azure ClientSecret of the service principle used for authentication.

        :schema: AcrAccessTokenSpecAuthServicePrincipalSecretRef
        '''
        if isinstance(client_id, dict):
            client_id = AcrAccessTokenSpecAuthServicePrincipalSecretRefClientId(**client_id)
        if isinstance(client_secret, dict):
            client_secret = AcrAccessTokenSpecAuthServicePrincipalSecretRefClientSecret(**client_secret)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__a984720a180e603b46cc0b78e2bed7f4b7631e98821965df9496bdb760e60e39)
            check_type(argname="argument client_id", value=client_id, expected_type=type_hints["client_id"])
            check_type(argname="argument client_secret", value=client_secret, expected_type=type_hints["client_secret"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if client_id is not None:
            self._values["client_id"] = client_id
        if client_secret is not None:
            self._values["client_secret"] = client_secret

    @builtins.property
    def client_id(
        self,
    ) -> typing.Optional["AcrAccessTokenSpecAuthServicePrincipalSecretRefClientId"]:
        '''The Azure clientId of the service principle used for authentication.

        :schema: AcrAccessTokenSpecAuthServicePrincipalSecretRef#clientId
        '''
        result = self._values.get("client_id")
        return typing.cast(typing.Optional["AcrAccessTokenSpecAuthServicePrincipalSecretRefClientId"], result)

    @builtins.property
    def client_secret(
        self,
    ) -> typing.Optional["AcrAccessTokenSpecAuthServicePrincipalSecretRefClientSecret"]:
        '''The Azure ClientSecret of the service principle used for authentication.

        :schema: AcrAccessTokenSpecAuthServicePrincipalSecretRef#clientSecret
        '''
        result = self._values.get("client_secret")
        return typing.cast(typing.Optional["AcrAccessTokenSpecAuthServicePrincipalSecretRefClientSecret"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AcrAccessTokenSpecAuthServicePrincipalSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.AcrAccessTokenSpecAuthServicePrincipalSecretRefClientId",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class AcrAccessTokenSpecAuthServicePrincipalSecretRefClientId:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''The Azure clientId of the service principle used for authentication.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: AcrAccessTokenSpecAuthServicePrincipalSecretRefClientId
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__0b79bca6f37947d2a7ae2c512a6aab77a20054adb9de54b29e1fb65eace7f4c5)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: AcrAccessTokenSpecAuthServicePrincipalSecretRefClientId#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: AcrAccessTokenSpecAuthServicePrincipalSecretRefClientId#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: AcrAccessTokenSpecAuthServicePrincipalSecretRefClientId#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AcrAccessTokenSpecAuthServicePrincipalSecretRefClientId(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.AcrAccessTokenSpecAuthServicePrincipalSecretRefClientSecret",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class AcrAccessTokenSpecAuthServicePrincipalSecretRefClientSecret:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''The Azure ClientSecret of the service principle used for authentication.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: AcrAccessTokenSpecAuthServicePrincipalSecretRefClientSecret
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__59ab052d3221edb153fc5273b3020c1f9474bc5688618e2d67fe9c5f9141ec6e)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: AcrAccessTokenSpecAuthServicePrincipalSecretRefClientSecret#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: AcrAccessTokenSpecAuthServicePrincipalSecretRefClientSecret#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: AcrAccessTokenSpecAuthServicePrincipalSecretRefClientSecret#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AcrAccessTokenSpecAuthServicePrincipalSecretRefClientSecret(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.AcrAccessTokenSpecAuthWorkloadIdentity",
    jsii_struct_bases=[],
    name_mapping={"service_account_ref": "serviceAccountRef"},
)
class AcrAccessTokenSpecAuthWorkloadIdentity:
    def __init__(
        self,
        *,
        service_account_ref: typing.Optional[typing.Union["AcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''WorkloadIdentity uses Azure Workload Identity to authenticate with Azure.

        :param service_account_ref: ServiceAccountRef specified the service account that should be used when authenticating with WorkloadIdentity.

        :schema: AcrAccessTokenSpecAuthWorkloadIdentity
        '''
        if isinstance(service_account_ref, dict):
            service_account_ref = AcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef(**service_account_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__75713e68e1305d61adc704c00bc5068c4d3765385d5bb9b2bd763d760a61d39c)
            check_type(argname="argument service_account_ref", value=service_account_ref, expected_type=type_hints["service_account_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if service_account_ref is not None:
            self._values["service_account_ref"] = service_account_ref

    @builtins.property
    def service_account_ref(
        self,
    ) -> typing.Optional["AcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef"]:
        '''ServiceAccountRef specified the service account that should be used when authenticating with WorkloadIdentity.

        :schema: AcrAccessTokenSpecAuthWorkloadIdentity#serviceAccountRef
        '''
        result = self._values.get("service_account_ref")
        return typing.cast(typing.Optional["AcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AcrAccessTokenSpecAuthWorkloadIdentity(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.AcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "audiences": "audiences", "namespace": "namespace"},
)
class AcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef:
    def __init__(
        self,
        *,
        name: builtins.str,
        audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''ServiceAccountRef specified the service account that should be used when authenticating with WorkloadIdentity.

        :param name: The name of the ServiceAccount resource being referred to.
        :param audiences: Audience specifies the ``aud`` claim for the service account token If the service account uses a well-known annotation for e.g. IRSA or GCP Workload Identity then this audiences will be appended to the list.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: AcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__ddf0afa1f998410811287e82c3097165fb87092b51d21d6220a7bd0ceedb8ebe)
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument audiences", value=audiences, expected_type=type_hints["audiences"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "name": name,
        }
        if audiences is not None:
            self._values["audiences"] = audiences
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the ServiceAccount resource being referred to.

        :schema: AcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def audiences(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Audience specifies the ``aud`` claim for the service account token If the service account uses a well-known annotation for e.g. IRSA or GCP Workload Identity then this audiences will be appended to the list.

        :schema: AcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef#audiences
        '''
        result = self._values.get("audiences")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: AcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="ioexternal-secretsgenerators.AcrAccessTokenSpecEnvironmentType")
class AcrAccessTokenSpecEnvironmentType(enum.Enum):
    '''EnvironmentType specifies the Azure cloud environment endpoints to use for connecting and authenticating with Azure.

    By default it points to the public cloud AAD endpoint.
    The following endpoints are available, also see here: https://github.com/Azure/go-autorest/blob/main/autorest/azure/environments.go#L152
    PublicCloud, USGovernmentCloud, ChinaCloud, GermanCloud

    :schema: AcrAccessTokenSpecEnvironmentType
    '''

    PUBLIC_CLOUD = "PUBLIC_CLOUD"
    '''PublicCloud.'''
    US_GOVERNMENT_CLOUD = "US_GOVERNMENT_CLOUD"
    '''USGovernmentCloud.'''
    CHINA_CLOUD = "CHINA_CLOUD"
    '''ChinaCloud.'''
    GERMAN_CLOUD = "GERMAN_CLOUD"
    '''GermanCloud.'''


class ClusterGenerator(
    _cdk8s_d3d9af27.ApiObject,
    metaclass=jsii.JSIIMeta,
    jsii_type="ioexternal-secretsgenerators.ClusterGenerator",
):
    '''ClusterGenerator represents a cluster-wide generator which can be referenced as part of ``generatorRef`` fields.

    :schema: ClusterGenerator
    '''

    def __init__(
        self,
        scope: _constructs_77d1e7e8.Construct,
        id: builtins.str,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["ClusterGeneratorSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Defines a "ClusterGenerator" API object.

        :param scope: the scope in which to define this object.
        :param id: a scope-local name for the object.
        :param metadata: 
        :param spec: 
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__9a344af75ed1cbccde2cb0736d9fd19650ccfcf8db8041ebef1f47376fdd8893)
            check_type(argname="argument scope", value=scope, expected_type=type_hints["scope"])
            check_type(argname="argument id", value=id, expected_type=type_hints["id"])
        props = ClusterGeneratorProps(metadata=metadata, spec=spec)

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="manifest")
    @builtins.classmethod
    def manifest(
        cls,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["ClusterGeneratorSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> typing.Any:
        '''Renders a Kubernetes manifest for "ClusterGenerator".

        This can be used to inline resource manifests inside other objects (e.g. as templates).

        :param metadata: 
        :param spec: 
        '''
        props = ClusterGeneratorProps(metadata=metadata, spec=spec)

        return typing.cast(typing.Any, jsii.sinvoke(cls, "manifest", [props]))

    @jsii.member(jsii_name="toJson")
    def to_json(self) -> typing.Any:
        '''Renders the object to Kubernetes JSON.'''
        return typing.cast(typing.Any, jsii.invoke(self, "toJson", []))

    @jsii.python.classproperty
    @jsii.member(jsii_name="GVK")
    def GVK(cls) -> _cdk8s_d3d9af27.GroupVersionKind:
        '''Returns the apiVersion and kind for "ClusterGenerator".'''
        return typing.cast(_cdk8s_d3d9af27.GroupVersionKind, jsii.sget(cls, "GVK"))


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorProps",
    jsii_struct_bases=[],
    name_mapping={"metadata": "metadata", "spec": "spec"},
)
class ClusterGeneratorProps:
    def __init__(
        self,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["ClusterGeneratorSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''ClusterGenerator represents a cluster-wide generator which can be referenced as part of ``generatorRef`` fields.

        :param metadata: 
        :param spec: 

        :schema: ClusterGenerator
        '''
        if isinstance(metadata, dict):
            metadata = _cdk8s_d3d9af27.ApiObjectMetadata(**metadata)
        if isinstance(spec, dict):
            spec = ClusterGeneratorSpec(**spec)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__207c380f932a7c6b5b9d3e0bbd7a5201b91f49ecb28f7e16c23097608f878a95)
            check_type(argname="argument metadata", value=metadata, expected_type=type_hints["metadata"])
            check_type(argname="argument spec", value=spec, expected_type=type_hints["spec"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if metadata is not None:
            self._values["metadata"] = metadata
        if spec is not None:
            self._values["spec"] = spec

    @builtins.property
    def metadata(self) -> typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata]:
        '''
        :schema: ClusterGenerator#metadata
        '''
        result = self._values.get("metadata")
        return typing.cast(typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata], result)

    @builtins.property
    def spec(self) -> typing.Optional["ClusterGeneratorSpec"]:
        '''
        :schema: ClusterGenerator#spec
        '''
        result = self._values.get("spec")
        return typing.cast(typing.Optional["ClusterGeneratorSpec"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpec",
    jsii_struct_bases=[],
    name_mapping={"generator": "generator", "kind": "kind"},
)
class ClusterGeneratorSpec:
    def __init__(
        self,
        *,
        generator: typing.Union["ClusterGeneratorSpecGenerator", typing.Dict[builtins.str, typing.Any]],
        kind: "ClusterGeneratorSpecKind",
    ) -> None:
        '''
        :param generator: Generator the spec for this generator, must match the kind.
        :param kind: Kind the kind of this generator.

        :schema: ClusterGeneratorSpec
        '''
        if isinstance(generator, dict):
            generator = ClusterGeneratorSpecGenerator(**generator)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__64d7f76e7038ac114e970dfd5c153b3eb78c0bd1f509f47d2e2323fe85dee042)
            check_type(argname="argument generator", value=generator, expected_type=type_hints["generator"])
            check_type(argname="argument kind", value=kind, expected_type=type_hints["kind"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "generator": generator,
            "kind": kind,
        }

    @builtins.property
    def generator(self) -> "ClusterGeneratorSpecGenerator":
        '''Generator the spec for this generator, must match the kind.

        :schema: ClusterGeneratorSpec#generator
        '''
        result = self._values.get("generator")
        assert result is not None, "Required property 'generator' is missing"
        return typing.cast("ClusterGeneratorSpecGenerator", result)

    @builtins.property
    def kind(self) -> "ClusterGeneratorSpecKind":
        '''Kind the kind of this generator.

        :schema: ClusterGeneratorSpec#kind
        '''
        result = self._values.get("kind")
        assert result is not None, "Required property 'kind' is missing"
        return typing.cast("ClusterGeneratorSpecKind", result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpec(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGenerator",
    jsii_struct_bases=[],
    name_mapping={
        "acr_access_token_spec": "acrAccessTokenSpec",
        "ecr_authorization_token_spec": "ecrAuthorizationTokenSpec",
        "fake_spec": "fakeSpec",
        "gcr_access_token_spec": "gcrAccessTokenSpec",
        "github_access_token_spec": "githubAccessTokenSpec",
        "grafana_spec": "grafanaSpec",
        "password_spec": "passwordSpec",
        "quay_access_token_spec": "quayAccessTokenSpec",
        "sts_session_token_spec": "stsSessionTokenSpec",
        "uuid_spec": "uuidSpec",
        "vault_dynamic_secret_spec": "vaultDynamicSecretSpec",
        "webhook_spec": "webhookSpec",
    },
)
class ClusterGeneratorSpecGenerator:
    def __init__(
        self,
        *,
        acr_access_token_spec: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorAcrAccessTokenSpec", typing.Dict[builtins.str, typing.Any]]] = None,
        ecr_authorization_token_spec: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpec", typing.Dict[builtins.str, typing.Any]]] = None,
        fake_spec: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorFakeSpec", typing.Dict[builtins.str, typing.Any]]] = None,
        gcr_access_token_spec: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorGcrAccessTokenSpec", typing.Dict[builtins.str, typing.Any]]] = None,
        github_access_token_spec: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorGithubAccessTokenSpec", typing.Dict[builtins.str, typing.Any]]] = None,
        grafana_spec: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorGrafanaSpec", typing.Dict[builtins.str, typing.Any]]] = None,
        password_spec: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorPasswordSpec", typing.Dict[builtins.str, typing.Any]]] = None,
        quay_access_token_spec: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorQuayAccessTokenSpec", typing.Dict[builtins.str, typing.Any]]] = None,
        sts_session_token_spec: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorStsSessionTokenSpec", typing.Dict[builtins.str, typing.Any]]] = None,
        uuid_spec: typing.Any = None,
        vault_dynamic_secret_spec: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpec", typing.Dict[builtins.str, typing.Any]]] = None,
        webhook_spec: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorWebhookSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Generator the spec for this generator, must match the kind.

        :param acr_access_token_spec: ACRAccessTokenSpec defines how to generate the access token e.g. how to authenticate and which registry to use. see: https://github.com/Azure/acr/blob/main/docs/AAD-OAuth.md#overview.
        :param ecr_authorization_token_spec: 
        :param fake_spec: FakeSpec contains the static data.
        :param gcr_access_token_spec: 
        :param github_access_token_spec: 
        :param grafana_spec: GrafanaSpec controls the behavior of the grafana generator.
        :param password_spec: PasswordSpec controls the behavior of the password generator.
        :param quay_access_token_spec: 
        :param sts_session_token_spec: 
        :param uuid_spec: UUIDSpec controls the behavior of the uuid generator.
        :param vault_dynamic_secret_spec: 
        :param webhook_spec: WebhookSpec controls the behavior of the external generator. Any body parameters should be passed to the server through the parameters field.

        :schema: ClusterGeneratorSpecGenerator
        '''
        if isinstance(acr_access_token_spec, dict):
            acr_access_token_spec = ClusterGeneratorSpecGeneratorAcrAccessTokenSpec(**acr_access_token_spec)
        if isinstance(ecr_authorization_token_spec, dict):
            ecr_authorization_token_spec = ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpec(**ecr_authorization_token_spec)
        if isinstance(fake_spec, dict):
            fake_spec = ClusterGeneratorSpecGeneratorFakeSpec(**fake_spec)
        if isinstance(gcr_access_token_spec, dict):
            gcr_access_token_spec = ClusterGeneratorSpecGeneratorGcrAccessTokenSpec(**gcr_access_token_spec)
        if isinstance(github_access_token_spec, dict):
            github_access_token_spec = ClusterGeneratorSpecGeneratorGithubAccessTokenSpec(**github_access_token_spec)
        if isinstance(grafana_spec, dict):
            grafana_spec = ClusterGeneratorSpecGeneratorGrafanaSpec(**grafana_spec)
        if isinstance(password_spec, dict):
            password_spec = ClusterGeneratorSpecGeneratorPasswordSpec(**password_spec)
        if isinstance(quay_access_token_spec, dict):
            quay_access_token_spec = ClusterGeneratorSpecGeneratorQuayAccessTokenSpec(**quay_access_token_spec)
        if isinstance(sts_session_token_spec, dict):
            sts_session_token_spec = ClusterGeneratorSpecGeneratorStsSessionTokenSpec(**sts_session_token_spec)
        if isinstance(vault_dynamic_secret_spec, dict):
            vault_dynamic_secret_spec = ClusterGeneratorSpecGeneratorVaultDynamicSecretSpec(**vault_dynamic_secret_spec)
        if isinstance(webhook_spec, dict):
            webhook_spec = ClusterGeneratorSpecGeneratorWebhookSpec(**webhook_spec)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__75697d100ce0404120222110ca16af3984f4ab31958e84b7756b37400e311f59)
            check_type(argname="argument acr_access_token_spec", value=acr_access_token_spec, expected_type=type_hints["acr_access_token_spec"])
            check_type(argname="argument ecr_authorization_token_spec", value=ecr_authorization_token_spec, expected_type=type_hints["ecr_authorization_token_spec"])
            check_type(argname="argument fake_spec", value=fake_spec, expected_type=type_hints["fake_spec"])
            check_type(argname="argument gcr_access_token_spec", value=gcr_access_token_spec, expected_type=type_hints["gcr_access_token_spec"])
            check_type(argname="argument github_access_token_spec", value=github_access_token_spec, expected_type=type_hints["github_access_token_spec"])
            check_type(argname="argument grafana_spec", value=grafana_spec, expected_type=type_hints["grafana_spec"])
            check_type(argname="argument password_spec", value=password_spec, expected_type=type_hints["password_spec"])
            check_type(argname="argument quay_access_token_spec", value=quay_access_token_spec, expected_type=type_hints["quay_access_token_spec"])
            check_type(argname="argument sts_session_token_spec", value=sts_session_token_spec, expected_type=type_hints["sts_session_token_spec"])
            check_type(argname="argument uuid_spec", value=uuid_spec, expected_type=type_hints["uuid_spec"])
            check_type(argname="argument vault_dynamic_secret_spec", value=vault_dynamic_secret_spec, expected_type=type_hints["vault_dynamic_secret_spec"])
            check_type(argname="argument webhook_spec", value=webhook_spec, expected_type=type_hints["webhook_spec"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if acr_access_token_spec is not None:
            self._values["acr_access_token_spec"] = acr_access_token_spec
        if ecr_authorization_token_spec is not None:
            self._values["ecr_authorization_token_spec"] = ecr_authorization_token_spec
        if fake_spec is not None:
            self._values["fake_spec"] = fake_spec
        if gcr_access_token_spec is not None:
            self._values["gcr_access_token_spec"] = gcr_access_token_spec
        if github_access_token_spec is not None:
            self._values["github_access_token_spec"] = github_access_token_spec
        if grafana_spec is not None:
            self._values["grafana_spec"] = grafana_spec
        if password_spec is not None:
            self._values["password_spec"] = password_spec
        if quay_access_token_spec is not None:
            self._values["quay_access_token_spec"] = quay_access_token_spec
        if sts_session_token_spec is not None:
            self._values["sts_session_token_spec"] = sts_session_token_spec
        if uuid_spec is not None:
            self._values["uuid_spec"] = uuid_spec
        if vault_dynamic_secret_spec is not None:
            self._values["vault_dynamic_secret_spec"] = vault_dynamic_secret_spec
        if webhook_spec is not None:
            self._values["webhook_spec"] = webhook_spec

    @builtins.property
    def acr_access_token_spec(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorAcrAccessTokenSpec"]:
        '''ACRAccessTokenSpec defines how to generate the access token e.g. how to authenticate and which registry to use. see: https://github.com/Azure/acr/blob/main/docs/AAD-OAuth.md#overview.

        :schema: ClusterGeneratorSpecGenerator#acrAccessTokenSpec
        '''
        result = self._values.get("acr_access_token_spec")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorAcrAccessTokenSpec"], result)

    @builtins.property
    def ecr_authorization_token_spec(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpec"]:
        '''
        :schema: ClusterGeneratorSpecGenerator#ecrAuthorizationTokenSpec
        '''
        result = self._values.get("ecr_authorization_token_spec")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpec"], result)

    @builtins.property
    def fake_spec(self) -> typing.Optional["ClusterGeneratorSpecGeneratorFakeSpec"]:
        '''FakeSpec contains the static data.

        :schema: ClusterGeneratorSpecGenerator#fakeSpec
        '''
        result = self._values.get("fake_spec")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorFakeSpec"], result)

    @builtins.property
    def gcr_access_token_spec(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorGcrAccessTokenSpec"]:
        '''
        :schema: ClusterGeneratorSpecGenerator#gcrAccessTokenSpec
        '''
        result = self._values.get("gcr_access_token_spec")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorGcrAccessTokenSpec"], result)

    @builtins.property
    def github_access_token_spec(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorGithubAccessTokenSpec"]:
        '''
        :schema: ClusterGeneratorSpecGenerator#githubAccessTokenSpec
        '''
        result = self._values.get("github_access_token_spec")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorGithubAccessTokenSpec"], result)

    @builtins.property
    def grafana_spec(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorGrafanaSpec"]:
        '''GrafanaSpec controls the behavior of the grafana generator.

        :schema: ClusterGeneratorSpecGenerator#grafanaSpec
        '''
        result = self._values.get("grafana_spec")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorGrafanaSpec"], result)

    @builtins.property
    def password_spec(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorPasswordSpec"]:
        '''PasswordSpec controls the behavior of the password generator.

        :schema: ClusterGeneratorSpecGenerator#passwordSpec
        '''
        result = self._values.get("password_spec")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorPasswordSpec"], result)

    @builtins.property
    def quay_access_token_spec(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorQuayAccessTokenSpec"]:
        '''
        :schema: ClusterGeneratorSpecGenerator#quayAccessTokenSpec
        '''
        result = self._values.get("quay_access_token_spec")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorQuayAccessTokenSpec"], result)

    @builtins.property
    def sts_session_token_spec(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorStsSessionTokenSpec"]:
        '''
        :schema: ClusterGeneratorSpecGenerator#stsSessionTokenSpec
        '''
        result = self._values.get("sts_session_token_spec")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorStsSessionTokenSpec"], result)

    @builtins.property
    def uuid_spec(self) -> typing.Any:
        '''UUIDSpec controls the behavior of the uuid generator.

        :schema: ClusterGeneratorSpecGenerator#uuidSpec
        '''
        result = self._values.get("uuid_spec")
        return typing.cast(typing.Any, result)

    @builtins.property
    def vault_dynamic_secret_spec(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpec"]:
        '''
        :schema: ClusterGeneratorSpecGenerator#vaultDynamicSecretSpec
        '''
        result = self._values.get("vault_dynamic_secret_spec")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpec"], result)

    @builtins.property
    def webhook_spec(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorWebhookSpec"]:
        '''WebhookSpec controls the behavior of the external generator.

        Any body parameters should be passed to the server through the parameters field.

        :schema: ClusterGeneratorSpecGenerator#webhookSpec
        '''
        result = self._values.get("webhook_spec")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorWebhookSpec"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGenerator(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorAcrAccessTokenSpec",
    jsii_struct_bases=[],
    name_mapping={
        "auth": "auth",
        "registry": "registry",
        "environment_type": "environmentType",
        "scope": "scope",
        "tenant_id": "tenantId",
    },
)
class ClusterGeneratorSpecGeneratorAcrAccessTokenSpec:
    def __init__(
        self,
        *,
        auth: typing.Union["ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuth", typing.Dict[builtins.str, typing.Any]],
        registry: builtins.str,
        environment_type: typing.Optional["ClusterGeneratorSpecGeneratorAcrAccessTokenSpecEnvironmentType"] = None,
        scope: typing.Optional[builtins.str] = None,
        tenant_id: typing.Optional[builtins.str] = None,
    ) -> None:
        '''ACRAccessTokenSpec defines how to generate the access token e.g. how to authenticate and which registry to use. see: https://github.com/Azure/acr/blob/main/docs/AAD-OAuth.md#overview.

        :param auth: 
        :param registry: the domain name of the ACR registry e.g. foobarexample.azurecr.io.
        :param environment_type: EnvironmentType specifies the Azure cloud environment endpoints to use for connecting and authenticating with Azure. By default it points to the public cloud AAD endpoint. The following endpoints are available, also see here: https://github.com/Azure/go-autorest/blob/main/autorest/azure/environments.go#L152 PublicCloud, USGovernmentCloud, ChinaCloud, GermanCloud
        :param scope: Define the scope for the access token, e.g. pull/push access for a repository. if not provided it will return a refresh token that has full scope. Note: you need to pin it down to the repository level, there is no wildcard available. examples: repository:my-repository:pull,push repository:my-repository:pull see docs for details: https://docs.docker.com/registry/spec/auth/scope/
        :param tenant_id: TenantID configures the Azure Tenant to send requests to. Required for ServicePrincipal auth type.

        :schema: ClusterGeneratorSpecGeneratorAcrAccessTokenSpec
        '''
        if isinstance(auth, dict):
            auth = ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuth(**auth)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__32c3cfb77fca6e94afe340dbd2ce7fd362533690b4a5bb8be7f89eb9ffad6954)
            check_type(argname="argument auth", value=auth, expected_type=type_hints["auth"])
            check_type(argname="argument registry", value=registry, expected_type=type_hints["registry"])
            check_type(argname="argument environment_type", value=environment_type, expected_type=type_hints["environment_type"])
            check_type(argname="argument scope", value=scope, expected_type=type_hints["scope"])
            check_type(argname="argument tenant_id", value=tenant_id, expected_type=type_hints["tenant_id"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "auth": auth,
            "registry": registry,
        }
        if environment_type is not None:
            self._values["environment_type"] = environment_type
        if scope is not None:
            self._values["scope"] = scope
        if tenant_id is not None:
            self._values["tenant_id"] = tenant_id

    @builtins.property
    def auth(self) -> "ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuth":
        '''
        :schema: ClusterGeneratorSpecGeneratorAcrAccessTokenSpec#auth
        '''
        result = self._values.get("auth")
        assert result is not None, "Required property 'auth' is missing"
        return typing.cast("ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuth", result)

    @builtins.property
    def registry(self) -> builtins.str:
        '''the domain name of the ACR registry e.g. foobarexample.azurecr.io.

        :schema: ClusterGeneratorSpecGeneratorAcrAccessTokenSpec#registry
        '''
        result = self._values.get("registry")
        assert result is not None, "Required property 'registry' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def environment_type(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorAcrAccessTokenSpecEnvironmentType"]:
        '''EnvironmentType specifies the Azure cloud environment endpoints to use for connecting and authenticating with Azure.

        By default it points to the public cloud AAD endpoint.
        The following endpoints are available, also see here: https://github.com/Azure/go-autorest/blob/main/autorest/azure/environments.go#L152
        PublicCloud, USGovernmentCloud, ChinaCloud, GermanCloud

        :schema: ClusterGeneratorSpecGeneratorAcrAccessTokenSpec#environmentType
        '''
        result = self._values.get("environment_type")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorAcrAccessTokenSpecEnvironmentType"], result)

    @builtins.property
    def scope(self) -> typing.Optional[builtins.str]:
        '''Define the scope for the access token, e.g. pull/push access for a repository. if not provided it will return a refresh token that has full scope. Note: you need to pin it down to the repository level, there is no wildcard available.

        examples:
        repository:my-repository:pull,push
        repository:my-repository:pull

        see docs for details: https://docs.docker.com/registry/spec/auth/scope/

        :schema: ClusterGeneratorSpecGeneratorAcrAccessTokenSpec#scope
        '''
        result = self._values.get("scope")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tenant_id(self) -> typing.Optional[builtins.str]:
        '''TenantID configures the Azure Tenant to send requests to.

        Required for ServicePrincipal auth type.

        :schema: ClusterGeneratorSpecGeneratorAcrAccessTokenSpec#tenantId
        '''
        result = self._values.get("tenant_id")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorAcrAccessTokenSpec(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuth",
    jsii_struct_bases=[],
    name_mapping={
        "managed_identity": "managedIdentity",
        "service_principal": "servicePrincipal",
        "workload_identity": "workloadIdentity",
    },
)
class ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuth:
    def __init__(
        self,
        *,
        managed_identity: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthManagedIdentity", typing.Dict[builtins.str, typing.Any]]] = None,
        service_principal: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipal", typing.Dict[builtins.str, typing.Any]]] = None,
        workload_identity: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthWorkloadIdentity", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''
        :param managed_identity: ManagedIdentity uses Azure Managed Identity to authenticate with Azure.
        :param service_principal: ServicePrincipal uses Azure Service Principal credentials to authenticate with Azure.
        :param workload_identity: WorkloadIdentity uses Azure Workload Identity to authenticate with Azure.

        :schema: ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuth
        '''
        if isinstance(managed_identity, dict):
            managed_identity = ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthManagedIdentity(**managed_identity)
        if isinstance(service_principal, dict):
            service_principal = ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipal(**service_principal)
        if isinstance(workload_identity, dict):
            workload_identity = ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthWorkloadIdentity(**workload_identity)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__072c1a68bb9ff416e5ccefff762ee5c327b6c6de3469b1275eb05d997ced3f3c)
            check_type(argname="argument managed_identity", value=managed_identity, expected_type=type_hints["managed_identity"])
            check_type(argname="argument service_principal", value=service_principal, expected_type=type_hints["service_principal"])
            check_type(argname="argument workload_identity", value=workload_identity, expected_type=type_hints["workload_identity"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if managed_identity is not None:
            self._values["managed_identity"] = managed_identity
        if service_principal is not None:
            self._values["service_principal"] = service_principal
        if workload_identity is not None:
            self._values["workload_identity"] = workload_identity

    @builtins.property
    def managed_identity(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthManagedIdentity"]:
        '''ManagedIdentity uses Azure Managed Identity to authenticate with Azure.

        :schema: ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuth#managedIdentity
        '''
        result = self._values.get("managed_identity")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthManagedIdentity"], result)

    @builtins.property
    def service_principal(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipal"]:
        '''ServicePrincipal uses Azure Service Principal credentials to authenticate with Azure.

        :schema: ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuth#servicePrincipal
        '''
        result = self._values.get("service_principal")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipal"], result)

    @builtins.property
    def workload_identity(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthWorkloadIdentity"]:
        '''WorkloadIdentity uses Azure Workload Identity to authenticate with Azure.

        :schema: ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuth#workloadIdentity
        '''
        result = self._values.get("workload_identity")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthWorkloadIdentity"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuth(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthManagedIdentity",
    jsii_struct_bases=[],
    name_mapping={"identity_id": "identityId"},
)
class ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthManagedIdentity:
    def __init__(self, *, identity_id: typing.Optional[builtins.str] = None) -> None:
        '''ManagedIdentity uses Azure Managed Identity to authenticate with Azure.

        :param identity_id: If multiple Managed Identity is assigned to the pod, you can select the one to be used.

        :schema: ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthManagedIdentity
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__dd8060e4227f6226de189ed62d96d1dc8717d4afe6b8a4bc76056e4f094009e4)
            check_type(argname="argument identity_id", value=identity_id, expected_type=type_hints["identity_id"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if identity_id is not None:
            self._values["identity_id"] = identity_id

    @builtins.property
    def identity_id(self) -> typing.Optional[builtins.str]:
        '''If multiple Managed Identity is assigned to the pod, you can select the one to be used.

        :schema: ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthManagedIdentity#identityId
        '''
        result = self._values.get("identity_id")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthManagedIdentity(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipal",
    jsii_struct_bases=[],
    name_mapping={"secret_ref": "secretRef"},
)
class ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipal:
    def __init__(
        self,
        *,
        secret_ref: typing.Union["ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRef", typing.Dict[builtins.str, typing.Any]],
    ) -> None:
        '''ServicePrincipal uses Azure Service Principal credentials to authenticate with Azure.

        :param secret_ref: Configuration used to authenticate with Azure using static credentials stored in a Kind=Secret.

        :schema: ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipal
        '''
        if isinstance(secret_ref, dict):
            secret_ref = ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRef(**secret_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__225e6080231fd8bc5a63fd915cf9ab3f134297b9a067f5474ad283159e35a281)
            check_type(argname="argument secret_ref", value=secret_ref, expected_type=type_hints["secret_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "secret_ref": secret_ref,
        }

    @builtins.property
    def secret_ref(
        self,
    ) -> "ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRef":
        '''Configuration used to authenticate with Azure using static credentials stored in a Kind=Secret.

        :schema: ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipal#secretRef
        '''
        result = self._values.get("secret_ref")
        assert result is not None, "Required property 'secret_ref' is missing"
        return typing.cast("ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRef", result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipal(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRef",
    jsii_struct_bases=[],
    name_mapping={"client_id": "clientId", "client_secret": "clientSecret"},
)
class ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRef:
    def __init__(
        self,
        *,
        client_id: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRefClientId", typing.Dict[builtins.str, typing.Any]]] = None,
        client_secret: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRefClientSecret", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Configuration used to authenticate with Azure using static credentials stored in a Kind=Secret.

        :param client_id: The Azure clientId of the service principle used for authentication.
        :param client_secret: The Azure ClientSecret of the service principle used for authentication.

        :schema: ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRef
        '''
        if isinstance(client_id, dict):
            client_id = ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRefClientId(**client_id)
        if isinstance(client_secret, dict):
            client_secret = ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRefClientSecret(**client_secret)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__0576c090978772e2637761bf2418b1e576ad1ee0c6e30e25ce92dde0912a4403)
            check_type(argname="argument client_id", value=client_id, expected_type=type_hints["client_id"])
            check_type(argname="argument client_secret", value=client_secret, expected_type=type_hints["client_secret"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if client_id is not None:
            self._values["client_id"] = client_id
        if client_secret is not None:
            self._values["client_secret"] = client_secret

    @builtins.property
    def client_id(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRefClientId"]:
        '''The Azure clientId of the service principle used for authentication.

        :schema: ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRef#clientId
        '''
        result = self._values.get("client_id")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRefClientId"], result)

    @builtins.property
    def client_secret(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRefClientSecret"]:
        '''The Azure ClientSecret of the service principle used for authentication.

        :schema: ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRef#clientSecret
        '''
        result = self._values.get("client_secret")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRefClientSecret"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRefClientId",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRefClientId:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''The Azure clientId of the service principle used for authentication.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRefClientId
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__e68cf16cb70f2ae0d8972eedac8e207caacf468d8b68461fac4d28c373642ec2)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRefClientId#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRefClientId#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRefClientId#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRefClientId(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRefClientSecret",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRefClientSecret:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''The Azure ClientSecret of the service principle used for authentication.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRefClientSecret
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__788ff2bccef6a0ebbe6b1098111be5ad2ba7eee98205a83d00e256cd60b90fe1)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRefClientSecret#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRefClientSecret#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRefClientSecret#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRefClientSecret(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthWorkloadIdentity",
    jsii_struct_bases=[],
    name_mapping={"service_account_ref": "serviceAccountRef"},
)
class ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthWorkloadIdentity:
    def __init__(
        self,
        *,
        service_account_ref: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''WorkloadIdentity uses Azure Workload Identity to authenticate with Azure.

        :param service_account_ref: ServiceAccountRef specified the service account that should be used when authenticating with WorkloadIdentity.

        :schema: ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthWorkloadIdentity
        '''
        if isinstance(service_account_ref, dict):
            service_account_ref = ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef(**service_account_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__7a4acab66a42181590587e19c100a1d7003b65b1d598652c5f1488434a472fee)
            check_type(argname="argument service_account_ref", value=service_account_ref, expected_type=type_hints["service_account_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if service_account_ref is not None:
            self._values["service_account_ref"] = service_account_ref

    @builtins.property
    def service_account_ref(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef"]:
        '''ServiceAccountRef specified the service account that should be used when authenticating with WorkloadIdentity.

        :schema: ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthWorkloadIdentity#serviceAccountRef
        '''
        result = self._values.get("service_account_ref")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthWorkloadIdentity(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "audiences": "audiences", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef:
    def __init__(
        self,
        *,
        name: builtins.str,
        audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''ServiceAccountRef specified the service account that should be used when authenticating with WorkloadIdentity.

        :param name: The name of the ServiceAccount resource being referred to.
        :param audiences: Audience specifies the ``aud`` claim for the service account token If the service account uses a well-known annotation for e.g. IRSA or GCP Workload Identity then this audiences will be appended to the list.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__2c68f57cbeb67b574e5a877d5e187c847dc30c3640b23c4c04763b2a37647017)
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument audiences", value=audiences, expected_type=type_hints["audiences"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "name": name,
        }
        if audiences is not None:
            self._values["audiences"] = audiences
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the ServiceAccount resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def audiences(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Audience specifies the ``aud`` claim for the service account token If the service account uses a well-known annotation for e.g. IRSA or GCP Workload Identity then this audiences will be appended to the list.

        :schema: ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef#audiences
        '''
        result = self._values.get("audiences")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorAcrAccessTokenSpecEnvironmentType"
)
class ClusterGeneratorSpecGeneratorAcrAccessTokenSpecEnvironmentType(enum.Enum):
    '''EnvironmentType specifies the Azure cloud environment endpoints to use for connecting and authenticating with Azure.

    By default it points to the public cloud AAD endpoint.
    The following endpoints are available, also see here: https://github.com/Azure/go-autorest/blob/main/autorest/azure/environments.go#L152
    PublicCloud, USGovernmentCloud, ChinaCloud, GermanCloud

    :schema: ClusterGeneratorSpecGeneratorAcrAccessTokenSpecEnvironmentType
    '''

    PUBLIC_CLOUD = "PUBLIC_CLOUD"
    '''PublicCloud.'''
    US_GOVERNMENT_CLOUD = "US_GOVERNMENT_CLOUD"
    '''USGovernmentCloud.'''
    CHINA_CLOUD = "CHINA_CLOUD"
    '''ChinaCloud.'''
    GERMAN_CLOUD = "GERMAN_CLOUD"
    '''GermanCloud.'''


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpec",
    jsii_struct_bases=[],
    name_mapping={
        "region": "region",
        "auth": "auth",
        "role": "role",
        "scope": "scope",
    },
)
class ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpec:
    def __init__(
        self,
        *,
        region: builtins.str,
        auth: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuth", typing.Dict[builtins.str, typing.Any]]] = None,
        role: typing.Optional[builtins.str] = None,
        scope: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param region: Region specifies the region to operate in.
        :param auth: Auth defines how to authenticate with AWS.
        :param role: You can assume a role before making calls to the desired AWS service.
        :param scope: Scope specifies the ECR service scope. Valid options are private and public.

        :schema: ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpec
        '''
        if isinstance(auth, dict):
            auth = ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuth(**auth)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__7feb236f7f8335245adcf0201e0e6420ddf651d09231a4e577189b005b5398b9)
            check_type(argname="argument region", value=region, expected_type=type_hints["region"])
            check_type(argname="argument auth", value=auth, expected_type=type_hints["auth"])
            check_type(argname="argument role", value=role, expected_type=type_hints["role"])
            check_type(argname="argument scope", value=scope, expected_type=type_hints["scope"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "region": region,
        }
        if auth is not None:
            self._values["auth"] = auth
        if role is not None:
            self._values["role"] = role
        if scope is not None:
            self._values["scope"] = scope

    @builtins.property
    def region(self) -> builtins.str:
        '''Region specifies the region to operate in.

        :schema: ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpec#region
        '''
        result = self._values.get("region")
        assert result is not None, "Required property 'region' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def auth(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuth"]:
        '''Auth defines how to authenticate with AWS.

        :schema: ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpec#auth
        '''
        result = self._values.get("auth")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuth"], result)

    @builtins.property
    def role(self) -> typing.Optional[builtins.str]:
        '''You can assume a role before making calls to the desired AWS service.

        :schema: ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpec#role
        '''
        result = self._values.get("role")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def scope(self) -> typing.Optional[builtins.str]:
        '''Scope specifies the ECR service scope.

        Valid options are private and public.

        :schema: ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpec#scope
        '''
        result = self._values.get("scope")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpec(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuth",
    jsii_struct_bases=[],
    name_mapping={"jwt": "jwt", "secret_ref": "secretRef"},
)
class ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuth:
    def __init__(
        self,
        *,
        jwt: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthJwt", typing.Dict[builtins.str, typing.Any]]] = None,
        secret_ref: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Auth defines how to authenticate with AWS.

        :param jwt: Authenticate against AWS using service account tokens.
        :param secret_ref: AWSAuthSecretRef holds secret references for AWS credentials both AccessKeyID and SecretAccessKey must be defined in order to properly authenticate.

        :schema: ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuth
        '''
        if isinstance(jwt, dict):
            jwt = ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthJwt(**jwt)
        if isinstance(secret_ref, dict):
            secret_ref = ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRef(**secret_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__b49d7ee1addfbf6e7385a299a9ccc30c848df7b4a1e27f2bda288dd43265d0de)
            check_type(argname="argument jwt", value=jwt, expected_type=type_hints["jwt"])
            check_type(argname="argument secret_ref", value=secret_ref, expected_type=type_hints["secret_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if jwt is not None:
            self._values["jwt"] = jwt
        if secret_ref is not None:
            self._values["secret_ref"] = secret_ref

    @builtins.property
    def jwt(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthJwt"]:
        '''Authenticate against AWS using service account tokens.

        :schema: ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuth#jwt
        '''
        result = self._values.get("jwt")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthJwt"], result)

    @builtins.property
    def secret_ref(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRef"]:
        '''AWSAuthSecretRef holds secret references for AWS credentials both AccessKeyID and SecretAccessKey must be defined in order to properly authenticate.

        :schema: ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuth#secretRef
        '''
        result = self._values.get("secret_ref")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuth(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthJwt",
    jsii_struct_bases=[],
    name_mapping={"service_account_ref": "serviceAccountRef"},
)
class ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthJwt:
    def __init__(
        self,
        *,
        service_account_ref: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthJwtServiceAccountRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Authenticate against AWS using service account tokens.

        :param service_account_ref: A reference to a ServiceAccount resource.

        :schema: ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthJwt
        '''
        if isinstance(service_account_ref, dict):
            service_account_ref = ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthJwtServiceAccountRef(**service_account_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__999087dd2add6c11bb5aebdfa9c03015b3c8b3e432c6c576b46596aac07d1c22)
            check_type(argname="argument service_account_ref", value=service_account_ref, expected_type=type_hints["service_account_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if service_account_ref is not None:
            self._values["service_account_ref"] = service_account_ref

    @builtins.property
    def service_account_ref(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthJwtServiceAccountRef"]:
        '''A reference to a ServiceAccount resource.

        :schema: ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthJwt#serviceAccountRef
        '''
        result = self._values.get("service_account_ref")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthJwtServiceAccountRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthJwt(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthJwtServiceAccountRef",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "audiences": "audiences", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthJwtServiceAccountRef:
    def __init__(
        self,
        *,
        name: builtins.str,
        audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''A reference to a ServiceAccount resource.

        :param name: The name of the ServiceAccount resource being referred to.
        :param audiences: Audience specifies the ``aud`` claim for the service account token If the service account uses a well-known annotation for e.g. IRSA or GCP Workload Identity then this audiences will be appended to the list.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthJwtServiceAccountRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__544153e51088c5c19ab22ddfc28cae00e464ac73d8349a958d037764766cf9f8)
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument audiences", value=audiences, expected_type=type_hints["audiences"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "name": name,
        }
        if audiences is not None:
            self._values["audiences"] = audiences
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the ServiceAccount resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthJwtServiceAccountRef#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def audiences(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Audience specifies the ``aud`` claim for the service account token If the service account uses a well-known annotation for e.g. IRSA or GCP Workload Identity then this audiences will be appended to the list.

        :schema: ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthJwtServiceAccountRef#audiences
        '''
        result = self._values.get("audiences")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthJwtServiceAccountRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthJwtServiceAccountRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRef",
    jsii_struct_bases=[],
    name_mapping={
        "access_key_id_secret_ref": "accessKeyIdSecretRef",
        "secret_access_key_secret_ref": "secretAccessKeySecretRef",
        "session_token_secret_ref": "sessionTokenSecretRef",
    },
)
class ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRef:
    def __init__(
        self,
        *,
        access_key_id_secret_ref: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefAccessKeyIdSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
        secret_access_key_secret_ref: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefSecretAccessKeySecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
        session_token_secret_ref: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefSessionTokenSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''AWSAuthSecretRef holds secret references for AWS credentials both AccessKeyID and SecretAccessKey must be defined in order to properly authenticate.

        :param access_key_id_secret_ref: The AccessKeyID is used for authentication.
        :param secret_access_key_secret_ref: The SecretAccessKey is used for authentication.
        :param session_token_secret_ref: The SessionToken used for authentication This must be defined if AccessKeyID and SecretAccessKey are temporary credentials see: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html.

        :schema: ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRef
        '''
        if isinstance(access_key_id_secret_ref, dict):
            access_key_id_secret_ref = ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefAccessKeyIdSecretRef(**access_key_id_secret_ref)
        if isinstance(secret_access_key_secret_ref, dict):
            secret_access_key_secret_ref = ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefSecretAccessKeySecretRef(**secret_access_key_secret_ref)
        if isinstance(session_token_secret_ref, dict):
            session_token_secret_ref = ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefSessionTokenSecretRef(**session_token_secret_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__43a336479ba385edf417d5a66424a3fcf31b9f4115de62dc32d60ac5f316d383)
            check_type(argname="argument access_key_id_secret_ref", value=access_key_id_secret_ref, expected_type=type_hints["access_key_id_secret_ref"])
            check_type(argname="argument secret_access_key_secret_ref", value=secret_access_key_secret_ref, expected_type=type_hints["secret_access_key_secret_ref"])
            check_type(argname="argument session_token_secret_ref", value=session_token_secret_ref, expected_type=type_hints["session_token_secret_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if access_key_id_secret_ref is not None:
            self._values["access_key_id_secret_ref"] = access_key_id_secret_ref
        if secret_access_key_secret_ref is not None:
            self._values["secret_access_key_secret_ref"] = secret_access_key_secret_ref
        if session_token_secret_ref is not None:
            self._values["session_token_secret_ref"] = session_token_secret_ref

    @builtins.property
    def access_key_id_secret_ref(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefAccessKeyIdSecretRef"]:
        '''The AccessKeyID is used for authentication.

        :schema: ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRef#accessKeyIDSecretRef
        '''
        result = self._values.get("access_key_id_secret_ref")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefAccessKeyIdSecretRef"], result)

    @builtins.property
    def secret_access_key_secret_ref(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefSecretAccessKeySecretRef"]:
        '''The SecretAccessKey is used for authentication.

        :schema: ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRef#secretAccessKeySecretRef
        '''
        result = self._values.get("secret_access_key_secret_ref")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefSecretAccessKeySecretRef"], result)

    @builtins.property
    def session_token_secret_ref(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefSessionTokenSecretRef"]:
        '''The SessionToken used for authentication This must be defined if AccessKeyID and SecretAccessKey are temporary credentials see: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html.

        :schema: ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRef#sessionTokenSecretRef
        '''
        result = self._values.get("session_token_secret_ref")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefSessionTokenSecretRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefAccessKeyIdSecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefAccessKeyIdSecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''The AccessKeyID is used for authentication.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefAccessKeyIdSecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__f97c93efa15a9809bde63d0f97633067aff530a43ed949824dc7bc76e9871735)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefAccessKeyIdSecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefAccessKeyIdSecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefAccessKeyIdSecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefAccessKeyIdSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefSecretAccessKeySecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefSecretAccessKeySecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''The SecretAccessKey is used for authentication.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefSecretAccessKeySecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__bde2f101525a2945490e3e868e0c47768925132383751c8fc136c6399674bdba)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefSecretAccessKeySecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefSecretAccessKeySecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefSecretAccessKeySecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefSecretAccessKeySecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefSessionTokenSecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefSessionTokenSecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''The SessionToken used for authentication This must be defined if AccessKeyID and SecretAccessKey are temporary credentials see: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefSessionTokenSecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__7a4a61094821c7569683a2f537b0248ded8e4d034dbd5066ed28c9e88da147e4)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefSessionTokenSecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefSessionTokenSecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefSessionTokenSecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefSessionTokenSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorFakeSpec",
    jsii_struct_bases=[],
    name_mapping={"controller": "controller", "data": "data"},
)
class ClusterGeneratorSpecGeneratorFakeSpec:
    def __init__(
        self,
        *,
        controller: typing.Optional[builtins.str] = None,
        data: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''FakeSpec contains the static data.

        :param controller: Used to select the correct ESO controller (think: ingress.ingressClassName) The ESO controller is instantiated with a specific controller name and filters VDS based on this property.
        :param data: Data defines the static data returned by this generator.

        :schema: ClusterGeneratorSpecGeneratorFakeSpec
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__2c86832ce77d47f397dde092dc8227f1703d1315bd5a48a4515d7255dd73a887)
            check_type(argname="argument controller", value=controller, expected_type=type_hints["controller"])
            check_type(argname="argument data", value=data, expected_type=type_hints["data"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if controller is not None:
            self._values["controller"] = controller
        if data is not None:
            self._values["data"] = data

    @builtins.property
    def controller(self) -> typing.Optional[builtins.str]:
        '''Used to select the correct ESO controller (think: ingress.ingressClassName) The ESO controller is instantiated with a specific controller name and filters VDS based on this property.

        :schema: ClusterGeneratorSpecGeneratorFakeSpec#controller
        '''
        result = self._values.get("controller")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def data(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Data defines the static data returned by this generator.

        :schema: ClusterGeneratorSpecGeneratorFakeSpec#data
        '''
        result = self._values.get("data")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorFakeSpec(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorGcrAccessTokenSpec",
    jsii_struct_bases=[],
    name_mapping={"auth": "auth", "project_id": "projectId"},
)
class ClusterGeneratorSpecGeneratorGcrAccessTokenSpec:
    def __init__(
        self,
        *,
        auth: typing.Union["ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuth", typing.Dict[builtins.str, typing.Any]],
        project_id: builtins.str,
    ) -> None:
        '''
        :param auth: Auth defines the means for authenticating with GCP.
        :param project_id: ProjectID defines which project to use to authenticate with.

        :schema: ClusterGeneratorSpecGeneratorGcrAccessTokenSpec
        '''
        if isinstance(auth, dict):
            auth = ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuth(**auth)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__6b9360ae269e38195de96ddce27de70ca878354be107a7d7c5e7f7f3a5ff18c8)
            check_type(argname="argument auth", value=auth, expected_type=type_hints["auth"])
            check_type(argname="argument project_id", value=project_id, expected_type=type_hints["project_id"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "auth": auth,
            "project_id": project_id,
        }

    @builtins.property
    def auth(self) -> "ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuth":
        '''Auth defines the means for authenticating with GCP.

        :schema: ClusterGeneratorSpecGeneratorGcrAccessTokenSpec#auth
        '''
        result = self._values.get("auth")
        assert result is not None, "Required property 'auth' is missing"
        return typing.cast("ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuth", result)

    @builtins.property
    def project_id(self) -> builtins.str:
        '''ProjectID defines which project to use to authenticate with.

        :schema: ClusterGeneratorSpecGeneratorGcrAccessTokenSpec#projectID
        '''
        result = self._values.get("project_id")
        assert result is not None, "Required property 'project_id' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorGcrAccessTokenSpec(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuth",
    jsii_struct_bases=[],
    name_mapping={"secret_ref": "secretRef", "workload_identity": "workloadIdentity"},
)
class ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuth:
    def __init__(
        self,
        *,
        secret_ref: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
        workload_identity: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthWorkloadIdentity", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Auth defines the means for authenticating with GCP.

        :param secret_ref: 
        :param workload_identity: 

        :schema: ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuth
        '''
        if isinstance(secret_ref, dict):
            secret_ref = ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthSecretRef(**secret_ref)
        if isinstance(workload_identity, dict):
            workload_identity = ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthWorkloadIdentity(**workload_identity)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__5c8999aeefd932f01d9db846a206c060725cfe557132891c96a281dd55eb65cb)
            check_type(argname="argument secret_ref", value=secret_ref, expected_type=type_hints["secret_ref"])
            check_type(argname="argument workload_identity", value=workload_identity, expected_type=type_hints["workload_identity"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if secret_ref is not None:
            self._values["secret_ref"] = secret_ref
        if workload_identity is not None:
            self._values["workload_identity"] = workload_identity

    @builtins.property
    def secret_ref(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthSecretRef"]:
        '''
        :schema: ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuth#secretRef
        '''
        result = self._values.get("secret_ref")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthSecretRef"], result)

    @builtins.property
    def workload_identity(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthWorkloadIdentity"]:
        '''
        :schema: ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuth#workloadIdentity
        '''
        result = self._values.get("workload_identity")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthWorkloadIdentity"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuth(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthSecretRef",
    jsii_struct_bases=[],
    name_mapping={"secret_access_key_secret_ref": "secretAccessKeySecretRef"},
)
class ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthSecretRef:
    def __init__(
        self,
        *,
        secret_access_key_secret_ref: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthSecretRefSecretAccessKeySecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''
        :param secret_access_key_secret_ref: The SecretAccessKey is used for authentication.

        :schema: ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthSecretRef
        '''
        if isinstance(secret_access_key_secret_ref, dict):
            secret_access_key_secret_ref = ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthSecretRefSecretAccessKeySecretRef(**secret_access_key_secret_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__69d2db6600643f3c5fa4f842ad2a5bbebaa2fb26b7dafa8012171b5e49d181b3)
            check_type(argname="argument secret_access_key_secret_ref", value=secret_access_key_secret_ref, expected_type=type_hints["secret_access_key_secret_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if secret_access_key_secret_ref is not None:
            self._values["secret_access_key_secret_ref"] = secret_access_key_secret_ref

    @builtins.property
    def secret_access_key_secret_ref(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthSecretRefSecretAccessKeySecretRef"]:
        '''The SecretAccessKey is used for authentication.

        :schema: ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthSecretRef#secretAccessKeySecretRef
        '''
        result = self._values.get("secret_access_key_secret_ref")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthSecretRefSecretAccessKeySecretRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthSecretRefSecretAccessKeySecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthSecretRefSecretAccessKeySecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''The SecretAccessKey is used for authentication.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthSecretRefSecretAccessKeySecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__34a05f31abd31deb2dcbf758e0186bd7aecddb446e8f2b2fa7d99ea3d9e87bdd)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthSecretRefSecretAccessKeySecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthSecretRefSecretAccessKeySecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthSecretRefSecretAccessKeySecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthSecretRefSecretAccessKeySecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthWorkloadIdentity",
    jsii_struct_bases=[],
    name_mapping={
        "cluster_location": "clusterLocation",
        "cluster_name": "clusterName",
        "service_account_ref": "serviceAccountRef",
        "cluster_project_id": "clusterProjectId",
    },
)
class ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthWorkloadIdentity:
    def __init__(
        self,
        *,
        cluster_location: builtins.str,
        cluster_name: builtins.str,
        service_account_ref: typing.Union["ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef", typing.Dict[builtins.str, typing.Any]],
        cluster_project_id: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param cluster_location: 
        :param cluster_name: 
        :param service_account_ref: A reference to a ServiceAccount resource.
        :param cluster_project_id: 

        :schema: ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthWorkloadIdentity
        '''
        if isinstance(service_account_ref, dict):
            service_account_ref = ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef(**service_account_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__887b623b0239bbb2317604070f1fb61930a4e755b022243ffbd63f615a93873a)
            check_type(argname="argument cluster_location", value=cluster_location, expected_type=type_hints["cluster_location"])
            check_type(argname="argument cluster_name", value=cluster_name, expected_type=type_hints["cluster_name"])
            check_type(argname="argument service_account_ref", value=service_account_ref, expected_type=type_hints["service_account_ref"])
            check_type(argname="argument cluster_project_id", value=cluster_project_id, expected_type=type_hints["cluster_project_id"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "cluster_location": cluster_location,
            "cluster_name": cluster_name,
            "service_account_ref": service_account_ref,
        }
        if cluster_project_id is not None:
            self._values["cluster_project_id"] = cluster_project_id

    @builtins.property
    def cluster_location(self) -> builtins.str:
        '''
        :schema: ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthWorkloadIdentity#clusterLocation
        '''
        result = self._values.get("cluster_location")
        assert result is not None, "Required property 'cluster_location' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def cluster_name(self) -> builtins.str:
        '''
        :schema: ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthWorkloadIdentity#clusterName
        '''
        result = self._values.get("cluster_name")
        assert result is not None, "Required property 'cluster_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def service_account_ref(
        self,
    ) -> "ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef":
        '''A reference to a ServiceAccount resource.

        :schema: ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthWorkloadIdentity#serviceAccountRef
        '''
        result = self._values.get("service_account_ref")
        assert result is not None, "Required property 'service_account_ref' is missing"
        return typing.cast("ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef", result)

    @builtins.property
    def cluster_project_id(self) -> typing.Optional[builtins.str]:
        '''
        :schema: ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthWorkloadIdentity#clusterProjectID
        '''
        result = self._values.get("cluster_project_id")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthWorkloadIdentity(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "audiences": "audiences", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef:
    def __init__(
        self,
        *,
        name: builtins.str,
        audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''A reference to a ServiceAccount resource.

        :param name: The name of the ServiceAccount resource being referred to.
        :param audiences: Audience specifies the ``aud`` claim for the service account token If the service account uses a well-known annotation for e.g. IRSA or GCP Workload Identity then this audiences will be appended to the list.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__5414094787b3664e12f165e43a7b615bd19ef1a0e2034f3d3c910a2379cdce1d)
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument audiences", value=audiences, expected_type=type_hints["audiences"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "name": name,
        }
        if audiences is not None:
            self._values["audiences"] = audiences
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the ServiceAccount resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def audiences(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Audience specifies the ``aud`` claim for the service account token If the service account uses a well-known annotation for e.g. IRSA or GCP Workload Identity then this audiences will be appended to the list.

        :schema: ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef#audiences
        '''
        result = self._values.get("audiences")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorGithubAccessTokenSpec",
    jsii_struct_bases=[],
    name_mapping={
        "app_id": "appId",
        "auth": "auth",
        "install_id": "installId",
        "permissions": "permissions",
        "repositories": "repositories",
        "url": "url",
    },
)
class ClusterGeneratorSpecGeneratorGithubAccessTokenSpec:
    def __init__(
        self,
        *,
        app_id: builtins.str,
        auth: typing.Union["ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuth", typing.Dict[builtins.str, typing.Any]],
        install_id: builtins.str,
        permissions: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        repositories: typing.Optional[typing.Sequence[builtins.str]] = None,
        url: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param app_id: 
        :param auth: Auth configures how ESO authenticates with a Github instance.
        :param install_id: 
        :param permissions: Map of permissions the token will have. If omitted, defaults to all permissions the GitHub App has.
        :param repositories: List of repositories the token will have access to. If omitted, defaults to all repositories the GitHub App is installed to.
        :param url: URL configures the Github instance URL. Defaults to https://github.com/. Default: https://github.com/.

        :schema: ClusterGeneratorSpecGeneratorGithubAccessTokenSpec
        '''
        if isinstance(auth, dict):
            auth = ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuth(**auth)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__292ec9b435c52ded2f9e1a3fc879dc60a480c74153810bcd8257587046e66853)
            check_type(argname="argument app_id", value=app_id, expected_type=type_hints["app_id"])
            check_type(argname="argument auth", value=auth, expected_type=type_hints["auth"])
            check_type(argname="argument install_id", value=install_id, expected_type=type_hints["install_id"])
            check_type(argname="argument permissions", value=permissions, expected_type=type_hints["permissions"])
            check_type(argname="argument repositories", value=repositories, expected_type=type_hints["repositories"])
            check_type(argname="argument url", value=url, expected_type=type_hints["url"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "app_id": app_id,
            "auth": auth,
            "install_id": install_id,
        }
        if permissions is not None:
            self._values["permissions"] = permissions
        if repositories is not None:
            self._values["repositories"] = repositories
        if url is not None:
            self._values["url"] = url

    @builtins.property
    def app_id(self) -> builtins.str:
        '''
        :schema: ClusterGeneratorSpecGeneratorGithubAccessTokenSpec#appID
        '''
        result = self._values.get("app_id")
        assert result is not None, "Required property 'app_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def auth(self) -> "ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuth":
        '''Auth configures how ESO authenticates with a Github instance.

        :schema: ClusterGeneratorSpecGeneratorGithubAccessTokenSpec#auth
        '''
        result = self._values.get("auth")
        assert result is not None, "Required property 'auth' is missing"
        return typing.cast("ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuth", result)

    @builtins.property
    def install_id(self) -> builtins.str:
        '''
        :schema: ClusterGeneratorSpecGeneratorGithubAccessTokenSpec#installID
        '''
        result = self._values.get("install_id")
        assert result is not None, "Required property 'install_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def permissions(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Map of permissions the token will have.

        If omitted, defaults to all permissions the GitHub App has.

        :schema: ClusterGeneratorSpecGeneratorGithubAccessTokenSpec#permissions
        '''
        result = self._values.get("permissions")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def repositories(self) -> typing.Optional[typing.List[builtins.str]]:
        '''List of repositories the token will have access to.

        If omitted, defaults to all repositories the GitHub App
        is installed to.

        :schema: ClusterGeneratorSpecGeneratorGithubAccessTokenSpec#repositories
        '''
        result = self._values.get("repositories")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def url(self) -> typing.Optional[builtins.str]:
        '''URL configures the Github instance URL.

        Defaults to https://github.com/.

        :default: https://github.com/.

        :schema: ClusterGeneratorSpecGeneratorGithubAccessTokenSpec#url
        '''
        result = self._values.get("url")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorGithubAccessTokenSpec(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuth",
    jsii_struct_bases=[],
    name_mapping={"private_key": "privateKey"},
)
class ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuth:
    def __init__(
        self,
        *,
        private_key: typing.Union["ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuthPrivateKey", typing.Dict[builtins.str, typing.Any]],
    ) -> None:
        '''Auth configures how ESO authenticates with a Github instance.

        :param private_key: 

        :schema: ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuth
        '''
        if isinstance(private_key, dict):
            private_key = ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuthPrivateKey(**private_key)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__1110b3599256f7705731d088240f75aee915ccf9f75505751961559d4cea83e0)
            check_type(argname="argument private_key", value=private_key, expected_type=type_hints["private_key"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "private_key": private_key,
        }

    @builtins.property
    def private_key(
        self,
    ) -> "ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuthPrivateKey":
        '''
        :schema: ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuth#privateKey
        '''
        result = self._values.get("private_key")
        assert result is not None, "Required property 'private_key' is missing"
        return typing.cast("ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuthPrivateKey", result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuth(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuthPrivateKey",
    jsii_struct_bases=[],
    name_mapping={"secret_ref": "secretRef"},
)
class ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuthPrivateKey:
    def __init__(
        self,
        *,
        secret_ref: typing.Union["ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuthPrivateKeySecretRef", typing.Dict[builtins.str, typing.Any]],
    ) -> None:
        '''
        :param secret_ref: A reference to a specific 'key' within a Secret resource. In some instances, ``key`` is a required field.

        :schema: ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuthPrivateKey
        '''
        if isinstance(secret_ref, dict):
            secret_ref = ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuthPrivateKeySecretRef(**secret_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__337db2c2fa34849a191d608439f90fac159f2d703d407a4522719e4df8609142)
            check_type(argname="argument secret_ref", value=secret_ref, expected_type=type_hints["secret_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "secret_ref": secret_ref,
        }

    @builtins.property
    def secret_ref(
        self,
    ) -> "ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuthPrivateKeySecretRef":
        '''A reference to a specific 'key' within a Secret resource.

        In some instances, ``key`` is a required field.

        :schema: ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuthPrivateKey#secretRef
        '''
        result = self._values.get("secret_ref")
        assert result is not None, "Required property 'secret_ref' is missing"
        return typing.cast("ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuthPrivateKeySecretRef", result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuthPrivateKey(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuthPrivateKeySecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuthPrivateKeySecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''A reference to a specific 'key' within a Secret resource.

        In some instances, ``key`` is a required field.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuthPrivateKeySecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__9f5225114d04258c4451905d0b8fab6c9f168173f252619ec0e7e3456af07f4c)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuthPrivateKeySecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuthPrivateKeySecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuthPrivateKeySecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuthPrivateKeySecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorGrafanaSpec",
    jsii_struct_bases=[],
    name_mapping={"auth": "auth", "service_account": "serviceAccount", "url": "url"},
)
class ClusterGeneratorSpecGeneratorGrafanaSpec:
    def __init__(
        self,
        *,
        auth: typing.Union["ClusterGeneratorSpecGeneratorGrafanaSpecAuth", typing.Dict[builtins.str, typing.Any]],
        service_account: typing.Union["ClusterGeneratorSpecGeneratorGrafanaSpecServiceAccount", typing.Dict[builtins.str, typing.Any]],
        url: builtins.str,
    ) -> None:
        '''GrafanaSpec controls the behavior of the grafana generator.

        :param auth: Auth is the authentication configuration to authenticate against the Grafana instance.
        :param service_account: ServiceAccount is the configuration for the service account that is supposed to be generated by the generator.
        :param url: URL is the URL of the Grafana instance.

        :schema: ClusterGeneratorSpecGeneratorGrafanaSpec
        '''
        if isinstance(auth, dict):
            auth = ClusterGeneratorSpecGeneratorGrafanaSpecAuth(**auth)
        if isinstance(service_account, dict):
            service_account = ClusterGeneratorSpecGeneratorGrafanaSpecServiceAccount(**service_account)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__a03b1f0e454b3b76e179e25c68ac74f11bb9cebe3337ab374b3f2ed4d9ed2181)
            check_type(argname="argument auth", value=auth, expected_type=type_hints["auth"])
            check_type(argname="argument service_account", value=service_account, expected_type=type_hints["service_account"])
            check_type(argname="argument url", value=url, expected_type=type_hints["url"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "auth": auth,
            "service_account": service_account,
            "url": url,
        }

    @builtins.property
    def auth(self) -> "ClusterGeneratorSpecGeneratorGrafanaSpecAuth":
        '''Auth is the authentication configuration to authenticate against the Grafana instance.

        :schema: ClusterGeneratorSpecGeneratorGrafanaSpec#auth
        '''
        result = self._values.get("auth")
        assert result is not None, "Required property 'auth' is missing"
        return typing.cast("ClusterGeneratorSpecGeneratorGrafanaSpecAuth", result)

    @builtins.property
    def service_account(
        self,
    ) -> "ClusterGeneratorSpecGeneratorGrafanaSpecServiceAccount":
        '''ServiceAccount is the configuration for the service account that is supposed to be generated by the generator.

        :schema: ClusterGeneratorSpecGeneratorGrafanaSpec#serviceAccount
        '''
        result = self._values.get("service_account")
        assert result is not None, "Required property 'service_account' is missing"
        return typing.cast("ClusterGeneratorSpecGeneratorGrafanaSpecServiceAccount", result)

    @builtins.property
    def url(self) -> builtins.str:
        '''URL is the URL of the Grafana instance.

        :schema: ClusterGeneratorSpecGeneratorGrafanaSpec#url
        '''
        result = self._values.get("url")
        assert result is not None, "Required property 'url' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorGrafanaSpec(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorGrafanaSpecAuth",
    jsii_struct_bases=[],
    name_mapping={"basic": "basic", "token": "token"},
)
class ClusterGeneratorSpecGeneratorGrafanaSpecAuth:
    def __init__(
        self,
        *,
        basic: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorGrafanaSpecAuthBasic", typing.Dict[builtins.str, typing.Any]]] = None,
        token: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorGrafanaSpecAuthToken", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Auth is the authentication configuration to authenticate against the Grafana instance.

        :param basic: Basic auth credentials used to authenticate against the Grafana instance. Note: you need a token which has elevated permissions to create service accounts. See here for the documentation on basic roles offered by Grafana: https://grafana.com/docs/grafana/latest/administration/roles-and-permissions/access-control/rbac-fixed-basic-role-definitions/
        :param token: A service account token used to authenticate against the Grafana instance. Note: you need a token which has elevated permissions to create service accounts. See here for the documentation on basic roles offered by Grafana: https://grafana.com/docs/grafana/latest/administration/roles-and-permissions/access-control/rbac-fixed-basic-role-definitions/

        :schema: ClusterGeneratorSpecGeneratorGrafanaSpecAuth
        '''
        if isinstance(basic, dict):
            basic = ClusterGeneratorSpecGeneratorGrafanaSpecAuthBasic(**basic)
        if isinstance(token, dict):
            token = ClusterGeneratorSpecGeneratorGrafanaSpecAuthToken(**token)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__c7d48488f332ab62b6ff8f5758ff141bd4ec8d41be6369cc454654d1635bc550)
            check_type(argname="argument basic", value=basic, expected_type=type_hints["basic"])
            check_type(argname="argument token", value=token, expected_type=type_hints["token"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if basic is not None:
            self._values["basic"] = basic
        if token is not None:
            self._values["token"] = token

    @builtins.property
    def basic(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorGrafanaSpecAuthBasic"]:
        '''Basic auth credentials used to authenticate against the Grafana instance.

        Note: you need a token which has elevated permissions to create service accounts.
        See here for the documentation on basic roles offered by Grafana:
        https://grafana.com/docs/grafana/latest/administration/roles-and-permissions/access-control/rbac-fixed-basic-role-definitions/

        :schema: ClusterGeneratorSpecGeneratorGrafanaSpecAuth#basic
        '''
        result = self._values.get("basic")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorGrafanaSpecAuthBasic"], result)

    @builtins.property
    def token(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorGrafanaSpecAuthToken"]:
        '''A service account token used to authenticate against the Grafana instance.

        Note: you need a token which has elevated permissions to create service accounts.
        See here for the documentation on basic roles offered by Grafana:
        https://grafana.com/docs/grafana/latest/administration/roles-and-permissions/access-control/rbac-fixed-basic-role-definitions/

        :schema: ClusterGeneratorSpecGeneratorGrafanaSpecAuth#token
        '''
        result = self._values.get("token")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorGrafanaSpecAuthToken"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorGrafanaSpecAuth(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorGrafanaSpecAuthBasic",
    jsii_struct_bases=[],
    name_mapping={"password": "password", "username": "username"},
)
class ClusterGeneratorSpecGeneratorGrafanaSpecAuthBasic:
    def __init__(
        self,
        *,
        password: typing.Union["ClusterGeneratorSpecGeneratorGrafanaSpecAuthBasicPassword", typing.Dict[builtins.str, typing.Any]],
        username: builtins.str,
    ) -> None:
        '''Basic auth credentials used to authenticate against the Grafana instance.

        Note: you need a token which has elevated permissions to create service accounts.
        See here for the documentation on basic roles offered by Grafana:
        https://grafana.com/docs/grafana/latest/administration/roles-and-permissions/access-control/rbac-fixed-basic-role-definitions/

        :param password: A basic auth password used to authenticate against the Grafana instance.
        :param username: A basic auth username used to authenticate against the Grafana instance.

        :schema: ClusterGeneratorSpecGeneratorGrafanaSpecAuthBasic
        '''
        if isinstance(password, dict):
            password = ClusterGeneratorSpecGeneratorGrafanaSpecAuthBasicPassword(**password)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__0ca9e0312250798706b0bbbc493bb9f05d7676fc92dd825ae023d37d7286ef86)
            check_type(argname="argument password", value=password, expected_type=type_hints["password"])
            check_type(argname="argument username", value=username, expected_type=type_hints["username"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "password": password,
            "username": username,
        }

    @builtins.property
    def password(self) -> "ClusterGeneratorSpecGeneratorGrafanaSpecAuthBasicPassword":
        '''A basic auth password used to authenticate against the Grafana instance.

        :schema: ClusterGeneratorSpecGeneratorGrafanaSpecAuthBasic#password
        '''
        result = self._values.get("password")
        assert result is not None, "Required property 'password' is missing"
        return typing.cast("ClusterGeneratorSpecGeneratorGrafanaSpecAuthBasicPassword", result)

    @builtins.property
    def username(self) -> builtins.str:
        '''A basic auth username used to authenticate against the Grafana instance.

        :schema: ClusterGeneratorSpecGeneratorGrafanaSpecAuthBasic#username
        '''
        result = self._values.get("username")
        assert result is not None, "Required property 'username' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorGrafanaSpecAuthBasic(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorGrafanaSpecAuthBasicPassword",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name"},
)
class ClusterGeneratorSpecGeneratorGrafanaSpecAuthBasicPassword:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''A basic auth password used to authenticate against the Grafana instance.

        :param key: The key where the token is found.
        :param name: The name of the Secret resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorGrafanaSpecAuthBasicPassword
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__52cbf108e35477a5a146125711b6edb5cb2e91146f6276f2d40795dc8149d0ec)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''The key where the token is found.

        :schema: ClusterGeneratorSpecGeneratorGrafanaSpecAuthBasicPassword#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorGrafanaSpecAuthBasicPassword#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorGrafanaSpecAuthBasicPassword(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorGrafanaSpecAuthToken",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name"},
)
class ClusterGeneratorSpecGeneratorGrafanaSpecAuthToken:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''A service account token used to authenticate against the Grafana instance.

        Note: you need a token which has elevated permissions to create service accounts.
        See here for the documentation on basic roles offered by Grafana:
        https://grafana.com/docs/grafana/latest/administration/roles-and-permissions/access-control/rbac-fixed-basic-role-definitions/

        :param key: The key where the token is found.
        :param name: The name of the Secret resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorGrafanaSpecAuthToken
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__5d5967d1dd883faa977030d1a3045ba2620b8f9c2c50ca22bba80be43429c9fe)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''The key where the token is found.

        :schema: ClusterGeneratorSpecGeneratorGrafanaSpecAuthToken#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorGrafanaSpecAuthToken#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorGrafanaSpecAuthToken(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorGrafanaSpecServiceAccount",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "role": "role"},
)
class ClusterGeneratorSpecGeneratorGrafanaSpecServiceAccount:
    def __init__(self, *, name: builtins.str, role: builtins.str) -> None:
        '''ServiceAccount is the configuration for the service account that is supposed to be generated by the generator.

        :param name: Name is the name of the service account that will be created by ESO.
        :param role: Role is the role of the service account. See here for the documentation on basic roles offered by Grafana: https://grafana.com/docs/grafana/latest/administration/roles-and-permissions/access-control/rbac-fixed-basic-role-definitions/

        :schema: ClusterGeneratorSpecGeneratorGrafanaSpecServiceAccount
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__c952f78a75a5bbd20df3105965c9af2c7aabb17469a906f4db76fe7c9d677307)
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument role", value=role, expected_type=type_hints["role"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "name": name,
            "role": role,
        }

    @builtins.property
    def name(self) -> builtins.str:
        '''Name is the name of the service account that will be created by ESO.

        :schema: ClusterGeneratorSpecGeneratorGrafanaSpecServiceAccount#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def role(self) -> builtins.str:
        '''Role is the role of the service account.

        See here for the documentation on basic roles offered by Grafana:
        https://grafana.com/docs/grafana/latest/administration/roles-and-permissions/access-control/rbac-fixed-basic-role-definitions/

        :schema: ClusterGeneratorSpecGeneratorGrafanaSpecServiceAccount#role
        '''
        result = self._values.get("role")
        assert result is not None, "Required property 'role' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorGrafanaSpecServiceAccount(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorPasswordSpec",
    jsii_struct_bases=[],
    name_mapping={
        "allow_repeat": "allowRepeat",
        "length": "length",
        "no_upper": "noUpper",
        "digits": "digits",
        "symbol_characters": "symbolCharacters",
        "symbols": "symbols",
    },
)
class ClusterGeneratorSpecGeneratorPasswordSpec:
    def __init__(
        self,
        *,
        allow_repeat: builtins.bool,
        length: jsii.Number,
        no_upper: builtins.bool,
        digits: typing.Optional[jsii.Number] = None,
        symbol_characters: typing.Optional[builtins.str] = None,
        symbols: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''PasswordSpec controls the behavior of the password generator.

        :param allow_repeat: set AllowRepeat to true to allow repeating characters.
        :param length: Length of the password to be generated. Defaults to 24 Default: 24
        :param no_upper: Set NoUpper to disable uppercase characters.
        :param digits: Digits specifies the number of digits in the generated password. If omitted it defaults to 25% of the length of the password
        :param symbol_characters: SymbolCharacters specifies the special characters that should be used in the generated password.
        :param symbols: Symbols specifies the number of symbol characters in the generated password. If omitted it defaults to 25% of the length of the password

        :schema: ClusterGeneratorSpecGeneratorPasswordSpec
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__6b3ec65a0916fa97e69ec9837c4c6798e17e81eb424563cc5bd5349de2ec13d6)
            check_type(argname="argument allow_repeat", value=allow_repeat, expected_type=type_hints["allow_repeat"])
            check_type(argname="argument length", value=length, expected_type=type_hints["length"])
            check_type(argname="argument no_upper", value=no_upper, expected_type=type_hints["no_upper"])
            check_type(argname="argument digits", value=digits, expected_type=type_hints["digits"])
            check_type(argname="argument symbol_characters", value=symbol_characters, expected_type=type_hints["symbol_characters"])
            check_type(argname="argument symbols", value=symbols, expected_type=type_hints["symbols"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "allow_repeat": allow_repeat,
            "length": length,
            "no_upper": no_upper,
        }
        if digits is not None:
            self._values["digits"] = digits
        if symbol_characters is not None:
            self._values["symbol_characters"] = symbol_characters
        if symbols is not None:
            self._values["symbols"] = symbols

    @builtins.property
    def allow_repeat(self) -> builtins.bool:
        '''set AllowRepeat to true to allow repeating characters.

        :schema: ClusterGeneratorSpecGeneratorPasswordSpec#allowRepeat
        '''
        result = self._values.get("allow_repeat")
        assert result is not None, "Required property 'allow_repeat' is missing"
        return typing.cast(builtins.bool, result)

    @builtins.property
    def length(self) -> jsii.Number:
        '''Length of the password to be generated.

        Defaults to 24

        :default: 24

        :schema: ClusterGeneratorSpecGeneratorPasswordSpec#length
        '''
        result = self._values.get("length")
        assert result is not None, "Required property 'length' is missing"
        return typing.cast(jsii.Number, result)

    @builtins.property
    def no_upper(self) -> builtins.bool:
        '''Set NoUpper to disable uppercase characters.

        :schema: ClusterGeneratorSpecGeneratorPasswordSpec#noUpper
        '''
        result = self._values.get("no_upper")
        assert result is not None, "Required property 'no_upper' is missing"
        return typing.cast(builtins.bool, result)

    @builtins.property
    def digits(self) -> typing.Optional[jsii.Number]:
        '''Digits specifies the number of digits in the generated password.

        If omitted it defaults to 25% of the length of the password

        :schema: ClusterGeneratorSpecGeneratorPasswordSpec#digits
        '''
        result = self._values.get("digits")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def symbol_characters(self) -> typing.Optional[builtins.str]:
        '''SymbolCharacters specifies the special characters that should be used in the generated password.

        :schema: ClusterGeneratorSpecGeneratorPasswordSpec#symbolCharacters
        '''
        result = self._values.get("symbol_characters")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def symbols(self) -> typing.Optional[jsii.Number]:
        '''Symbols specifies the number of symbol characters in the generated password.

        If omitted it defaults to 25% of the length of the password

        :schema: ClusterGeneratorSpecGeneratorPasswordSpec#symbols
        '''
        result = self._values.get("symbols")
        return typing.cast(typing.Optional[jsii.Number], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorPasswordSpec(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorQuayAccessTokenSpec",
    jsii_struct_bases=[],
    name_mapping={
        "robot_account": "robotAccount",
        "service_account_ref": "serviceAccountRef",
        "url": "url",
    },
)
class ClusterGeneratorSpecGeneratorQuayAccessTokenSpec:
    def __init__(
        self,
        *,
        robot_account: builtins.str,
        service_account_ref: typing.Union["ClusterGeneratorSpecGeneratorQuayAccessTokenSpecServiceAccountRef", typing.Dict[builtins.str, typing.Any]],
        url: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param robot_account: Name of the robot account you are federating with.
        :param service_account_ref: Name of the service account you are federating with.
        :param url: URL configures the Quay instance URL. Defaults to quay.io. Default: quay.io.

        :schema: ClusterGeneratorSpecGeneratorQuayAccessTokenSpec
        '''
        if isinstance(service_account_ref, dict):
            service_account_ref = ClusterGeneratorSpecGeneratorQuayAccessTokenSpecServiceAccountRef(**service_account_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__b760f8c5fad1753090f4c7fdeb158c58f3a5285b02656fd11f8fd4e619c8135f)
            check_type(argname="argument robot_account", value=robot_account, expected_type=type_hints["robot_account"])
            check_type(argname="argument service_account_ref", value=service_account_ref, expected_type=type_hints["service_account_ref"])
            check_type(argname="argument url", value=url, expected_type=type_hints["url"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "robot_account": robot_account,
            "service_account_ref": service_account_ref,
        }
        if url is not None:
            self._values["url"] = url

    @builtins.property
    def robot_account(self) -> builtins.str:
        '''Name of the robot account you are federating with.

        :schema: ClusterGeneratorSpecGeneratorQuayAccessTokenSpec#robotAccount
        '''
        result = self._values.get("robot_account")
        assert result is not None, "Required property 'robot_account' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def service_account_ref(
        self,
    ) -> "ClusterGeneratorSpecGeneratorQuayAccessTokenSpecServiceAccountRef":
        '''Name of the service account you are federating with.

        :schema: ClusterGeneratorSpecGeneratorQuayAccessTokenSpec#serviceAccountRef
        '''
        result = self._values.get("service_account_ref")
        assert result is not None, "Required property 'service_account_ref' is missing"
        return typing.cast("ClusterGeneratorSpecGeneratorQuayAccessTokenSpecServiceAccountRef", result)

    @builtins.property
    def url(self) -> typing.Optional[builtins.str]:
        '''URL configures the Quay instance URL.

        Defaults to quay.io.

        :default: quay.io.

        :schema: ClusterGeneratorSpecGeneratorQuayAccessTokenSpec#url
        '''
        result = self._values.get("url")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorQuayAccessTokenSpec(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorQuayAccessTokenSpecServiceAccountRef",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "audiences": "audiences", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorQuayAccessTokenSpecServiceAccountRef:
    def __init__(
        self,
        *,
        name: builtins.str,
        audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Name of the service account you are federating with.

        :param name: The name of the ServiceAccount resource being referred to.
        :param audiences: Audience specifies the ``aud`` claim for the service account token If the service account uses a well-known annotation for e.g. IRSA or GCP Workload Identity then this audiences will be appended to the list.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorQuayAccessTokenSpecServiceAccountRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__b680ae1b78ef0032f149e40bb4a19c7a0b03d8afb67edc0edde80e855f7132ee)
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument audiences", value=audiences, expected_type=type_hints["audiences"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "name": name,
        }
        if audiences is not None:
            self._values["audiences"] = audiences
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the ServiceAccount resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorQuayAccessTokenSpecServiceAccountRef#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def audiences(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Audience specifies the ``aud`` claim for the service account token If the service account uses a well-known annotation for e.g. IRSA or GCP Workload Identity then this audiences will be appended to the list.

        :schema: ClusterGeneratorSpecGeneratorQuayAccessTokenSpecServiceAccountRef#audiences
        '''
        result = self._values.get("audiences")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorQuayAccessTokenSpecServiceAccountRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorQuayAccessTokenSpecServiceAccountRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorStsSessionTokenSpec",
    jsii_struct_bases=[],
    name_mapping={
        "region": "region",
        "auth": "auth",
        "request_parameters": "requestParameters",
        "role": "role",
    },
)
class ClusterGeneratorSpecGeneratorStsSessionTokenSpec:
    def __init__(
        self,
        *,
        region: builtins.str,
        auth: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuth", typing.Dict[builtins.str, typing.Any]]] = None,
        request_parameters: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorStsSessionTokenSpecRequestParameters", typing.Dict[builtins.str, typing.Any]]] = None,
        role: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param region: Region specifies the region to operate in.
        :param auth: Auth defines how to authenticate with AWS.
        :param request_parameters: RequestParameters contains parameters that can be passed to the STS service.
        :param role: You can assume a role before making calls to the desired AWS service.

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpec
        '''
        if isinstance(auth, dict):
            auth = ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuth(**auth)
        if isinstance(request_parameters, dict):
            request_parameters = ClusterGeneratorSpecGeneratorStsSessionTokenSpecRequestParameters(**request_parameters)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__7b156d2563dfcafd7828f40e867dc8dbb62b46dfa7870adff7e1ac851c3b64a1)
            check_type(argname="argument region", value=region, expected_type=type_hints["region"])
            check_type(argname="argument auth", value=auth, expected_type=type_hints["auth"])
            check_type(argname="argument request_parameters", value=request_parameters, expected_type=type_hints["request_parameters"])
            check_type(argname="argument role", value=role, expected_type=type_hints["role"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "region": region,
        }
        if auth is not None:
            self._values["auth"] = auth
        if request_parameters is not None:
            self._values["request_parameters"] = request_parameters
        if role is not None:
            self._values["role"] = role

    @builtins.property
    def region(self) -> builtins.str:
        '''Region specifies the region to operate in.

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpec#region
        '''
        result = self._values.get("region")
        assert result is not None, "Required property 'region' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def auth(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuth"]:
        '''Auth defines how to authenticate with AWS.

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpec#auth
        '''
        result = self._values.get("auth")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuth"], result)

    @builtins.property
    def request_parameters(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorStsSessionTokenSpecRequestParameters"]:
        '''RequestParameters contains parameters that can be passed to the STS service.

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpec#requestParameters
        '''
        result = self._values.get("request_parameters")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorStsSessionTokenSpecRequestParameters"], result)

    @builtins.property
    def role(self) -> typing.Optional[builtins.str]:
        '''You can assume a role before making calls to the desired AWS service.

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpec#role
        '''
        result = self._values.get("role")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorStsSessionTokenSpec(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuth",
    jsii_struct_bases=[],
    name_mapping={"jwt": "jwt", "secret_ref": "secretRef"},
)
class ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuth:
    def __init__(
        self,
        *,
        jwt: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthJwt", typing.Dict[builtins.str, typing.Any]]] = None,
        secret_ref: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Auth defines how to authenticate with AWS.

        :param jwt: Authenticate against AWS using service account tokens.
        :param secret_ref: AWSAuthSecretRef holds secret references for AWS credentials both AccessKeyID and SecretAccessKey must be defined in order to properly authenticate.

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuth
        '''
        if isinstance(jwt, dict):
            jwt = ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthJwt(**jwt)
        if isinstance(secret_ref, dict):
            secret_ref = ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRef(**secret_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__500c178b87b78973cb00ae5c3d241645a7a490f3fe1a6e4706a7f938aac2027f)
            check_type(argname="argument jwt", value=jwt, expected_type=type_hints["jwt"])
            check_type(argname="argument secret_ref", value=secret_ref, expected_type=type_hints["secret_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if jwt is not None:
            self._values["jwt"] = jwt
        if secret_ref is not None:
            self._values["secret_ref"] = secret_ref

    @builtins.property
    def jwt(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthJwt"]:
        '''Authenticate against AWS using service account tokens.

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuth#jwt
        '''
        result = self._values.get("jwt")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthJwt"], result)

    @builtins.property
    def secret_ref(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRef"]:
        '''AWSAuthSecretRef holds secret references for AWS credentials both AccessKeyID and SecretAccessKey must be defined in order to properly authenticate.

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuth#secretRef
        '''
        result = self._values.get("secret_ref")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuth(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthJwt",
    jsii_struct_bases=[],
    name_mapping={"service_account_ref": "serviceAccountRef"},
)
class ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthJwt:
    def __init__(
        self,
        *,
        service_account_ref: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthJwtServiceAccountRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Authenticate against AWS using service account tokens.

        :param service_account_ref: A reference to a ServiceAccount resource.

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthJwt
        '''
        if isinstance(service_account_ref, dict):
            service_account_ref = ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthJwtServiceAccountRef(**service_account_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__98ee3f0efdabb7496c0d2194a3493544bf0466015126da23cfb9febac799df65)
            check_type(argname="argument service_account_ref", value=service_account_ref, expected_type=type_hints["service_account_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if service_account_ref is not None:
            self._values["service_account_ref"] = service_account_ref

    @builtins.property
    def service_account_ref(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthJwtServiceAccountRef"]:
        '''A reference to a ServiceAccount resource.

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthJwt#serviceAccountRef
        '''
        result = self._values.get("service_account_ref")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthJwtServiceAccountRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthJwt(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthJwtServiceAccountRef",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "audiences": "audiences", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthJwtServiceAccountRef:
    def __init__(
        self,
        *,
        name: builtins.str,
        audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''A reference to a ServiceAccount resource.

        :param name: The name of the ServiceAccount resource being referred to.
        :param audiences: Audience specifies the ``aud`` claim for the service account token If the service account uses a well-known annotation for e.g. IRSA or GCP Workload Identity then this audiences will be appended to the list.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthJwtServiceAccountRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__c2b7233aba1192fb4d482fa99d660bc1f1ba06a2aee2f70888ee3b93ba93edfe)
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument audiences", value=audiences, expected_type=type_hints["audiences"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "name": name,
        }
        if audiences is not None:
            self._values["audiences"] = audiences
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the ServiceAccount resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthJwtServiceAccountRef#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def audiences(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Audience specifies the ``aud`` claim for the service account token If the service account uses a well-known annotation for e.g. IRSA or GCP Workload Identity then this audiences will be appended to the list.

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthJwtServiceAccountRef#audiences
        '''
        result = self._values.get("audiences")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthJwtServiceAccountRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthJwtServiceAccountRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRef",
    jsii_struct_bases=[],
    name_mapping={
        "access_key_id_secret_ref": "accessKeyIdSecretRef",
        "secret_access_key_secret_ref": "secretAccessKeySecretRef",
        "session_token_secret_ref": "sessionTokenSecretRef",
    },
)
class ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRef:
    def __init__(
        self,
        *,
        access_key_id_secret_ref: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefAccessKeyIdSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
        secret_access_key_secret_ref: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefSecretAccessKeySecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
        session_token_secret_ref: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefSessionTokenSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''AWSAuthSecretRef holds secret references for AWS credentials both AccessKeyID and SecretAccessKey must be defined in order to properly authenticate.

        :param access_key_id_secret_ref: The AccessKeyID is used for authentication.
        :param secret_access_key_secret_ref: The SecretAccessKey is used for authentication.
        :param session_token_secret_ref: The SessionToken used for authentication This must be defined if AccessKeyID and SecretAccessKey are temporary credentials see: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html.

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRef
        '''
        if isinstance(access_key_id_secret_ref, dict):
            access_key_id_secret_ref = ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefAccessKeyIdSecretRef(**access_key_id_secret_ref)
        if isinstance(secret_access_key_secret_ref, dict):
            secret_access_key_secret_ref = ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefSecretAccessKeySecretRef(**secret_access_key_secret_ref)
        if isinstance(session_token_secret_ref, dict):
            session_token_secret_ref = ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefSessionTokenSecretRef(**session_token_secret_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__06818579d44e8d646ecdca0be2f54e320b0be3df9f6b0e5edaacc29106f66f6c)
            check_type(argname="argument access_key_id_secret_ref", value=access_key_id_secret_ref, expected_type=type_hints["access_key_id_secret_ref"])
            check_type(argname="argument secret_access_key_secret_ref", value=secret_access_key_secret_ref, expected_type=type_hints["secret_access_key_secret_ref"])
            check_type(argname="argument session_token_secret_ref", value=session_token_secret_ref, expected_type=type_hints["session_token_secret_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if access_key_id_secret_ref is not None:
            self._values["access_key_id_secret_ref"] = access_key_id_secret_ref
        if secret_access_key_secret_ref is not None:
            self._values["secret_access_key_secret_ref"] = secret_access_key_secret_ref
        if session_token_secret_ref is not None:
            self._values["session_token_secret_ref"] = session_token_secret_ref

    @builtins.property
    def access_key_id_secret_ref(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefAccessKeyIdSecretRef"]:
        '''The AccessKeyID is used for authentication.

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRef#accessKeyIDSecretRef
        '''
        result = self._values.get("access_key_id_secret_ref")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefAccessKeyIdSecretRef"], result)

    @builtins.property
    def secret_access_key_secret_ref(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefSecretAccessKeySecretRef"]:
        '''The SecretAccessKey is used for authentication.

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRef#secretAccessKeySecretRef
        '''
        result = self._values.get("secret_access_key_secret_ref")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefSecretAccessKeySecretRef"], result)

    @builtins.property
    def session_token_secret_ref(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefSessionTokenSecretRef"]:
        '''The SessionToken used for authentication This must be defined if AccessKeyID and SecretAccessKey are temporary credentials see: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html.

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRef#sessionTokenSecretRef
        '''
        result = self._values.get("session_token_secret_ref")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefSessionTokenSecretRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefAccessKeyIdSecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefAccessKeyIdSecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''The AccessKeyID is used for authentication.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefAccessKeyIdSecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__e5f427fb43d20a03744b87747aa16efdc936bdbf5b1ba330f266c27af19e6eb2)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefAccessKeyIdSecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefAccessKeyIdSecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefAccessKeyIdSecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefAccessKeyIdSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefSecretAccessKeySecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefSecretAccessKeySecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''The SecretAccessKey is used for authentication.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefSecretAccessKeySecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__5cf2daf36a0f3998c035450336e8d6275fb5e89e069a644559eddc2c1972f887)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefSecretAccessKeySecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefSecretAccessKeySecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefSecretAccessKeySecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefSecretAccessKeySecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefSessionTokenSecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefSessionTokenSecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''The SessionToken used for authentication This must be defined if AccessKeyID and SecretAccessKey are temporary credentials see: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefSessionTokenSecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__bba4b7c291a21145c9cbb073dd1e7f376419e55e1589bd1f3197fe98d06adfb2)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefSessionTokenSecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefSessionTokenSecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefSessionTokenSecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefSessionTokenSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorStsSessionTokenSpecRequestParameters",
    jsii_struct_bases=[],
    name_mapping={
        "serial_number": "serialNumber",
        "session_duration": "sessionDuration",
        "token_code": "tokenCode",
    },
)
class ClusterGeneratorSpecGeneratorStsSessionTokenSpecRequestParameters:
    def __init__(
        self,
        *,
        serial_number: typing.Optional[builtins.str] = None,
        session_duration: typing.Optional[jsii.Number] = None,
        token_code: typing.Optional[builtins.str] = None,
    ) -> None:
        '''RequestParameters contains parameters that can be passed to the STS service.

        :param serial_number: SerialNumber is the identification number of the MFA device that is associated with the IAM user who is making the GetSessionToken call. Possible values: hardware device (such as GAHT12345678) or an Amazon Resource Name (ARN) for a virtual device (such as arn:aws:iam::123456789012:mfa/user)
        :param session_duration: SessionDuration The duration, in seconds, that the credentials should remain valid. Acceptable durations for IAM user sessions range from 900 seconds (15 minutes) to 129,600 seconds (36 hours), with 43,200 seconds (12 hours) as the default.
        :param token_code: TokenCode is the value provided by the MFA device, if MFA is required.

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpecRequestParameters
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__ca0a298660bade99205cdcd1774aa724a0b72dd6d95821e051f8510cba60ffa5)
            check_type(argname="argument serial_number", value=serial_number, expected_type=type_hints["serial_number"])
            check_type(argname="argument session_duration", value=session_duration, expected_type=type_hints["session_duration"])
            check_type(argname="argument token_code", value=token_code, expected_type=type_hints["token_code"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if serial_number is not None:
            self._values["serial_number"] = serial_number
        if session_duration is not None:
            self._values["session_duration"] = session_duration
        if token_code is not None:
            self._values["token_code"] = token_code

    @builtins.property
    def serial_number(self) -> typing.Optional[builtins.str]:
        '''SerialNumber is the identification number of the MFA device that is associated with the IAM user who is making the GetSessionToken call.

        Possible values: hardware device (such as GAHT12345678) or an Amazon Resource Name (ARN) for a virtual device
        (such as arn:aws:iam::123456789012:mfa/user)

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpecRequestParameters#serialNumber
        '''
        result = self._values.get("serial_number")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def session_duration(self) -> typing.Optional[jsii.Number]:
        '''SessionDuration The duration, in seconds, that the credentials should remain valid.

        Acceptable durations for
        IAM user sessions range from 900 seconds (15 minutes) to 129,600 seconds (36 hours), with 43,200 seconds
        (12 hours) as the default.

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpecRequestParameters#sessionDuration
        '''
        result = self._values.get("session_duration")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def token_code(self) -> typing.Optional[builtins.str]:
        '''TokenCode is the value provided by the MFA device, if MFA is required.

        :schema: ClusterGeneratorSpecGeneratorStsSessionTokenSpecRequestParameters#tokenCode
        '''
        result = self._values.get("token_code")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorStsSessionTokenSpecRequestParameters(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpec",
    jsii_struct_bases=[],
    name_mapping={
        "path": "path",
        "provider": "provider",
        "allow_empty_response": "allowEmptyResponse",
        "controller": "controller",
        "method": "method",
        "parameters": "parameters",
        "result_type": "resultType",
        "retry_settings": "retrySettings",
    },
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpec:
    def __init__(
        self,
        *,
        path: builtins.str,
        provider: typing.Union["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProvider", typing.Dict[builtins.str, typing.Any]],
        allow_empty_response: typing.Optional[builtins.bool] = None,
        controller: typing.Optional[builtins.str] = None,
        method: typing.Optional[builtins.str] = None,
        parameters: typing.Any = None,
        result_type: typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecResultType"] = None,
        retry_settings: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecRetrySettings", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''
        :param path: Vault path to obtain the dynamic secret from.
        :param provider: Vault provider common spec.
        :param allow_empty_response: Do not fail if no secrets are found. Useful for requests where no data is expected.
        :param controller: Used to select the correct ESO controller (think: ingress.ingressClassName) The ESO controller is instantiated with a specific controller name and filters VDS based on this property.
        :param method: Vault API method to use (GET/POST/other).
        :param parameters: Parameters to pass to Vault write (for non-GET methods).
        :param result_type: Result type defines which data is returned from the generator. By default it is the "data" section of the Vault API response. When using e.g. /auth/token/create the "data" section is empty but the "auth" section contains the generated token. Please refer to the vault docs regarding the result data structure. Additionally, accessing the raw response is possibly by using "Raw" result type.
        :param retry_settings: Used to configure http retries if failed.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpec
        '''
        if isinstance(provider, dict):
            provider = ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProvider(**provider)
        if isinstance(retry_settings, dict):
            retry_settings = ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecRetrySettings(**retry_settings)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__10e2321e1cd5730bc9b0e182284aef50907db67d44c1acfada3f65f196f1582c)
            check_type(argname="argument path", value=path, expected_type=type_hints["path"])
            check_type(argname="argument provider", value=provider, expected_type=type_hints["provider"])
            check_type(argname="argument allow_empty_response", value=allow_empty_response, expected_type=type_hints["allow_empty_response"])
            check_type(argname="argument controller", value=controller, expected_type=type_hints["controller"])
            check_type(argname="argument method", value=method, expected_type=type_hints["method"])
            check_type(argname="argument parameters", value=parameters, expected_type=type_hints["parameters"])
            check_type(argname="argument result_type", value=result_type, expected_type=type_hints["result_type"])
            check_type(argname="argument retry_settings", value=retry_settings, expected_type=type_hints["retry_settings"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "path": path,
            "provider": provider,
        }
        if allow_empty_response is not None:
            self._values["allow_empty_response"] = allow_empty_response
        if controller is not None:
            self._values["controller"] = controller
        if method is not None:
            self._values["method"] = method
        if parameters is not None:
            self._values["parameters"] = parameters
        if result_type is not None:
            self._values["result_type"] = result_type
        if retry_settings is not None:
            self._values["retry_settings"] = retry_settings

    @builtins.property
    def path(self) -> builtins.str:
        '''Vault path to obtain the dynamic secret from.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpec#path
        '''
        result = self._values.get("path")
        assert result is not None, "Required property 'path' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def provider(self) -> "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProvider":
        '''Vault provider common spec.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpec#provider
        '''
        result = self._values.get("provider")
        assert result is not None, "Required property 'provider' is missing"
        return typing.cast("ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProvider", result)

    @builtins.property
    def allow_empty_response(self) -> typing.Optional[builtins.bool]:
        '''Do not fail if no secrets are found.

        Useful for requests where no data is expected.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpec#allowEmptyResponse
        '''
        result = self._values.get("allow_empty_response")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def controller(self) -> typing.Optional[builtins.str]:
        '''Used to select the correct ESO controller (think: ingress.ingressClassName) The ESO controller is instantiated with a specific controller name and filters VDS based on this property.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpec#controller
        '''
        result = self._values.get("controller")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def method(self) -> typing.Optional[builtins.str]:
        '''Vault API method to use (GET/POST/other).

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpec#method
        '''
        result = self._values.get("method")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def parameters(self) -> typing.Any:
        '''Parameters to pass to Vault write (for non-GET methods).

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpec#parameters
        '''
        result = self._values.get("parameters")
        return typing.cast(typing.Any, result)

    @builtins.property
    def result_type(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecResultType"]:
        '''Result type defines which data is returned from the generator.

        By default it is the "data" section of the Vault API response.
        When using e.g. /auth/token/create the "data" section is empty but
        the "auth" section contains the generated token.
        Please refer to the vault docs regarding the result data structure.
        Additionally, accessing the raw response is possibly by using "Raw" result type.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpec#resultType
        '''
        result = self._values.get("result_type")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecResultType"], result)

    @builtins.property
    def retry_settings(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecRetrySettings"]:
        '''Used to configure http retries if failed.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpec#retrySettings
        '''
        result = self._values.get("retry_settings")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecRetrySettings"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpec(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProvider",
    jsii_struct_bases=[],
    name_mapping={
        "server": "server",
        "auth": "auth",
        "ca_bundle": "caBundle",
        "ca_provider": "caProvider",
        "forward_inconsistent": "forwardInconsistent",
        "headers": "headers",
        "namespace": "namespace",
        "path": "path",
        "read_your_writes": "readYourWrites",
        "tls": "tls",
        "version": "version",
    },
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProvider:
    def __init__(
        self,
        *,
        server: builtins.str,
        auth: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuth", typing.Dict[builtins.str, typing.Any]]] = None,
        ca_bundle: typing.Optional[builtins.str] = None,
        ca_provider: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderCaProvider", typing.Dict[builtins.str, typing.Any]]] = None,
        forward_inconsistent: typing.Optional[builtins.bool] = None,
        headers: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        namespace: typing.Optional[builtins.str] = None,
        path: typing.Optional[builtins.str] = None,
        read_your_writes: typing.Optional[builtins.bool] = None,
        tls: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTls", typing.Dict[builtins.str, typing.Any]]] = None,
        version: typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderVersion"] = None,
    ) -> None:
        '''Vault provider common spec.

        :param server: Server is the connection address for the Vault server, e.g: "https://vault.example.com:8200".
        :param auth: Auth configures how secret-manager authenticates with the Vault server.
        :param ca_bundle: PEM encoded CA bundle used to validate Vault server certificate. Only used if the Server URL is using HTTPS protocol. This parameter is ignored for plain HTTP protocol connection. If not set the system root certificates are used to validate the TLS connection.
        :param ca_provider: The provider for the CA bundle to use to validate Vault server certificate.
        :param forward_inconsistent: ForwardInconsistent tells Vault to forward read-after-write requests to the Vault leader instead of simply retrying within a loop. This can increase performance if the option is enabled serverside. https://www.vaultproject.io/docs/configuration/replication#allow_forwarding_via_header
        :param headers: Headers to be added in Vault request.
        :param namespace: Name of the vault namespace. Namespaces is a set of features within Vault Enterprise that allows Vault environments to support Secure Multi-tenancy. e.g: "ns1". More about namespaces can be found here https://www.vaultproject.io/docs/enterprise/namespaces
        :param path: Path is the mount path of the Vault KV backend endpoint, e.g: "secret". The v2 KV secret engine version specific "/data" path suffix for fetching secrets from Vault is optional and will be appended if not present in specified path.
        :param read_your_writes: ReadYourWrites ensures isolated read-after-write semantics by providing discovered cluster replication states in each request. More information about eventual consistency in Vault can be found here https://www.vaultproject.io/docs/enterprise/consistency
        :param tls: The configuration used for client side related TLS communication, when the Vault server requires mutual authentication. Only used if the Server URL is using HTTPS protocol. This parameter is ignored for plain HTTP protocol connection. It's worth noting this configuration is different from the "TLS certificates auth method", which is available under the ``auth.cert`` section.
        :param version: Version is the Vault KV secret engine version. This can be either "v1" or "v2". Version defaults to "v2".

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProvider
        '''
        if isinstance(auth, dict):
            auth = ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuth(**auth)
        if isinstance(ca_provider, dict):
            ca_provider = ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderCaProvider(**ca_provider)
        if isinstance(tls, dict):
            tls = ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTls(**tls)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__02abd566c822847d8f25656374f5c631e294093b6020fa8ec60a874e692efe08)
            check_type(argname="argument server", value=server, expected_type=type_hints["server"])
            check_type(argname="argument auth", value=auth, expected_type=type_hints["auth"])
            check_type(argname="argument ca_bundle", value=ca_bundle, expected_type=type_hints["ca_bundle"])
            check_type(argname="argument ca_provider", value=ca_provider, expected_type=type_hints["ca_provider"])
            check_type(argname="argument forward_inconsistent", value=forward_inconsistent, expected_type=type_hints["forward_inconsistent"])
            check_type(argname="argument headers", value=headers, expected_type=type_hints["headers"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
            check_type(argname="argument path", value=path, expected_type=type_hints["path"])
            check_type(argname="argument read_your_writes", value=read_your_writes, expected_type=type_hints["read_your_writes"])
            check_type(argname="argument tls", value=tls, expected_type=type_hints["tls"])
            check_type(argname="argument version", value=version, expected_type=type_hints["version"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "server": server,
        }
        if auth is not None:
            self._values["auth"] = auth
        if ca_bundle is not None:
            self._values["ca_bundle"] = ca_bundle
        if ca_provider is not None:
            self._values["ca_provider"] = ca_provider
        if forward_inconsistent is not None:
            self._values["forward_inconsistent"] = forward_inconsistent
        if headers is not None:
            self._values["headers"] = headers
        if namespace is not None:
            self._values["namespace"] = namespace
        if path is not None:
            self._values["path"] = path
        if read_your_writes is not None:
            self._values["read_your_writes"] = read_your_writes
        if tls is not None:
            self._values["tls"] = tls
        if version is not None:
            self._values["version"] = version

    @builtins.property
    def server(self) -> builtins.str:
        '''Server is the connection address for the Vault server, e.g: "https://vault.example.com:8200".

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProvider#server
        '''
        result = self._values.get("server")
        assert result is not None, "Required property 'server' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def auth(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuth"]:
        '''Auth configures how secret-manager authenticates with the Vault server.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProvider#auth
        '''
        result = self._values.get("auth")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuth"], result)

    @builtins.property
    def ca_bundle(self) -> typing.Optional[builtins.str]:
        '''PEM encoded CA bundle used to validate Vault server certificate.

        Only used
        if the Server URL is using HTTPS protocol. This parameter is ignored for
        plain HTTP protocol connection. If not set the system root certificates
        are used to validate the TLS connection.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProvider#caBundle
        '''
        result = self._values.get("ca_bundle")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ca_provider(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderCaProvider"]:
        '''The provider for the CA bundle to use to validate Vault server certificate.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProvider#caProvider
        '''
        result = self._values.get("ca_provider")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderCaProvider"], result)

    @builtins.property
    def forward_inconsistent(self) -> typing.Optional[builtins.bool]:
        '''ForwardInconsistent tells Vault to forward read-after-write requests to the Vault leader instead of simply retrying within a loop.

        This can increase performance if
        the option is enabled serverside.
        https://www.vaultproject.io/docs/configuration/replication#allow_forwarding_via_header

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProvider#forwardInconsistent
        '''
        result = self._values.get("forward_inconsistent")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def headers(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Headers to be added in Vault request.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProvider#headers
        '''
        result = self._values.get("headers")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''Name of the vault namespace.

        Namespaces is a set of features within Vault Enterprise that allows
        Vault environments to support Secure Multi-tenancy. e.g: "ns1".
        More about namespaces can be found here https://www.vaultproject.io/docs/enterprise/namespaces

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProvider#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def path(self) -> typing.Optional[builtins.str]:
        '''Path is the mount path of the Vault KV backend endpoint, e.g: "secret". The v2 KV secret engine version specific "/data" path suffix for fetching secrets from Vault is optional and will be appended if not present in specified path.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProvider#path
        '''
        result = self._values.get("path")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def read_your_writes(self) -> typing.Optional[builtins.bool]:
        '''ReadYourWrites ensures isolated read-after-write semantics by providing discovered cluster replication states in each request.

        More information about eventual consistency in Vault can be found here
        https://www.vaultproject.io/docs/enterprise/consistency

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProvider#readYourWrites
        '''
        result = self._values.get("read_your_writes")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def tls(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTls"]:
        '''The configuration used for client side related TLS communication, when the Vault server requires mutual authentication.

        Only used if the Server URL is using HTTPS protocol.
        This parameter is ignored for plain HTTP protocol connection.
        It's worth noting this configuration is different from the "TLS certificates auth method",
        which is available under the ``auth.cert`` section.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProvider#tls
        '''
        result = self._values.get("tls")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTls"], result)

    @builtins.property
    def version(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderVersion"]:
        '''Version is the Vault KV secret engine version.

        This can be either "v1" or
        "v2". Version defaults to "v2".

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProvider#version
        '''
        result = self._values.get("version")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderVersion"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProvider(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuth",
    jsii_struct_bases=[],
    name_mapping={
        "app_role": "appRole",
        "cert": "cert",
        "iam": "iam",
        "jwt": "jwt",
        "kubernetes": "kubernetes",
        "ldap": "ldap",
        "namespace": "namespace",
        "token_secret_ref": "tokenSecretRef",
        "user_pass": "userPass",
    },
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuth:
    def __init__(
        self,
        *,
        app_role: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRole", typing.Dict[builtins.str, typing.Any]]] = None,
        cert: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCert", typing.Dict[builtins.str, typing.Any]]] = None,
        iam: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIam", typing.Dict[builtins.str, typing.Any]]] = None,
        jwt: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwt", typing.Dict[builtins.str, typing.Any]]] = None,
        kubernetes: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetes", typing.Dict[builtins.str, typing.Any]]] = None,
        ldap: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthLdap", typing.Dict[builtins.str, typing.Any]]] = None,
        namespace: typing.Optional[builtins.str] = None,
        token_secret_ref: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthTokenSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
        user_pass: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthUserPass", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Auth configures how secret-manager authenticates with the Vault server.

        :param app_role: AppRole authenticates with Vault using the App Role auth mechanism, with the role and secret stored in a Kubernetes Secret resource.
        :param cert: Cert authenticates with TLS Certificates by passing client certificate, private key and ca certificate Cert authentication method.
        :param iam: Iam authenticates with vault by passing a special AWS request signed with AWS IAM credentials AWS IAM authentication method.
        :param jwt: Jwt authenticates with Vault by passing role and JWT token using the JWT/OIDC authentication method.
        :param kubernetes: Kubernetes authenticates with Vault by passing the ServiceAccount token stored in the named Secret resource to the Vault server.
        :param ldap: Ldap authenticates with Vault by passing username/password pair using the LDAP authentication method.
        :param namespace: Name of the vault namespace to authenticate to. This can be different than the namespace your secret is in. Namespaces is a set of features within Vault Enterprise that allows Vault environments to support Secure Multi-tenancy. e.g: "ns1". More about namespaces can be found here https://www.vaultproject.io/docs/enterprise/namespaces This will default to Vault.Namespace field if set, or empty otherwise
        :param token_secret_ref: TokenSecretRef authenticates with Vault by presenting a token.
        :param user_pass: UserPass authenticates with Vault by passing username/password pair.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuth
        '''
        if isinstance(app_role, dict):
            app_role = ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRole(**app_role)
        if isinstance(cert, dict):
            cert = ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCert(**cert)
        if isinstance(iam, dict):
            iam = ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIam(**iam)
        if isinstance(jwt, dict):
            jwt = ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwt(**jwt)
        if isinstance(kubernetes, dict):
            kubernetes = ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetes(**kubernetes)
        if isinstance(ldap, dict):
            ldap = ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthLdap(**ldap)
        if isinstance(token_secret_ref, dict):
            token_secret_ref = ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthTokenSecretRef(**token_secret_ref)
        if isinstance(user_pass, dict):
            user_pass = ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthUserPass(**user_pass)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__6b46ee2f06aed6663e7fe9a51398de8f44b17d4c003a7d923ba902471c122d6c)
            check_type(argname="argument app_role", value=app_role, expected_type=type_hints["app_role"])
            check_type(argname="argument cert", value=cert, expected_type=type_hints["cert"])
            check_type(argname="argument iam", value=iam, expected_type=type_hints["iam"])
            check_type(argname="argument jwt", value=jwt, expected_type=type_hints["jwt"])
            check_type(argname="argument kubernetes", value=kubernetes, expected_type=type_hints["kubernetes"])
            check_type(argname="argument ldap", value=ldap, expected_type=type_hints["ldap"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
            check_type(argname="argument token_secret_ref", value=token_secret_ref, expected_type=type_hints["token_secret_ref"])
            check_type(argname="argument user_pass", value=user_pass, expected_type=type_hints["user_pass"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if app_role is not None:
            self._values["app_role"] = app_role
        if cert is not None:
            self._values["cert"] = cert
        if iam is not None:
            self._values["iam"] = iam
        if jwt is not None:
            self._values["jwt"] = jwt
        if kubernetes is not None:
            self._values["kubernetes"] = kubernetes
        if ldap is not None:
            self._values["ldap"] = ldap
        if namespace is not None:
            self._values["namespace"] = namespace
        if token_secret_ref is not None:
            self._values["token_secret_ref"] = token_secret_ref
        if user_pass is not None:
            self._values["user_pass"] = user_pass

    @builtins.property
    def app_role(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRole"]:
        '''AppRole authenticates with Vault using the App Role auth mechanism, with the role and secret stored in a Kubernetes Secret resource.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuth#appRole
        '''
        result = self._values.get("app_role")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRole"], result)

    @builtins.property
    def cert(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCert"]:
        '''Cert authenticates with TLS Certificates by passing client certificate, private key and ca certificate Cert authentication method.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuth#cert
        '''
        result = self._values.get("cert")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCert"], result)

    @builtins.property
    def iam(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIam"]:
        '''Iam authenticates with vault by passing a special AWS request signed with AWS IAM credentials AWS IAM authentication method.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuth#iam
        '''
        result = self._values.get("iam")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIam"], result)

    @builtins.property
    def jwt(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwt"]:
        '''Jwt authenticates with Vault by passing role and JWT token using the JWT/OIDC authentication method.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuth#jwt
        '''
        result = self._values.get("jwt")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwt"], result)

    @builtins.property
    def kubernetes(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetes"]:
        '''Kubernetes authenticates with Vault by passing the ServiceAccount token stored in the named Secret resource to the Vault server.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuth#kubernetes
        '''
        result = self._values.get("kubernetes")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetes"], result)

    @builtins.property
    def ldap(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthLdap"]:
        '''Ldap authenticates with Vault by passing username/password pair using the LDAP authentication method.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuth#ldap
        '''
        result = self._values.get("ldap")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthLdap"], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''Name of the vault namespace to authenticate to.

        This can be different than the namespace your secret is in.
        Namespaces is a set of features within Vault Enterprise that allows
        Vault environments to support Secure Multi-tenancy. e.g: "ns1".
        More about namespaces can be found here https://www.vaultproject.io/docs/enterprise/namespaces
        This will default to Vault.Namespace field if set, or empty otherwise

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuth#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def token_secret_ref(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthTokenSecretRef"]:
        '''TokenSecretRef authenticates with Vault by presenting a token.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuth#tokenSecretRef
        '''
        result = self._values.get("token_secret_ref")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthTokenSecretRef"], result)

    @builtins.property
    def user_pass(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthUserPass"]:
        '''UserPass authenticates with Vault by passing username/password pair.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuth#userPass
        '''
        result = self._values.get("user_pass")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthUserPass"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuth(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRole",
    jsii_struct_bases=[],
    name_mapping={
        "path": "path",
        "secret_ref": "secretRef",
        "role_id": "roleId",
        "role_ref": "roleRef",
    },
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRole:
    def __init__(
        self,
        *,
        path: builtins.str,
        secret_ref: typing.Union["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRoleSecretRef", typing.Dict[builtins.str, typing.Any]],
        role_id: typing.Optional[builtins.str] = None,
        role_ref: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRoleRoleRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''AppRole authenticates with Vault using the App Role auth mechanism, with the role and secret stored in a Kubernetes Secret resource.

        :param path: Path where the App Role authentication backend is mounted in Vault, e.g: "approle".
        :param secret_ref: Reference to a key in a Secret that contains the App Role secret used to authenticate with Vault. The ``key`` field must be specified and denotes which entry within the Secret resource is used as the app role secret.
        :param role_id: RoleID configured in the App Role authentication backend when setting up the authentication backend in Vault.
        :param role_ref: Reference to a key in a Secret that contains the App Role ID used to authenticate with Vault. The ``key`` field must be specified and denotes which entry within the Secret resource is used as the app role id.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRole
        '''
        if isinstance(secret_ref, dict):
            secret_ref = ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRoleSecretRef(**secret_ref)
        if isinstance(role_ref, dict):
            role_ref = ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRoleRoleRef(**role_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__b1b2ca1676dd1d58a898f4207b7372f83856a2dea3dca6925938016912fe01bc)
            check_type(argname="argument path", value=path, expected_type=type_hints["path"])
            check_type(argname="argument secret_ref", value=secret_ref, expected_type=type_hints["secret_ref"])
            check_type(argname="argument role_id", value=role_id, expected_type=type_hints["role_id"])
            check_type(argname="argument role_ref", value=role_ref, expected_type=type_hints["role_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "path": path,
            "secret_ref": secret_ref,
        }
        if role_id is not None:
            self._values["role_id"] = role_id
        if role_ref is not None:
            self._values["role_ref"] = role_ref

    @builtins.property
    def path(self) -> builtins.str:
        '''Path where the App Role authentication backend is mounted in Vault, e.g: "approle".

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRole#path
        '''
        result = self._values.get("path")
        assert result is not None, "Required property 'path' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def secret_ref(
        self,
    ) -> "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRoleSecretRef":
        '''Reference to a key in a Secret that contains the App Role secret used to authenticate with Vault.

        The ``key`` field must be specified and denotes which entry within the Secret
        resource is used as the app role secret.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRole#secretRef
        '''
        result = self._values.get("secret_ref")
        assert result is not None, "Required property 'secret_ref' is missing"
        return typing.cast("ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRoleSecretRef", result)

    @builtins.property
    def role_id(self) -> typing.Optional[builtins.str]:
        '''RoleID configured in the App Role authentication backend when setting up the authentication backend in Vault.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRole#roleId
        '''
        result = self._values.get("role_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def role_ref(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRoleRoleRef"]:
        '''Reference to a key in a Secret that contains the App Role ID used to authenticate with Vault.

        The ``key`` field must be specified and denotes which entry within the Secret
        resource is used as the app role id.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRole#roleRef
        '''
        result = self._values.get("role_ref")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRoleRoleRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRole(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRoleRoleRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRoleRoleRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Reference to a key in a Secret that contains the App Role ID used to authenticate with Vault.

        The ``key`` field must be specified and denotes which entry within the Secret
        resource is used as the app role id.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRoleRoleRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__eac36a6ae09b90df622a8885e385f95e01a2bb1c1025cb1eb6748db3b6260c7b)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRoleRoleRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRoleRoleRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRoleRoleRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRoleRoleRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRoleSecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRoleSecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Reference to a key in a Secret that contains the App Role secret used to authenticate with Vault.

        The ``key`` field must be specified and denotes which entry within the Secret
        resource is used as the app role secret.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRoleSecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__cf9b835649610475ffd96ef188f0154ea6898cb01beb95dfa906f18367047270)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRoleSecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRoleSecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRoleSecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRoleSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCert",
    jsii_struct_bases=[],
    name_mapping={"client_cert": "clientCert", "secret_ref": "secretRef"},
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCert:
    def __init__(
        self,
        *,
        client_cert: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCertClientCert", typing.Dict[builtins.str, typing.Any]]] = None,
        secret_ref: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCertSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Cert authenticates with TLS Certificates by passing client certificate, private key and ca certificate Cert authentication method.

        :param client_cert: ClientCert is a certificate to authenticate using the Cert Vault authentication method.
        :param secret_ref: SecretRef to a key in a Secret resource containing client private key to authenticate with Vault using the Cert authentication method.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCert
        '''
        if isinstance(client_cert, dict):
            client_cert = ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCertClientCert(**client_cert)
        if isinstance(secret_ref, dict):
            secret_ref = ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCertSecretRef(**secret_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__6a48a6f2044f51d1f9bce54540f955f0f3c0e34ca0c5a81e258fb25258a1812d)
            check_type(argname="argument client_cert", value=client_cert, expected_type=type_hints["client_cert"])
            check_type(argname="argument secret_ref", value=secret_ref, expected_type=type_hints["secret_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if client_cert is not None:
            self._values["client_cert"] = client_cert
        if secret_ref is not None:
            self._values["secret_ref"] = secret_ref

    @builtins.property
    def client_cert(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCertClientCert"]:
        '''ClientCert is a certificate to authenticate using the Cert Vault authentication method.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCert#clientCert
        '''
        result = self._values.get("client_cert")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCertClientCert"], result)

    @builtins.property
    def secret_ref(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCertSecretRef"]:
        '''SecretRef to a key in a Secret resource containing client private key to authenticate with Vault using the Cert authentication method.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCert#secretRef
        '''
        result = self._values.get("secret_ref")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCertSecretRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCert(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCertClientCert",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCertClientCert:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''ClientCert is a certificate to authenticate using the Cert Vault authentication method.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCertClientCert
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__b61c2f8625d6b6eefba3b38478f3db3ca23f00985a1fbade641377af48f21430)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCertClientCert#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCertClientCert#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCertClientCert#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCertClientCert(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCertSecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCertSecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''SecretRef to a key in a Secret resource containing client private key to authenticate with Vault using the Cert authentication method.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCertSecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__4096b6822d9c79e1ab7826475c9b916df90eb40d1748c567b038c74e769d3520)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCertSecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCertSecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCertSecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCertSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIam",
    jsii_struct_bases=[],
    name_mapping={
        "vault_role": "vaultRole",
        "external_id": "externalId",
        "jwt": "jwt",
        "path": "path",
        "region": "region",
        "role": "role",
        "secret_ref": "secretRef",
        "vault_aws_iam_server_id": "vaultAwsIamServerId",
    },
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIam:
    def __init__(
        self,
        *,
        vault_role: builtins.str,
        external_id: typing.Optional[builtins.str] = None,
        jwt: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamJwt", typing.Dict[builtins.str, typing.Any]]] = None,
        path: typing.Optional[builtins.str] = None,
        region: typing.Optional[builtins.str] = None,
        role: typing.Optional[builtins.str] = None,
        secret_ref: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
        vault_aws_iam_server_id: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Iam authenticates with vault by passing a special AWS request signed with AWS IAM credentials AWS IAM authentication method.

        :param vault_role: Vault Role. In vault, a role describes an identity with a set of permissions, groups, or policies you want to attach a user of the secrets engine
        :param external_id: AWS External ID set on assumed IAM roles.
        :param jwt: Specify a service account with IRSA enabled.
        :param path: Path where the AWS auth method is enabled in Vault, e.g: "aws".
        :param region: AWS region.
        :param role: This is the AWS role to be assumed before talking to vault.
        :param secret_ref: Specify credentials in a Secret object.
        :param vault_aws_iam_server_id: X-Vault-AWS-IAM-Server-ID is an additional header used by Vault IAM auth method to mitigate against different types of replay attacks. More details here: https://developer.hashicorp.com/vault/docs/auth/aws

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIam
        '''
        if isinstance(jwt, dict):
            jwt = ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamJwt(**jwt)
        if isinstance(secret_ref, dict):
            secret_ref = ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRef(**secret_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__1ae76c20b2d3d164d46c1682c2dcbfe8293b4b1a1c429ba0d9ccd8de1623aefa)
            check_type(argname="argument vault_role", value=vault_role, expected_type=type_hints["vault_role"])
            check_type(argname="argument external_id", value=external_id, expected_type=type_hints["external_id"])
            check_type(argname="argument jwt", value=jwt, expected_type=type_hints["jwt"])
            check_type(argname="argument path", value=path, expected_type=type_hints["path"])
            check_type(argname="argument region", value=region, expected_type=type_hints["region"])
            check_type(argname="argument role", value=role, expected_type=type_hints["role"])
            check_type(argname="argument secret_ref", value=secret_ref, expected_type=type_hints["secret_ref"])
            check_type(argname="argument vault_aws_iam_server_id", value=vault_aws_iam_server_id, expected_type=type_hints["vault_aws_iam_server_id"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "vault_role": vault_role,
        }
        if external_id is not None:
            self._values["external_id"] = external_id
        if jwt is not None:
            self._values["jwt"] = jwt
        if path is not None:
            self._values["path"] = path
        if region is not None:
            self._values["region"] = region
        if role is not None:
            self._values["role"] = role
        if secret_ref is not None:
            self._values["secret_ref"] = secret_ref
        if vault_aws_iam_server_id is not None:
            self._values["vault_aws_iam_server_id"] = vault_aws_iam_server_id

    @builtins.property
    def vault_role(self) -> builtins.str:
        '''Vault Role.

        In vault, a role describes an identity with a set of permissions, groups, or policies you want to attach a user of the secrets engine

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIam#vaultRole
        '''
        result = self._values.get("vault_role")
        assert result is not None, "Required property 'vault_role' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def external_id(self) -> typing.Optional[builtins.str]:
        '''AWS External ID set on assumed IAM roles.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIam#externalID
        '''
        result = self._values.get("external_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def jwt(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamJwt"]:
        '''Specify a service account with IRSA enabled.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIam#jwt
        '''
        result = self._values.get("jwt")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamJwt"], result)

    @builtins.property
    def path(self) -> typing.Optional[builtins.str]:
        '''Path where the AWS auth method is enabled in Vault, e.g: "aws".

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIam#path
        '''
        result = self._values.get("path")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def region(self) -> typing.Optional[builtins.str]:
        '''AWS region.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIam#region
        '''
        result = self._values.get("region")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def role(self) -> typing.Optional[builtins.str]:
        '''This is the AWS role to be assumed before talking to vault.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIam#role
        '''
        result = self._values.get("role")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def secret_ref(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRef"]:
        '''Specify credentials in a Secret object.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIam#secretRef
        '''
        result = self._values.get("secret_ref")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRef"], result)

    @builtins.property
    def vault_aws_iam_server_id(self) -> typing.Optional[builtins.str]:
        '''X-Vault-AWS-IAM-Server-ID is an additional header used by Vault IAM auth method to mitigate against different types of replay attacks.

        More details here: https://developer.hashicorp.com/vault/docs/auth/aws

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIam#vaultAwsIamServerID
        '''
        result = self._values.get("vault_aws_iam_server_id")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIam(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamJwt",
    jsii_struct_bases=[],
    name_mapping={"service_account_ref": "serviceAccountRef"},
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamJwt:
    def __init__(
        self,
        *,
        service_account_ref: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamJwtServiceAccountRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Specify a service account with IRSA enabled.

        :param service_account_ref: A reference to a ServiceAccount resource.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamJwt
        '''
        if isinstance(service_account_ref, dict):
            service_account_ref = ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamJwtServiceAccountRef(**service_account_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__3fcc58f46b972c368790d6aa7a694146a711fc7d454e2384196381bd3d4e3dcb)
            check_type(argname="argument service_account_ref", value=service_account_ref, expected_type=type_hints["service_account_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if service_account_ref is not None:
            self._values["service_account_ref"] = service_account_ref

    @builtins.property
    def service_account_ref(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamJwtServiceAccountRef"]:
        '''A reference to a ServiceAccount resource.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamJwt#serviceAccountRef
        '''
        result = self._values.get("service_account_ref")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamJwtServiceAccountRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamJwt(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamJwtServiceAccountRef",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "audiences": "audiences", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamJwtServiceAccountRef:
    def __init__(
        self,
        *,
        name: builtins.str,
        audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''A reference to a ServiceAccount resource.

        :param name: The name of the ServiceAccount resource being referred to.
        :param audiences: Audience specifies the ``aud`` claim for the service account token If the service account uses a well-known annotation for e.g. IRSA or GCP Workload Identity then this audiences will be appended to the list.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamJwtServiceAccountRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__f63c96e8522ed1b707467a41e21ae71d33e43a489100b2d1c588267e91dda515)
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument audiences", value=audiences, expected_type=type_hints["audiences"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "name": name,
        }
        if audiences is not None:
            self._values["audiences"] = audiences
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the ServiceAccount resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamJwtServiceAccountRef#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def audiences(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Audience specifies the ``aud`` claim for the service account token If the service account uses a well-known annotation for e.g. IRSA or GCP Workload Identity then this audiences will be appended to the list.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamJwtServiceAccountRef#audiences
        '''
        result = self._values.get("audiences")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamJwtServiceAccountRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamJwtServiceAccountRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRef",
    jsii_struct_bases=[],
    name_mapping={
        "access_key_id_secret_ref": "accessKeyIdSecretRef",
        "secret_access_key_secret_ref": "secretAccessKeySecretRef",
        "session_token_secret_ref": "sessionTokenSecretRef",
    },
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRef:
    def __init__(
        self,
        *,
        access_key_id_secret_ref: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefAccessKeyIdSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
        secret_access_key_secret_ref: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefSecretAccessKeySecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
        session_token_secret_ref: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefSessionTokenSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Specify credentials in a Secret object.

        :param access_key_id_secret_ref: The AccessKeyID is used for authentication.
        :param secret_access_key_secret_ref: The SecretAccessKey is used for authentication.
        :param session_token_secret_ref: The SessionToken used for authentication This must be defined if AccessKeyID and SecretAccessKey are temporary credentials see: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRef
        '''
        if isinstance(access_key_id_secret_ref, dict):
            access_key_id_secret_ref = ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefAccessKeyIdSecretRef(**access_key_id_secret_ref)
        if isinstance(secret_access_key_secret_ref, dict):
            secret_access_key_secret_ref = ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefSecretAccessKeySecretRef(**secret_access_key_secret_ref)
        if isinstance(session_token_secret_ref, dict):
            session_token_secret_ref = ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefSessionTokenSecretRef(**session_token_secret_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__7575de5f8d585e9e8d36ce3120891d2047b67e87999e2f56ac0153b68fd7536c)
            check_type(argname="argument access_key_id_secret_ref", value=access_key_id_secret_ref, expected_type=type_hints["access_key_id_secret_ref"])
            check_type(argname="argument secret_access_key_secret_ref", value=secret_access_key_secret_ref, expected_type=type_hints["secret_access_key_secret_ref"])
            check_type(argname="argument session_token_secret_ref", value=session_token_secret_ref, expected_type=type_hints["session_token_secret_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if access_key_id_secret_ref is not None:
            self._values["access_key_id_secret_ref"] = access_key_id_secret_ref
        if secret_access_key_secret_ref is not None:
            self._values["secret_access_key_secret_ref"] = secret_access_key_secret_ref
        if session_token_secret_ref is not None:
            self._values["session_token_secret_ref"] = session_token_secret_ref

    @builtins.property
    def access_key_id_secret_ref(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefAccessKeyIdSecretRef"]:
        '''The AccessKeyID is used for authentication.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRef#accessKeyIDSecretRef
        '''
        result = self._values.get("access_key_id_secret_ref")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefAccessKeyIdSecretRef"], result)

    @builtins.property
    def secret_access_key_secret_ref(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefSecretAccessKeySecretRef"]:
        '''The SecretAccessKey is used for authentication.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRef#secretAccessKeySecretRef
        '''
        result = self._values.get("secret_access_key_secret_ref")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefSecretAccessKeySecretRef"], result)

    @builtins.property
    def session_token_secret_ref(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefSessionTokenSecretRef"]:
        '''The SessionToken used for authentication This must be defined if AccessKeyID and SecretAccessKey are temporary credentials see: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRef#sessionTokenSecretRef
        '''
        result = self._values.get("session_token_secret_ref")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefSessionTokenSecretRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefAccessKeyIdSecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefAccessKeyIdSecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''The AccessKeyID is used for authentication.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefAccessKeyIdSecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__d22620df921362fb2070bb61692fe2d2d4bf351da0f0dc43557fe4cf436cd013)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefAccessKeyIdSecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefAccessKeyIdSecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefAccessKeyIdSecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefAccessKeyIdSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefSecretAccessKeySecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefSecretAccessKeySecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''The SecretAccessKey is used for authentication.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefSecretAccessKeySecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__c40fc197e2530062ac9b7ca3810c8fb65299f01a12ef9d4625d149ec27bc04f9)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefSecretAccessKeySecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefSecretAccessKeySecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefSecretAccessKeySecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefSecretAccessKeySecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefSessionTokenSecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefSessionTokenSecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''The SessionToken used for authentication This must be defined if AccessKeyID and SecretAccessKey are temporary credentials see: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefSessionTokenSecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__dadefaafed9cee8323181fe7b8a76aaeba9aaca5d903a75d4b86a38bbffd3c2a)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefSessionTokenSecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefSessionTokenSecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefSessionTokenSecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefSessionTokenSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwt",
    jsii_struct_bases=[],
    name_mapping={
        "path": "path",
        "kubernetes_service_account_token": "kubernetesServiceAccountToken",
        "role": "role",
        "secret_ref": "secretRef",
    },
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwt:
    def __init__(
        self,
        *,
        path: builtins.str,
        kubernetes_service_account_token: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountToken", typing.Dict[builtins.str, typing.Any]]] = None,
        role: typing.Optional[builtins.str] = None,
        secret_ref: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Jwt authenticates with Vault by passing role and JWT token using the JWT/OIDC authentication method.

        :param path: Path where the JWT authentication backend is mounted in Vault, e.g: "jwt".
        :param kubernetes_service_account_token: Optional ServiceAccountToken specifies the Kubernetes service account for which to request a token for with the ``TokenRequest`` API.
        :param role: Role is a JWT role to authenticate using the JWT/OIDC Vault authentication method.
        :param secret_ref: Optional SecretRef that refers to a key in a Secret resource containing JWT token to authenticate with Vault using the JWT/OIDC authentication method.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwt
        '''
        if isinstance(kubernetes_service_account_token, dict):
            kubernetes_service_account_token = ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountToken(**kubernetes_service_account_token)
        if isinstance(secret_ref, dict):
            secret_ref = ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtSecretRef(**secret_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__229aac6ec0f9c5f66d1afbf2decfa1c8000fc02dc6e634373bc263260b357be5)
            check_type(argname="argument path", value=path, expected_type=type_hints["path"])
            check_type(argname="argument kubernetes_service_account_token", value=kubernetes_service_account_token, expected_type=type_hints["kubernetes_service_account_token"])
            check_type(argname="argument role", value=role, expected_type=type_hints["role"])
            check_type(argname="argument secret_ref", value=secret_ref, expected_type=type_hints["secret_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "path": path,
        }
        if kubernetes_service_account_token is not None:
            self._values["kubernetes_service_account_token"] = kubernetes_service_account_token
        if role is not None:
            self._values["role"] = role
        if secret_ref is not None:
            self._values["secret_ref"] = secret_ref

    @builtins.property
    def path(self) -> builtins.str:
        '''Path where the JWT authentication backend is mounted in Vault, e.g: "jwt".

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwt#path
        '''
        result = self._values.get("path")
        assert result is not None, "Required property 'path' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def kubernetes_service_account_token(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountToken"]:
        '''Optional ServiceAccountToken specifies the Kubernetes service account for which to request a token for with the ``TokenRequest`` API.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwt#kubernetesServiceAccountToken
        '''
        result = self._values.get("kubernetes_service_account_token")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountToken"], result)

    @builtins.property
    def role(self) -> typing.Optional[builtins.str]:
        '''Role is a JWT role to authenticate using the JWT/OIDC Vault authentication method.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwt#role
        '''
        result = self._values.get("role")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def secret_ref(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtSecretRef"]:
        '''Optional SecretRef that refers to a key in a Secret resource containing JWT token to authenticate with Vault using the JWT/OIDC authentication method.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwt#secretRef
        '''
        result = self._values.get("secret_ref")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtSecretRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwt(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountToken",
    jsii_struct_bases=[],
    name_mapping={
        "service_account_ref": "serviceAccountRef",
        "audiences": "audiences",
        "expiration_seconds": "expirationSeconds",
    },
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountToken:
    def __init__(
        self,
        *,
        service_account_ref: typing.Union["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountTokenServiceAccountRef", typing.Dict[builtins.str, typing.Any]],
        audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
        expiration_seconds: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''Optional ServiceAccountToken specifies the Kubernetes service account for which to request a token for with the ``TokenRequest`` API.

        :param service_account_ref: Service account field containing the name of a kubernetes ServiceAccount.
        :param audiences: Optional audiences field that will be used to request a temporary Kubernetes service account token for the service account referenced by ``serviceAccountRef``. Defaults to a single audience ``vault`` it not specified. Deprecated: use serviceAccountRef.Audiences instead Default: a single audience ``vault`` it not specified.
        :param expiration_seconds: Optional expiration time in seconds that will be used to request a temporary Kubernetes service account token for the service account referenced by ``serviceAccountRef``. Deprecated: this will be removed in the future. Defaults to 10 minutes. Default: 10 minutes.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountToken
        '''
        if isinstance(service_account_ref, dict):
            service_account_ref = ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountTokenServiceAccountRef(**service_account_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__b199dcf4dc37caedda88bf3e2af1f395f9eac497f86fd3c9ae9e442da85fcb3c)
            check_type(argname="argument service_account_ref", value=service_account_ref, expected_type=type_hints["service_account_ref"])
            check_type(argname="argument audiences", value=audiences, expected_type=type_hints["audiences"])
            check_type(argname="argument expiration_seconds", value=expiration_seconds, expected_type=type_hints["expiration_seconds"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "service_account_ref": service_account_ref,
        }
        if audiences is not None:
            self._values["audiences"] = audiences
        if expiration_seconds is not None:
            self._values["expiration_seconds"] = expiration_seconds

    @builtins.property
    def service_account_ref(
        self,
    ) -> "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountTokenServiceAccountRef":
        '''Service account field containing the name of a kubernetes ServiceAccount.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountToken#serviceAccountRef
        '''
        result = self._values.get("service_account_ref")
        assert result is not None, "Required property 'service_account_ref' is missing"
        return typing.cast("ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountTokenServiceAccountRef", result)

    @builtins.property
    def audiences(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Optional audiences field that will be used to request a temporary Kubernetes service account token for the service account referenced by ``serviceAccountRef``.

        Defaults to a single audience ``vault`` it not specified.
        Deprecated: use serviceAccountRef.Audiences instead

        :default: a single audience ``vault`` it not specified.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountToken#audiences
        '''
        result = self._values.get("audiences")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def expiration_seconds(self) -> typing.Optional[jsii.Number]:
        '''Optional expiration time in seconds that will be used to request a temporary Kubernetes service account token for the service account referenced by ``serviceAccountRef``.

        Deprecated: this will be removed in the future.
        Defaults to 10 minutes.

        :default: 10 minutes.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountToken#expirationSeconds
        '''
        result = self._values.get("expiration_seconds")
        return typing.cast(typing.Optional[jsii.Number], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountToken(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountTokenServiceAccountRef",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "audiences": "audiences", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountTokenServiceAccountRef:
    def __init__(
        self,
        *,
        name: builtins.str,
        audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Service account field containing the name of a kubernetes ServiceAccount.

        :param name: The name of the ServiceAccount resource being referred to.
        :param audiences: Audience specifies the ``aud`` claim for the service account token If the service account uses a well-known annotation for e.g. IRSA or GCP Workload Identity then this audiences will be appended to the list.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountTokenServiceAccountRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__c0016c0d95b5a9e529ece0f4d6f80e3743686de5accf1efd2a269de96df7c640)
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument audiences", value=audiences, expected_type=type_hints["audiences"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "name": name,
        }
        if audiences is not None:
            self._values["audiences"] = audiences
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the ServiceAccount resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountTokenServiceAccountRef#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def audiences(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Audience specifies the ``aud`` claim for the service account token If the service account uses a well-known annotation for e.g. IRSA or GCP Workload Identity then this audiences will be appended to the list.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountTokenServiceAccountRef#audiences
        '''
        result = self._values.get("audiences")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountTokenServiceAccountRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountTokenServiceAccountRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtSecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtSecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Optional SecretRef that refers to a key in a Secret resource containing JWT token to authenticate with Vault using the JWT/OIDC authentication method.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtSecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__7017adabfb955003a67f5f12cf98885af650cc813cb74468384a84a23de6e3e7)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtSecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtSecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtSecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetes",
    jsii_struct_bases=[],
    name_mapping={
        "mount_path": "mountPath",
        "role": "role",
        "secret_ref": "secretRef",
        "service_account_ref": "serviceAccountRef",
    },
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetes:
    def __init__(
        self,
        *,
        mount_path: builtins.str,
        role: builtins.str,
        secret_ref: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetesSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
        service_account_ref: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetesServiceAccountRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Kubernetes authenticates with Vault by passing the ServiceAccount token stored in the named Secret resource to the Vault server.

        :param mount_path: Path where the Kubernetes authentication backend is mounted in Vault, e.g: "kubernetes".
        :param role: A required field containing the Vault Role to assume. A Role binds a Kubernetes ServiceAccount with a set of Vault policies.
        :param secret_ref: Optional secret field containing a Kubernetes ServiceAccount JWT used for authenticating with Vault. If a name is specified without a key, ``token`` is the default. If one is not specified, the one bound to the controller will be used.
        :param service_account_ref: Optional service account field containing the name of a kubernetes ServiceAccount. If the service account is specified, the service account secret token JWT will be used for authenticating with Vault. If the service account selector is not supplied, the secretRef will be used instead.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetes
        '''
        if isinstance(secret_ref, dict):
            secret_ref = ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetesSecretRef(**secret_ref)
        if isinstance(service_account_ref, dict):
            service_account_ref = ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetesServiceAccountRef(**service_account_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__55a715f0a7b9bcda5866ee8db8c2a171f2eccf9248b40b5dbb9405e47a65c174)
            check_type(argname="argument mount_path", value=mount_path, expected_type=type_hints["mount_path"])
            check_type(argname="argument role", value=role, expected_type=type_hints["role"])
            check_type(argname="argument secret_ref", value=secret_ref, expected_type=type_hints["secret_ref"])
            check_type(argname="argument service_account_ref", value=service_account_ref, expected_type=type_hints["service_account_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "mount_path": mount_path,
            "role": role,
        }
        if secret_ref is not None:
            self._values["secret_ref"] = secret_ref
        if service_account_ref is not None:
            self._values["service_account_ref"] = service_account_ref

    @builtins.property
    def mount_path(self) -> builtins.str:
        '''Path where the Kubernetes authentication backend is mounted in Vault, e.g: "kubernetes".

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetes#mountPath
        '''
        result = self._values.get("mount_path")
        assert result is not None, "Required property 'mount_path' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def role(self) -> builtins.str:
        '''A required field containing the Vault Role to assume.

        A Role binds a
        Kubernetes ServiceAccount with a set of Vault policies.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetes#role
        '''
        result = self._values.get("role")
        assert result is not None, "Required property 'role' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def secret_ref(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetesSecretRef"]:
        '''Optional secret field containing a Kubernetes ServiceAccount JWT used for authenticating with Vault.

        If a name is specified without a key,
        ``token`` is the default. If one is not specified, the one bound to
        the controller will be used.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetes#secretRef
        '''
        result = self._values.get("secret_ref")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetesSecretRef"], result)

    @builtins.property
    def service_account_ref(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetesServiceAccountRef"]:
        '''Optional service account field containing the name of a kubernetes ServiceAccount.

        If the service account is specified, the service account secret token JWT will be used
        for authenticating with Vault. If the service account selector is not supplied,
        the secretRef will be used instead.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetes#serviceAccountRef
        '''
        result = self._values.get("service_account_ref")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetesServiceAccountRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetes(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetesSecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetesSecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Optional secret field containing a Kubernetes ServiceAccount JWT used for authenticating with Vault.

        If a name is specified without a key,
        ``token`` is the default. If one is not specified, the one bound to
        the controller will be used.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetesSecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__730f50d2640b9b2319c67640982a729e38afa13f614f8a7a2162ac6a4e2311b9)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetesSecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetesSecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetesSecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetesSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetesServiceAccountRef",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "audiences": "audiences", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetesServiceAccountRef:
    def __init__(
        self,
        *,
        name: builtins.str,
        audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Optional service account field containing the name of a kubernetes ServiceAccount.

        If the service account is specified, the service account secret token JWT will be used
        for authenticating with Vault. If the service account selector is not supplied,
        the secretRef will be used instead.

        :param name: The name of the ServiceAccount resource being referred to.
        :param audiences: Audience specifies the ``aud`` claim for the service account token If the service account uses a well-known annotation for e.g. IRSA or GCP Workload Identity then this audiences will be appended to the list.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetesServiceAccountRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__885d994531e7fc8461134148bac78f677ccb70cd6801065ed09c572438a39362)
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument audiences", value=audiences, expected_type=type_hints["audiences"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "name": name,
        }
        if audiences is not None:
            self._values["audiences"] = audiences
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the ServiceAccount resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetesServiceAccountRef#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def audiences(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Audience specifies the ``aud`` claim for the service account token If the service account uses a well-known annotation for e.g. IRSA or GCP Workload Identity then this audiences will be appended to the list.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetesServiceAccountRef#audiences
        '''
        result = self._values.get("audiences")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetesServiceAccountRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetesServiceAccountRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthLdap",
    jsii_struct_bases=[],
    name_mapping={"path": "path", "username": "username", "secret_ref": "secretRef"},
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthLdap:
    def __init__(
        self,
        *,
        path: builtins.str,
        username: builtins.str,
        secret_ref: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthLdapSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Ldap authenticates with Vault by passing username/password pair using the LDAP authentication method.

        :param path: Path where the LDAP authentication backend is mounted in Vault, e.g: "ldap".
        :param username: Username is an LDAP username used to authenticate using the LDAP Vault authentication method.
        :param secret_ref: SecretRef to a key in a Secret resource containing password for the LDAP user used to authenticate with Vault using the LDAP authentication method.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthLdap
        '''
        if isinstance(secret_ref, dict):
            secret_ref = ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthLdapSecretRef(**secret_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__14be59466583be10ad4bceb3c7eec0590d6926f769661ac2d858b9a6f02c06a5)
            check_type(argname="argument path", value=path, expected_type=type_hints["path"])
            check_type(argname="argument username", value=username, expected_type=type_hints["username"])
            check_type(argname="argument secret_ref", value=secret_ref, expected_type=type_hints["secret_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "path": path,
            "username": username,
        }
        if secret_ref is not None:
            self._values["secret_ref"] = secret_ref

    @builtins.property
    def path(self) -> builtins.str:
        '''Path where the LDAP authentication backend is mounted in Vault, e.g: "ldap".

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthLdap#path
        '''
        result = self._values.get("path")
        assert result is not None, "Required property 'path' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def username(self) -> builtins.str:
        '''Username is an LDAP username used to authenticate using the LDAP Vault authentication method.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthLdap#username
        '''
        result = self._values.get("username")
        assert result is not None, "Required property 'username' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def secret_ref(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthLdapSecretRef"]:
        '''SecretRef to a key in a Secret resource containing password for the LDAP user used to authenticate with Vault using the LDAP authentication method.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthLdap#secretRef
        '''
        result = self._values.get("secret_ref")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthLdapSecretRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthLdap(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthLdapSecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthLdapSecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''SecretRef to a key in a Secret resource containing password for the LDAP user used to authenticate with Vault using the LDAP authentication method.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthLdapSecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__9d1b45b98fc97110f897716ff6bb350ca01b97a452a0e7ed1631a19e2fa1677e)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthLdapSecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthLdapSecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthLdapSecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthLdapSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthTokenSecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthTokenSecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''TokenSecretRef authenticates with Vault by presenting a token.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthTokenSecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__ba0256d12910007e8b85f34c9d7ea393f52fa367cca7b507767570486806cb3e)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthTokenSecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthTokenSecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthTokenSecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthTokenSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthUserPass",
    jsii_struct_bases=[],
    name_mapping={"path": "path", "username": "username", "secret_ref": "secretRef"},
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthUserPass:
    def __init__(
        self,
        *,
        path: builtins.str,
        username: builtins.str,
        secret_ref: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthUserPassSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''UserPass authenticates with Vault by passing username/password pair.

        :param path: Path where the UserPassword authentication backend is mounted in Vault, e.g: "userpass".
        :param username: Username is a username used to authenticate using the UserPass Vault authentication method.
        :param secret_ref: SecretRef to a key in a Secret resource containing password for the user used to authenticate with Vault using the UserPass authentication method.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthUserPass
        '''
        if isinstance(secret_ref, dict):
            secret_ref = ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthUserPassSecretRef(**secret_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__814bccc7eee2bb0b01c55e861c30268f3aa9e3d17c1930afb52360cdbf7a0fa2)
            check_type(argname="argument path", value=path, expected_type=type_hints["path"])
            check_type(argname="argument username", value=username, expected_type=type_hints["username"])
            check_type(argname="argument secret_ref", value=secret_ref, expected_type=type_hints["secret_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "path": path,
            "username": username,
        }
        if secret_ref is not None:
            self._values["secret_ref"] = secret_ref

    @builtins.property
    def path(self) -> builtins.str:
        '''Path where the UserPassword authentication backend is mounted in Vault, e.g: "userpass".

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthUserPass#path
        '''
        result = self._values.get("path")
        assert result is not None, "Required property 'path' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def username(self) -> builtins.str:
        '''Username is a username used to authenticate using the UserPass Vault authentication method.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthUserPass#username
        '''
        result = self._values.get("username")
        assert result is not None, "Required property 'username' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def secret_ref(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthUserPassSecretRef"]:
        '''SecretRef to a key in a Secret resource containing password for the user used to authenticate with Vault using the UserPass authentication method.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthUserPass#secretRef
        '''
        result = self._values.get("secret_ref")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthUserPassSecretRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthUserPass(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthUserPassSecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthUserPassSecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''SecretRef to a key in a Secret resource containing password for the user used to authenticate with Vault using the UserPass authentication method.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthUserPassSecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__1c41bb2e70be3a1141aa7931963f1605cf7b10f76a2d70a55fe2005969b40056)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthUserPassSecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthUserPassSecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthUserPassSecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthUserPassSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderCaProvider",
    jsii_struct_bases=[],
    name_mapping={
        "name": "name",
        "type": "type",
        "key": "key",
        "namespace": "namespace",
    },
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderCaProvider:
    def __init__(
        self,
        *,
        name: builtins.str,
        type: "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderCaProviderType",
        key: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''The provider for the CA bundle to use to validate Vault server certificate.

        :param name: The name of the object located at the provider type.
        :param type: The type of provider to use such as "Secret", or "ConfigMap".
        :param key: The key where the CA certificate can be found in the Secret or ConfigMap.
        :param namespace: The namespace the Provider type is in. Can only be defined when used in a ClusterSecretStore.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderCaProvider
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__340569b935c53537966a2561c57a24a76cbf9c69dbf7689874dd5ce46ffeaf82)
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument type", value=type, expected_type=type_hints["type"])
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "name": name,
            "type": type,
        }
        if key is not None:
            self._values["key"] = key
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the object located at the provider type.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderCaProvider#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def type(
        self,
    ) -> "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderCaProviderType":
        '''The type of provider to use such as "Secret", or "ConfigMap".

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderCaProvider#type
        '''
        result = self._values.get("type")
        assert result is not None, "Required property 'type' is missing"
        return typing.cast("ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderCaProviderType", result)

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''The key where the CA certificate can be found in the Secret or ConfigMap.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderCaProvider#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace the Provider type is in.

        Can only be defined when used in a ClusterSecretStore.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderCaProvider#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderCaProvider(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderCaProviderType"
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderCaProviderType(
    enum.Enum,
):
    '''The type of provider to use such as "Secret", or "ConfigMap".

    :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderCaProviderType
    '''

    SECRET = "SECRET"
    '''Secret.'''
    CONFIG_MAP = "CONFIG_MAP"
    '''ConfigMap.'''


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTls",
    jsii_struct_bases=[],
    name_mapping={
        "cert_secret_ref": "certSecretRef",
        "key_secret_ref": "keySecretRef",
    },
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTls:
    def __init__(
        self,
        *,
        cert_secret_ref: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTlsCertSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
        key_secret_ref: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTlsKeySecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''The configuration used for client side related TLS communication, when the Vault server requires mutual authentication.

        Only used if the Server URL is using HTTPS protocol.
        This parameter is ignored for plain HTTP protocol connection.
        It's worth noting this configuration is different from the "TLS certificates auth method",
        which is available under the ``auth.cert`` section.

        :param cert_secret_ref: CertSecretRef is a certificate added to the transport layer when communicating with the Vault server. If no key for the Secret is specified, external-secret will default to 'tls.crt'.
        :param key_secret_ref: KeySecretRef to a key in a Secret resource containing client private key added to the transport layer when communicating with the Vault server. If no key for the Secret is specified, external-secret will default to 'tls.key'.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTls
        '''
        if isinstance(cert_secret_ref, dict):
            cert_secret_ref = ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTlsCertSecretRef(**cert_secret_ref)
        if isinstance(key_secret_ref, dict):
            key_secret_ref = ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTlsKeySecretRef(**key_secret_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__057069f97defad41a9a7d25d600958df8a1fb8a29b4c5656f593c16c84c882c1)
            check_type(argname="argument cert_secret_ref", value=cert_secret_ref, expected_type=type_hints["cert_secret_ref"])
            check_type(argname="argument key_secret_ref", value=key_secret_ref, expected_type=type_hints["key_secret_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if cert_secret_ref is not None:
            self._values["cert_secret_ref"] = cert_secret_ref
        if key_secret_ref is not None:
            self._values["key_secret_ref"] = key_secret_ref

    @builtins.property
    def cert_secret_ref(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTlsCertSecretRef"]:
        '''CertSecretRef is a certificate added to the transport layer when communicating with the Vault server.

        If no key for the Secret is specified, external-secret will default to 'tls.crt'.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTls#certSecretRef
        '''
        result = self._values.get("cert_secret_ref")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTlsCertSecretRef"], result)

    @builtins.property
    def key_secret_ref(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTlsKeySecretRef"]:
        '''KeySecretRef to a key in a Secret resource containing client private key added to the transport layer when communicating with the Vault server.

        If no key for the Secret is specified, external-secret will default to 'tls.key'.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTls#keySecretRef
        '''
        result = self._values.get("key_secret_ref")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTlsKeySecretRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTls(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTlsCertSecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTlsCertSecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''CertSecretRef is a certificate added to the transport layer when communicating with the Vault server.

        If no key for the Secret is specified, external-secret will default to 'tls.crt'.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTlsCertSecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__a7a43432578b558898e36df977d0c9e9e0a455970e6f0eeade3dc49f5f8200e1)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTlsCertSecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTlsCertSecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTlsCertSecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTlsCertSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTlsKeySecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTlsKeySecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''KeySecretRef to a key in a Secret resource containing client private key added to the transport layer when communicating with the Vault server.

        If no key for the Secret is specified, external-secret will default to 'tls.key'.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTlsKeySecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__5b47872d55b2aa3ce83911b888bb441922abcd0a955c401e37dbef745d2e203d)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTlsKeySecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTlsKeySecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTlsKeySecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTlsKeySecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderVersion"
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderVersion(enum.Enum):
    '''Version is the Vault KV secret engine version.

    This can be either "v1" or
    "v2". Version defaults to "v2".

    :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderVersion
    '''

    V1 = "V1"
    '''v1.'''
    V2 = "V2"
    '''v2.'''


@jsii.enum(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecResultType"
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecResultType(enum.Enum):
    '''Result type defines which data is returned from the generator.

    By default it is the "data" section of the Vault API response.
    When using e.g. /auth/token/create the "data" section is empty but
    the "auth" section contains the generated token.
    Please refer to the vault docs regarding the result data structure.
    Additionally, accessing the raw response is possibly by using "Raw" result type.

    :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecResultType
    '''

    DATA = "DATA"
    '''Data.'''
    AUTH = "AUTH"
    '''Auth.'''
    RAW = "RAW"
    '''Raw.'''


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecRetrySettings",
    jsii_struct_bases=[],
    name_mapping={"max_retries": "maxRetries", "retry_interval": "retryInterval"},
)
class ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecRetrySettings:
    def __init__(
        self,
        *,
        max_retries: typing.Optional[jsii.Number] = None,
        retry_interval: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Used to configure http retries if failed.

        :param max_retries: 
        :param retry_interval: 

        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecRetrySettings
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__b74fcec0cfc5ad62fc03a55496882bcc7c5fc822f3d8f6820314e48d530e85f8)
            check_type(argname="argument max_retries", value=max_retries, expected_type=type_hints["max_retries"])
            check_type(argname="argument retry_interval", value=retry_interval, expected_type=type_hints["retry_interval"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if max_retries is not None:
            self._values["max_retries"] = max_retries
        if retry_interval is not None:
            self._values["retry_interval"] = retry_interval

    @builtins.property
    def max_retries(self) -> typing.Optional[jsii.Number]:
        '''
        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecRetrySettings#maxRetries
        '''
        result = self._values.get("max_retries")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def retry_interval(self) -> typing.Optional[builtins.str]:
        '''
        :schema: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecRetrySettings#retryInterval
        '''
        result = self._values.get("retry_interval")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecRetrySettings(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorWebhookSpec",
    jsii_struct_bases=[],
    name_mapping={
        "result": "result",
        "url": "url",
        "auth": "auth",
        "body": "body",
        "ca_bundle": "caBundle",
        "ca_provider": "caProvider",
        "headers": "headers",
        "method": "method",
        "secrets": "secrets",
        "timeout": "timeout",
    },
)
class ClusterGeneratorSpecGeneratorWebhookSpec:
    def __init__(
        self,
        *,
        result: typing.Union["ClusterGeneratorSpecGeneratorWebhookSpecResult", typing.Dict[builtins.str, typing.Any]],
        url: builtins.str,
        auth: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorWebhookSpecAuth", typing.Dict[builtins.str, typing.Any]]] = None,
        body: typing.Optional[builtins.str] = None,
        ca_bundle: typing.Optional[builtins.str] = None,
        ca_provider: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorWebhookSpecCaProvider", typing.Dict[builtins.str, typing.Any]]] = None,
        headers: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        method: typing.Optional[builtins.str] = None,
        secrets: typing.Optional[typing.Sequence[typing.Union["ClusterGeneratorSpecGeneratorWebhookSpecSecrets", typing.Dict[builtins.str, typing.Any]]]] = None,
        timeout: typing.Optional[builtins.str] = None,
    ) -> None:
        '''WebhookSpec controls the behavior of the external generator.

        Any body parameters should be passed to the server through the parameters field.

        :param result: Result formatting.
        :param url: Webhook url to call.
        :param auth: Auth specifies a authorization protocol. Only one protocol may be set.
        :param body: Body.
        :param ca_bundle: PEM encoded CA bundle used to validate webhook server certificate. Only used if the Server URL is using HTTPS protocol. This parameter is ignored for plain HTTP protocol connection. If not set the system root certificates are used to validate the TLS connection.
        :param ca_provider: The provider for the CA bundle to use to validate webhook server certificate.
        :param headers: Headers.
        :param method: Webhook Method.
        :param secrets: Secrets to fill in templates These secrets will be passed to the templating function as key value pairs under the given name.
        :param timeout: Timeout.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpec
        '''
        if isinstance(result, dict):
            result = ClusterGeneratorSpecGeneratorWebhookSpecResult(**result)
        if isinstance(auth, dict):
            auth = ClusterGeneratorSpecGeneratorWebhookSpecAuth(**auth)
        if isinstance(ca_provider, dict):
            ca_provider = ClusterGeneratorSpecGeneratorWebhookSpecCaProvider(**ca_provider)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__d6461244ada6ac27bc8b5825bc53378b49b97c43164c4e5d508c69ab37ef4761)
            check_type(argname="argument result", value=result, expected_type=type_hints["result"])
            check_type(argname="argument url", value=url, expected_type=type_hints["url"])
            check_type(argname="argument auth", value=auth, expected_type=type_hints["auth"])
            check_type(argname="argument body", value=body, expected_type=type_hints["body"])
            check_type(argname="argument ca_bundle", value=ca_bundle, expected_type=type_hints["ca_bundle"])
            check_type(argname="argument ca_provider", value=ca_provider, expected_type=type_hints["ca_provider"])
            check_type(argname="argument headers", value=headers, expected_type=type_hints["headers"])
            check_type(argname="argument method", value=method, expected_type=type_hints["method"])
            check_type(argname="argument secrets", value=secrets, expected_type=type_hints["secrets"])
            check_type(argname="argument timeout", value=timeout, expected_type=type_hints["timeout"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "result": result,
            "url": url,
        }
        if auth is not None:
            self._values["auth"] = auth
        if body is not None:
            self._values["body"] = body
        if ca_bundle is not None:
            self._values["ca_bundle"] = ca_bundle
        if ca_provider is not None:
            self._values["ca_provider"] = ca_provider
        if headers is not None:
            self._values["headers"] = headers
        if method is not None:
            self._values["method"] = method
        if secrets is not None:
            self._values["secrets"] = secrets
        if timeout is not None:
            self._values["timeout"] = timeout

    @builtins.property
    def result(self) -> "ClusterGeneratorSpecGeneratorWebhookSpecResult":
        '''Result formatting.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpec#result
        '''
        result = self._values.get("result")
        assert result is not None, "Required property 'result' is missing"
        return typing.cast("ClusterGeneratorSpecGeneratorWebhookSpecResult", result)

    @builtins.property
    def url(self) -> builtins.str:
        '''Webhook url to call.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpec#url
        '''
        result = self._values.get("url")
        assert result is not None, "Required property 'url' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def auth(self) -> typing.Optional["ClusterGeneratorSpecGeneratorWebhookSpecAuth"]:
        '''Auth specifies a authorization protocol.

        Only one protocol may be set.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpec#auth
        '''
        result = self._values.get("auth")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorWebhookSpecAuth"], result)

    @builtins.property
    def body(self) -> typing.Optional[builtins.str]:
        '''Body.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpec#body
        '''
        result = self._values.get("body")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ca_bundle(self) -> typing.Optional[builtins.str]:
        '''PEM encoded CA bundle used to validate webhook server certificate.

        Only used
        if the Server URL is using HTTPS protocol. This parameter is ignored for
        plain HTTP protocol connection. If not set the system root certificates
        are used to validate the TLS connection.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpec#caBundle
        '''
        result = self._values.get("ca_bundle")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ca_provider(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorWebhookSpecCaProvider"]:
        '''The provider for the CA bundle to use to validate webhook server certificate.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpec#caProvider
        '''
        result = self._values.get("ca_provider")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorWebhookSpecCaProvider"], result)

    @builtins.property
    def headers(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Headers.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpec#headers
        '''
        result = self._values.get("headers")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def method(self) -> typing.Optional[builtins.str]:
        '''Webhook Method.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpec#method
        '''
        result = self._values.get("method")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def secrets(
        self,
    ) -> typing.Optional[typing.List["ClusterGeneratorSpecGeneratorWebhookSpecSecrets"]]:
        '''Secrets to fill in templates These secrets will be passed to the templating function as key value pairs under the given name.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpec#secrets
        '''
        result = self._values.get("secrets")
        return typing.cast(typing.Optional[typing.List["ClusterGeneratorSpecGeneratorWebhookSpecSecrets"]], result)

    @builtins.property
    def timeout(self) -> typing.Optional[builtins.str]:
        '''Timeout.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpec#timeout
        '''
        result = self._values.get("timeout")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorWebhookSpec(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorWebhookSpecAuth",
    jsii_struct_bases=[],
    name_mapping={"ntlm": "ntlm"},
)
class ClusterGeneratorSpecGeneratorWebhookSpecAuth:
    def __init__(
        self,
        *,
        ntlm: typing.Optional[typing.Union["ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlm", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Auth specifies a authorization protocol.

        Only one protocol may be set.

        :param ntlm: NTLMProtocol configures the store to use NTLM for auth.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpecAuth
        '''
        if isinstance(ntlm, dict):
            ntlm = ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlm(**ntlm)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__5dcfc882e004f94cf73db65a2a920c62c718b548501cfa608829f09e91423b6d)
            check_type(argname="argument ntlm", value=ntlm, expected_type=type_hints["ntlm"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if ntlm is not None:
            self._values["ntlm"] = ntlm

    @builtins.property
    def ntlm(
        self,
    ) -> typing.Optional["ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlm"]:
        '''NTLMProtocol configures the store to use NTLM for auth.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpecAuth#ntlm
        '''
        result = self._values.get("ntlm")
        return typing.cast(typing.Optional["ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlm"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorWebhookSpecAuth(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlm",
    jsii_struct_bases=[],
    name_mapping={
        "password_secret": "passwordSecret",
        "username_secret": "usernameSecret",
    },
)
class ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlm:
    def __init__(
        self,
        *,
        password_secret: typing.Union["ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlmPasswordSecret", typing.Dict[builtins.str, typing.Any]],
        username_secret: typing.Union["ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlmUsernameSecret", typing.Dict[builtins.str, typing.Any]],
    ) -> None:
        '''NTLMProtocol configures the store to use NTLM for auth.

        :param password_secret: A reference to a specific 'key' within a Secret resource. In some instances, ``key`` is a required field.
        :param username_secret: A reference to a specific 'key' within a Secret resource. In some instances, ``key`` is a required field.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlm
        '''
        if isinstance(password_secret, dict):
            password_secret = ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlmPasswordSecret(**password_secret)
        if isinstance(username_secret, dict):
            username_secret = ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlmUsernameSecret(**username_secret)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__1c7b235434f71cb2dedf89df634e92c9be7c19319bdbabf850fb2ef0f7f26a81)
            check_type(argname="argument password_secret", value=password_secret, expected_type=type_hints["password_secret"])
            check_type(argname="argument username_secret", value=username_secret, expected_type=type_hints["username_secret"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "password_secret": password_secret,
            "username_secret": username_secret,
        }

    @builtins.property
    def password_secret(
        self,
    ) -> "ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlmPasswordSecret":
        '''A reference to a specific 'key' within a Secret resource.

        In some instances, ``key`` is a required field.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlm#passwordSecret
        '''
        result = self._values.get("password_secret")
        assert result is not None, "Required property 'password_secret' is missing"
        return typing.cast("ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlmPasswordSecret", result)

    @builtins.property
    def username_secret(
        self,
    ) -> "ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlmUsernameSecret":
        '''A reference to a specific 'key' within a Secret resource.

        In some instances, ``key`` is a required field.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlm#usernameSecret
        '''
        result = self._values.get("username_secret")
        assert result is not None, "Required property 'username_secret' is missing"
        return typing.cast("ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlmUsernameSecret", result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlm(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlmPasswordSecret",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlmPasswordSecret:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''A reference to a specific 'key' within a Secret resource.

        In some instances, ``key`` is a required field.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlmPasswordSecret
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__89e3c64096d7ab15ba070babc315844393aa774d5e6d59f8d8af1081809d3a33)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlmPasswordSecret#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlmPasswordSecret#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlmPasswordSecret#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlmPasswordSecret(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlmUsernameSecret",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlmUsernameSecret:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''A reference to a specific 'key' within a Secret resource.

        In some instances, ``key`` is a required field.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlmUsernameSecret
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__debabacb7a72e2aa4ed6e808a4b80893eb1122c2c840d54555a48ec65fe99f40)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlmUsernameSecret#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlmUsernameSecret#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlmUsernameSecret#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlmUsernameSecret(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorWebhookSpecCaProvider",
    jsii_struct_bases=[],
    name_mapping={
        "name": "name",
        "type": "type",
        "key": "key",
        "namespace": "namespace",
    },
)
class ClusterGeneratorSpecGeneratorWebhookSpecCaProvider:
    def __init__(
        self,
        *,
        name: builtins.str,
        type: "ClusterGeneratorSpecGeneratorWebhookSpecCaProviderType",
        key: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''The provider for the CA bundle to use to validate webhook server certificate.

        :param name: The name of the object located at the provider type.
        :param type: The type of provider to use such as "Secret", or "ConfigMap".
        :param key: The key where the CA certificate can be found in the Secret or ConfigMap.
        :param namespace: The namespace the Provider type is in.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpecCaProvider
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__4b92096e419e1807bd3716a182558dd52eb79fd93b0891aae2196fe701b6ef16)
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument type", value=type, expected_type=type_hints["type"])
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "name": name,
            "type": type,
        }
        if key is not None:
            self._values["key"] = key
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the object located at the provider type.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpecCaProvider#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def type(self) -> "ClusterGeneratorSpecGeneratorWebhookSpecCaProviderType":
        '''The type of provider to use such as "Secret", or "ConfigMap".

        :schema: ClusterGeneratorSpecGeneratorWebhookSpecCaProvider#type
        '''
        result = self._values.get("type")
        assert result is not None, "Required property 'type' is missing"
        return typing.cast("ClusterGeneratorSpecGeneratorWebhookSpecCaProviderType", result)

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''The key where the CA certificate can be found in the Secret or ConfigMap.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpecCaProvider#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace the Provider type is in.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpecCaProvider#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorWebhookSpecCaProvider(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorWebhookSpecCaProviderType"
)
class ClusterGeneratorSpecGeneratorWebhookSpecCaProviderType(enum.Enum):
    '''The type of provider to use such as "Secret", or "ConfigMap".

    :schema: ClusterGeneratorSpecGeneratorWebhookSpecCaProviderType
    '''

    SECRET = "SECRET"
    '''Secret.'''
    CONFIG_MAP = "CONFIG_MAP"
    '''ConfigMap.'''


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorWebhookSpecResult",
    jsii_struct_bases=[],
    name_mapping={"json_path": "jsonPath"},
)
class ClusterGeneratorSpecGeneratorWebhookSpecResult:
    def __init__(self, *, json_path: typing.Optional[builtins.str] = None) -> None:
        '''Result formatting.

        :param json_path: Json path of return value.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpecResult
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__8041ab4574aca2838e415c6546545a99564650a2e591ef65839792832acd0ddb)
            check_type(argname="argument json_path", value=json_path, expected_type=type_hints["json_path"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if json_path is not None:
            self._values["json_path"] = json_path

    @builtins.property
    def json_path(self) -> typing.Optional[builtins.str]:
        '''Json path of return value.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpecResult#jsonPath
        '''
        result = self._values.get("json_path")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorWebhookSpecResult(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorWebhookSpecSecrets",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "secret_ref": "secretRef"},
)
class ClusterGeneratorSpecGeneratorWebhookSpecSecrets:
    def __init__(
        self,
        *,
        name: builtins.str,
        secret_ref: typing.Union["ClusterGeneratorSpecGeneratorWebhookSpecSecretsSecretRef", typing.Dict[builtins.str, typing.Any]],
    ) -> None:
        '''
        :param name: Name of this secret in templates.
        :param secret_ref: Secret ref to fill in credentials.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpecSecrets
        '''
        if isinstance(secret_ref, dict):
            secret_ref = ClusterGeneratorSpecGeneratorWebhookSpecSecretsSecretRef(**secret_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__82ab7197f1b285356b812b884d29838271d2890f88cc26e4ec5c6691a6c19ee4)
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument secret_ref", value=secret_ref, expected_type=type_hints["secret_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "name": name,
            "secret_ref": secret_ref,
        }

    @builtins.property
    def name(self) -> builtins.str:
        '''Name of this secret in templates.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpecSecrets#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def secret_ref(self) -> "ClusterGeneratorSpecGeneratorWebhookSpecSecretsSecretRef":
        '''Secret ref to fill in credentials.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpecSecrets#secretRef
        '''
        result = self._values.get("secret_ref")
        assert result is not None, "Required property 'secret_ref' is missing"
        return typing.cast("ClusterGeneratorSpecGeneratorWebhookSpecSecretsSecretRef", result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorWebhookSpecSecrets(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecGeneratorWebhookSpecSecretsSecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name"},
)
class ClusterGeneratorSpecGeneratorWebhookSpecSecretsSecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Secret ref to fill in credentials.

        :param key: The key where the token is found.
        :param name: The name of the Secret resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpecSecretsSecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__c09ce5b92036fdb91cd0502923a430b4067e058dbfbceffe4e310b5de877491c)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''The key where the token is found.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpecSecretsSecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: ClusterGeneratorSpecGeneratorWebhookSpecSecretsSecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterGeneratorSpecGeneratorWebhookSpecSecretsSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="ioexternal-secretsgenerators.ClusterGeneratorSpecKind")
class ClusterGeneratorSpecKind(enum.Enum):
    '''Kind the kind of this generator.

    :schema: ClusterGeneratorSpecKind
    '''

    ACR_ACCESS_TOKEN = "ACR_ACCESS_TOKEN"
    '''ACRAccessToken.'''
    ECR_AUTHORIZATION_TOKEN = "ECR_AUTHORIZATION_TOKEN"
    '''ECRAuthorizationToken.'''
    FAKE = "FAKE"
    '''Fake.'''
    GCR_ACCESS_TOKEN = "GCR_ACCESS_TOKEN"
    '''GCRAccessToken.'''
    GITHUB_ACCESS_TOKEN = "GITHUB_ACCESS_TOKEN"
    '''GithubAccessToken.'''
    QUAY_ACCESS_TOKEN = "QUAY_ACCESS_TOKEN"
    '''QuayAccessToken.'''
    PASSWORD = "PASSWORD"
    '''Password.'''
    STS_SESSION_TOKEN = "STS_SESSION_TOKEN"
    '''STSSessionToken.'''
    UUID = "UUID"
    '''UUID.'''
    VAULT_DYNAMIC_SECRET = "VAULT_DYNAMIC_SECRET"
    '''VaultDynamicSecret.'''
    WEBHOOK = "WEBHOOK"
    '''Webhook.'''
    GRAFANA = "GRAFANA"
    '''Grafana.'''


class EcrAuthorizationToken(
    _cdk8s_d3d9af27.ApiObject,
    metaclass=jsii.JSIIMeta,
    jsii_type="ioexternal-secretsgenerators.EcrAuthorizationToken",
):
    '''ECRAuthorizationTokenSpec uses the GetAuthorizationToken API to retrieve an authorization token.

    The authorization token is valid for 12 hours.
    The authorizationToken returned is a base64 encoded string that can be decoded
    and used in a docker login command to authenticate to a registry.
    For more information, see Registry authentication (https://docs.aws.amazon.com/AmazonECR/latest/userguide/Registries.html#registry_auth) in the Amazon Elastic Container Registry User Guide.

    :schema: ECRAuthorizationToken
    '''

    def __init__(
        self,
        scope: _constructs_77d1e7e8.Construct,
        id: builtins.str,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["EcrAuthorizationTokenSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Defines a "ECRAuthorizationToken" API object.

        :param scope: the scope in which to define this object.
        :param id: a scope-local name for the object.
        :param metadata: 
        :param spec: 
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__e71cfb104a01494a1528bff38caa7ed42d6867f4d83a50d779a8e249dea7183a)
            check_type(argname="argument scope", value=scope, expected_type=type_hints["scope"])
            check_type(argname="argument id", value=id, expected_type=type_hints["id"])
        props = EcrAuthorizationTokenProps(metadata=metadata, spec=spec)

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="manifest")
    @builtins.classmethod
    def manifest(
        cls,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["EcrAuthorizationTokenSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> typing.Any:
        '''Renders a Kubernetes manifest for "ECRAuthorizationToken".

        This can be used to inline resource manifests inside other objects (e.g. as templates).

        :param metadata: 
        :param spec: 
        '''
        props = EcrAuthorizationTokenProps(metadata=metadata, spec=spec)

        return typing.cast(typing.Any, jsii.sinvoke(cls, "manifest", [props]))

    @jsii.member(jsii_name="toJson")
    def to_json(self) -> typing.Any:
        '''Renders the object to Kubernetes JSON.'''
        return typing.cast(typing.Any, jsii.invoke(self, "toJson", []))

    @jsii.python.classproperty
    @jsii.member(jsii_name="GVK")
    def GVK(cls) -> _cdk8s_d3d9af27.GroupVersionKind:
        '''Returns the apiVersion and kind for "ECRAuthorizationToken".'''
        return typing.cast(_cdk8s_d3d9af27.GroupVersionKind, jsii.sget(cls, "GVK"))


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.EcrAuthorizationTokenProps",
    jsii_struct_bases=[],
    name_mapping={"metadata": "metadata", "spec": "spec"},
)
class EcrAuthorizationTokenProps:
    def __init__(
        self,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["EcrAuthorizationTokenSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''ECRAuthorizationTokenSpec uses the GetAuthorizationToken API to retrieve an authorization token.

        The authorization token is valid for 12 hours.
        The authorizationToken returned is a base64 encoded string that can be decoded
        and used in a docker login command to authenticate to a registry.
        For more information, see Registry authentication (https://docs.aws.amazon.com/AmazonECR/latest/userguide/Registries.html#registry_auth) in the Amazon Elastic Container Registry User Guide.

        :param metadata: 
        :param spec: 

        :schema: ECRAuthorizationToken
        '''
        if isinstance(metadata, dict):
            metadata = _cdk8s_d3d9af27.ApiObjectMetadata(**metadata)
        if isinstance(spec, dict):
            spec = EcrAuthorizationTokenSpec(**spec)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__7e431d24fa6016e556b9f4cdc9b5634a7ec0488fcdd0149846b1011367978e2a)
            check_type(argname="argument metadata", value=metadata, expected_type=type_hints["metadata"])
            check_type(argname="argument spec", value=spec, expected_type=type_hints["spec"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if metadata is not None:
            self._values["metadata"] = metadata
        if spec is not None:
            self._values["spec"] = spec

    @builtins.property
    def metadata(self) -> typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata]:
        '''
        :schema: ECRAuthorizationToken#metadata
        '''
        result = self._values.get("metadata")
        return typing.cast(typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata], result)

    @builtins.property
    def spec(self) -> typing.Optional["EcrAuthorizationTokenSpec"]:
        '''
        :schema: ECRAuthorizationToken#spec
        '''
        result = self._values.get("spec")
        return typing.cast(typing.Optional["EcrAuthorizationTokenSpec"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "EcrAuthorizationTokenProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.EcrAuthorizationTokenSpec",
    jsii_struct_bases=[],
    name_mapping={
        "region": "region",
        "auth": "auth",
        "role": "role",
        "scope": "scope",
    },
)
class EcrAuthorizationTokenSpec:
    def __init__(
        self,
        *,
        region: builtins.str,
        auth: typing.Optional[typing.Union["EcrAuthorizationTokenSpecAuth", typing.Dict[builtins.str, typing.Any]]] = None,
        role: typing.Optional[builtins.str] = None,
        scope: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param region: Region specifies the region to operate in.
        :param auth: Auth defines how to authenticate with AWS.
        :param role: You can assume a role before making calls to the desired AWS service.
        :param scope: Scope specifies the ECR service scope. Valid options are private and public.

        :schema: EcrAuthorizationTokenSpec
        '''
        if isinstance(auth, dict):
            auth = EcrAuthorizationTokenSpecAuth(**auth)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__324512f7d0f8d8b457280dd1e15f21985b97b88f08bab8a4ee40bca0e64ea7f6)
            check_type(argname="argument region", value=region, expected_type=type_hints["region"])
            check_type(argname="argument auth", value=auth, expected_type=type_hints["auth"])
            check_type(argname="argument role", value=role, expected_type=type_hints["role"])
            check_type(argname="argument scope", value=scope, expected_type=type_hints["scope"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "region": region,
        }
        if auth is not None:
            self._values["auth"] = auth
        if role is not None:
            self._values["role"] = role
        if scope is not None:
            self._values["scope"] = scope

    @builtins.property
    def region(self) -> builtins.str:
        '''Region specifies the region to operate in.

        :schema: EcrAuthorizationTokenSpec#region
        '''
        result = self._values.get("region")
        assert result is not None, "Required property 'region' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def auth(self) -> typing.Optional["EcrAuthorizationTokenSpecAuth"]:
        '''Auth defines how to authenticate with AWS.

        :schema: EcrAuthorizationTokenSpec#auth
        '''
        result = self._values.get("auth")
        return typing.cast(typing.Optional["EcrAuthorizationTokenSpecAuth"], result)

    @builtins.property
    def role(self) -> typing.Optional[builtins.str]:
        '''You can assume a role before making calls to the desired AWS service.

        :schema: EcrAuthorizationTokenSpec#role
        '''
        result = self._values.get("role")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def scope(self) -> typing.Optional[builtins.str]:
        '''Scope specifies the ECR service scope.

        Valid options are private and public.

        :schema: EcrAuthorizationTokenSpec#scope
        '''
        result = self._values.get("scope")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "EcrAuthorizationTokenSpec(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.EcrAuthorizationTokenSpecAuth",
    jsii_struct_bases=[],
    name_mapping={"jwt": "jwt", "secret_ref": "secretRef"},
)
class EcrAuthorizationTokenSpecAuth:
    def __init__(
        self,
        *,
        jwt: typing.Optional[typing.Union["EcrAuthorizationTokenSpecAuthJwt", typing.Dict[builtins.str, typing.Any]]] = None,
        secret_ref: typing.Optional[typing.Union["EcrAuthorizationTokenSpecAuthSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Auth defines how to authenticate with AWS.

        :param jwt: Authenticate against AWS using service account tokens.
        :param secret_ref: AWSAuthSecretRef holds secret references for AWS credentials both AccessKeyID and SecretAccessKey must be defined in order to properly authenticate.

        :schema: EcrAuthorizationTokenSpecAuth
        '''
        if isinstance(jwt, dict):
            jwt = EcrAuthorizationTokenSpecAuthJwt(**jwt)
        if isinstance(secret_ref, dict):
            secret_ref = EcrAuthorizationTokenSpecAuthSecretRef(**secret_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__99a4157b913631f69b599f277cde66f7621cd2ccbc79b7044db9d53b11fbed6e)
            check_type(argname="argument jwt", value=jwt, expected_type=type_hints["jwt"])
            check_type(argname="argument secret_ref", value=secret_ref, expected_type=type_hints["secret_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if jwt is not None:
            self._values["jwt"] = jwt
        if secret_ref is not None:
            self._values["secret_ref"] = secret_ref

    @builtins.property
    def jwt(self) -> typing.Optional["EcrAuthorizationTokenSpecAuthJwt"]:
        '''Authenticate against AWS using service account tokens.

        :schema: EcrAuthorizationTokenSpecAuth#jwt
        '''
        result = self._values.get("jwt")
        return typing.cast(typing.Optional["EcrAuthorizationTokenSpecAuthJwt"], result)

    @builtins.property
    def secret_ref(self) -> typing.Optional["EcrAuthorizationTokenSpecAuthSecretRef"]:
        '''AWSAuthSecretRef holds secret references for AWS credentials both AccessKeyID and SecretAccessKey must be defined in order to properly authenticate.

        :schema: EcrAuthorizationTokenSpecAuth#secretRef
        '''
        result = self._values.get("secret_ref")
        return typing.cast(typing.Optional["EcrAuthorizationTokenSpecAuthSecretRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "EcrAuthorizationTokenSpecAuth(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.EcrAuthorizationTokenSpecAuthJwt",
    jsii_struct_bases=[],
    name_mapping={"service_account_ref": "serviceAccountRef"},
)
class EcrAuthorizationTokenSpecAuthJwt:
    def __init__(
        self,
        *,
        service_account_ref: typing.Optional[typing.Union["EcrAuthorizationTokenSpecAuthJwtServiceAccountRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Authenticate against AWS using service account tokens.

        :param service_account_ref: A reference to a ServiceAccount resource.

        :schema: EcrAuthorizationTokenSpecAuthJwt
        '''
        if isinstance(service_account_ref, dict):
            service_account_ref = EcrAuthorizationTokenSpecAuthJwtServiceAccountRef(**service_account_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__e21f0831584304a498cb602853af5f59bc58668301a4c6f20c4e2842a2297ff1)
            check_type(argname="argument service_account_ref", value=service_account_ref, expected_type=type_hints["service_account_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if service_account_ref is not None:
            self._values["service_account_ref"] = service_account_ref

    @builtins.property
    def service_account_ref(
        self,
    ) -> typing.Optional["EcrAuthorizationTokenSpecAuthJwtServiceAccountRef"]:
        '''A reference to a ServiceAccount resource.

        :schema: EcrAuthorizationTokenSpecAuthJwt#serviceAccountRef
        '''
        result = self._values.get("service_account_ref")
        return typing.cast(typing.Optional["EcrAuthorizationTokenSpecAuthJwtServiceAccountRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "EcrAuthorizationTokenSpecAuthJwt(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.EcrAuthorizationTokenSpecAuthJwtServiceAccountRef",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "audiences": "audiences", "namespace": "namespace"},
)
class EcrAuthorizationTokenSpecAuthJwtServiceAccountRef:
    def __init__(
        self,
        *,
        name: builtins.str,
        audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''A reference to a ServiceAccount resource.

        :param name: The name of the ServiceAccount resource being referred to.
        :param audiences: Audience specifies the ``aud`` claim for the service account token If the service account uses a well-known annotation for e.g. IRSA or GCP Workload Identity then this audiences will be appended to the list.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: EcrAuthorizationTokenSpecAuthJwtServiceAccountRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__8c10b7f6ffeed346ecf29b79cc6266f31bf1bd8effb7681cb7cb2578520cfdb7)
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument audiences", value=audiences, expected_type=type_hints["audiences"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "name": name,
        }
        if audiences is not None:
            self._values["audiences"] = audiences
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the ServiceAccount resource being referred to.

        :schema: EcrAuthorizationTokenSpecAuthJwtServiceAccountRef#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def audiences(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Audience specifies the ``aud`` claim for the service account token If the service account uses a well-known annotation for e.g. IRSA or GCP Workload Identity then this audiences will be appended to the list.

        :schema: EcrAuthorizationTokenSpecAuthJwtServiceAccountRef#audiences
        '''
        result = self._values.get("audiences")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: EcrAuthorizationTokenSpecAuthJwtServiceAccountRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "EcrAuthorizationTokenSpecAuthJwtServiceAccountRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.EcrAuthorizationTokenSpecAuthSecretRef",
    jsii_struct_bases=[],
    name_mapping={
        "access_key_id_secret_ref": "accessKeyIdSecretRef",
        "secret_access_key_secret_ref": "secretAccessKeySecretRef",
        "session_token_secret_ref": "sessionTokenSecretRef",
    },
)
class EcrAuthorizationTokenSpecAuthSecretRef:
    def __init__(
        self,
        *,
        access_key_id_secret_ref: typing.Optional[typing.Union["EcrAuthorizationTokenSpecAuthSecretRefAccessKeyIdSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
        secret_access_key_secret_ref: typing.Optional[typing.Union["EcrAuthorizationTokenSpecAuthSecretRefSecretAccessKeySecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
        session_token_secret_ref: typing.Optional[typing.Union["EcrAuthorizationTokenSpecAuthSecretRefSessionTokenSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''AWSAuthSecretRef holds secret references for AWS credentials both AccessKeyID and SecretAccessKey must be defined in order to properly authenticate.

        :param access_key_id_secret_ref: The AccessKeyID is used for authentication.
        :param secret_access_key_secret_ref: The SecretAccessKey is used for authentication.
        :param session_token_secret_ref: The SessionToken used for authentication This must be defined if AccessKeyID and SecretAccessKey are temporary credentials see: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html.

        :schema: EcrAuthorizationTokenSpecAuthSecretRef
        '''
        if isinstance(access_key_id_secret_ref, dict):
            access_key_id_secret_ref = EcrAuthorizationTokenSpecAuthSecretRefAccessKeyIdSecretRef(**access_key_id_secret_ref)
        if isinstance(secret_access_key_secret_ref, dict):
            secret_access_key_secret_ref = EcrAuthorizationTokenSpecAuthSecretRefSecretAccessKeySecretRef(**secret_access_key_secret_ref)
        if isinstance(session_token_secret_ref, dict):
            session_token_secret_ref = EcrAuthorizationTokenSpecAuthSecretRefSessionTokenSecretRef(**session_token_secret_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__bf78f11dcfa2cd9f8940d60487a5c7d2f01d9a4dd8d77e4bf8dcdd56085c7d95)
            check_type(argname="argument access_key_id_secret_ref", value=access_key_id_secret_ref, expected_type=type_hints["access_key_id_secret_ref"])
            check_type(argname="argument secret_access_key_secret_ref", value=secret_access_key_secret_ref, expected_type=type_hints["secret_access_key_secret_ref"])
            check_type(argname="argument session_token_secret_ref", value=session_token_secret_ref, expected_type=type_hints["session_token_secret_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if access_key_id_secret_ref is not None:
            self._values["access_key_id_secret_ref"] = access_key_id_secret_ref
        if secret_access_key_secret_ref is not None:
            self._values["secret_access_key_secret_ref"] = secret_access_key_secret_ref
        if session_token_secret_ref is not None:
            self._values["session_token_secret_ref"] = session_token_secret_ref

    @builtins.property
    def access_key_id_secret_ref(
        self,
    ) -> typing.Optional["EcrAuthorizationTokenSpecAuthSecretRefAccessKeyIdSecretRef"]:
        '''The AccessKeyID is used for authentication.

        :schema: EcrAuthorizationTokenSpecAuthSecretRef#accessKeyIDSecretRef
        '''
        result = self._values.get("access_key_id_secret_ref")
        return typing.cast(typing.Optional["EcrAuthorizationTokenSpecAuthSecretRefAccessKeyIdSecretRef"], result)

    @builtins.property
    def secret_access_key_secret_ref(
        self,
    ) -> typing.Optional["EcrAuthorizationTokenSpecAuthSecretRefSecretAccessKeySecretRef"]:
        '''The SecretAccessKey is used for authentication.

        :schema: EcrAuthorizationTokenSpecAuthSecretRef#secretAccessKeySecretRef
        '''
        result = self._values.get("secret_access_key_secret_ref")
        return typing.cast(typing.Optional["EcrAuthorizationTokenSpecAuthSecretRefSecretAccessKeySecretRef"], result)

    @builtins.property
    def session_token_secret_ref(
        self,
    ) -> typing.Optional["EcrAuthorizationTokenSpecAuthSecretRefSessionTokenSecretRef"]:
        '''The SessionToken used for authentication This must be defined if AccessKeyID and SecretAccessKey are temporary credentials see: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html.

        :schema: EcrAuthorizationTokenSpecAuthSecretRef#sessionTokenSecretRef
        '''
        result = self._values.get("session_token_secret_ref")
        return typing.cast(typing.Optional["EcrAuthorizationTokenSpecAuthSecretRefSessionTokenSecretRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "EcrAuthorizationTokenSpecAuthSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.EcrAuthorizationTokenSpecAuthSecretRefAccessKeyIdSecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class EcrAuthorizationTokenSpecAuthSecretRefAccessKeyIdSecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''The AccessKeyID is used for authentication.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: EcrAuthorizationTokenSpecAuthSecretRefAccessKeyIdSecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__3d68e594efb66902569f54fe98715ea46d6ba8ca83b27e99b98f38a8ade43a65)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: EcrAuthorizationTokenSpecAuthSecretRefAccessKeyIdSecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: EcrAuthorizationTokenSpecAuthSecretRefAccessKeyIdSecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: EcrAuthorizationTokenSpecAuthSecretRefAccessKeyIdSecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "EcrAuthorizationTokenSpecAuthSecretRefAccessKeyIdSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.EcrAuthorizationTokenSpecAuthSecretRefSecretAccessKeySecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class EcrAuthorizationTokenSpecAuthSecretRefSecretAccessKeySecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''The SecretAccessKey is used for authentication.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: EcrAuthorizationTokenSpecAuthSecretRefSecretAccessKeySecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__054461f11158e4dc81b90d77e99ce0fe74d37b917fedbcb4284ed8881d1bae57)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: EcrAuthorizationTokenSpecAuthSecretRefSecretAccessKeySecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: EcrAuthorizationTokenSpecAuthSecretRefSecretAccessKeySecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: EcrAuthorizationTokenSpecAuthSecretRefSecretAccessKeySecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "EcrAuthorizationTokenSpecAuthSecretRefSecretAccessKeySecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.EcrAuthorizationTokenSpecAuthSecretRefSessionTokenSecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class EcrAuthorizationTokenSpecAuthSecretRefSessionTokenSecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''The SessionToken used for authentication This must be defined if AccessKeyID and SecretAccessKey are temporary credentials see: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: EcrAuthorizationTokenSpecAuthSecretRefSessionTokenSecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__1b8c5ee22e2427c12cabf67d5cf6b1a7cdc91842cd7af9a753bc42ce2dd80e5d)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: EcrAuthorizationTokenSpecAuthSecretRefSessionTokenSecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: EcrAuthorizationTokenSpecAuthSecretRefSessionTokenSecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: EcrAuthorizationTokenSpecAuthSecretRefSessionTokenSecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "EcrAuthorizationTokenSpecAuthSecretRefSessionTokenSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class Fake(
    _cdk8s_d3d9af27.ApiObject,
    metaclass=jsii.JSIIMeta,
    jsii_type="ioexternal-secretsgenerators.Fake",
):
    '''Fake generator is used for testing.

    It lets you define
    a static set of credentials that is always returned.

    :schema: Fake
    '''

    def __init__(
        self,
        scope: _constructs_77d1e7e8.Construct,
        id: builtins.str,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["FakeSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Defines a "Fake" API object.

        :param scope: the scope in which to define this object.
        :param id: a scope-local name for the object.
        :param metadata: 
        :param spec: FakeSpec contains the static data.
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__b57d91e19285b6a8a017d2a83639b2a99389613e7a3f5ca4ebf7e0e4a717f1f1)
            check_type(argname="argument scope", value=scope, expected_type=type_hints["scope"])
            check_type(argname="argument id", value=id, expected_type=type_hints["id"])
        props = FakeProps(metadata=metadata, spec=spec)

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="manifest")
    @builtins.classmethod
    def manifest(
        cls,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["FakeSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> typing.Any:
        '''Renders a Kubernetes manifest for "Fake".

        This can be used to inline resource manifests inside other objects (e.g. as templates).

        :param metadata: 
        :param spec: FakeSpec contains the static data.
        '''
        props = FakeProps(metadata=metadata, spec=spec)

        return typing.cast(typing.Any, jsii.sinvoke(cls, "manifest", [props]))

    @jsii.member(jsii_name="toJson")
    def to_json(self) -> typing.Any:
        '''Renders the object to Kubernetes JSON.'''
        return typing.cast(typing.Any, jsii.invoke(self, "toJson", []))

    @jsii.python.classproperty
    @jsii.member(jsii_name="GVK")
    def GVK(cls) -> _cdk8s_d3d9af27.GroupVersionKind:
        '''Returns the apiVersion and kind for "Fake".'''
        return typing.cast(_cdk8s_d3d9af27.GroupVersionKind, jsii.sget(cls, "GVK"))


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.FakeProps",
    jsii_struct_bases=[],
    name_mapping={"metadata": "metadata", "spec": "spec"},
)
class FakeProps:
    def __init__(
        self,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["FakeSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Fake generator is used for testing.

        It lets you define
        a static set of credentials that is always returned.

        :param metadata: 
        :param spec: FakeSpec contains the static data.

        :schema: Fake
        '''
        if isinstance(metadata, dict):
            metadata = _cdk8s_d3d9af27.ApiObjectMetadata(**metadata)
        if isinstance(spec, dict):
            spec = FakeSpec(**spec)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__f6bcab3c7c36ee2c872120a58cef6b1878a6276f893325a6ff369928c8e1c75c)
            check_type(argname="argument metadata", value=metadata, expected_type=type_hints["metadata"])
            check_type(argname="argument spec", value=spec, expected_type=type_hints["spec"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if metadata is not None:
            self._values["metadata"] = metadata
        if spec is not None:
            self._values["spec"] = spec

    @builtins.property
    def metadata(self) -> typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata]:
        '''
        :schema: Fake#metadata
        '''
        result = self._values.get("metadata")
        return typing.cast(typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata], result)

    @builtins.property
    def spec(self) -> typing.Optional["FakeSpec"]:
        '''FakeSpec contains the static data.

        :schema: Fake#spec
        '''
        result = self._values.get("spec")
        return typing.cast(typing.Optional["FakeSpec"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "FakeProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.FakeSpec",
    jsii_struct_bases=[],
    name_mapping={"controller": "controller", "data": "data"},
)
class FakeSpec:
    def __init__(
        self,
        *,
        controller: typing.Optional[builtins.str] = None,
        data: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''FakeSpec contains the static data.

        :param controller: Used to select the correct ESO controller (think: ingress.ingressClassName) The ESO controller is instantiated with a specific controller name and filters VDS based on this property.
        :param data: Data defines the static data returned by this generator.

        :schema: FakeSpec
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__44ead58e4ef3208607864017deeaf29547ca20b830ae43c943a9ea1bb647a2be)
            check_type(argname="argument controller", value=controller, expected_type=type_hints["controller"])
            check_type(argname="argument data", value=data, expected_type=type_hints["data"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if controller is not None:
            self._values["controller"] = controller
        if data is not None:
            self._values["data"] = data

    @builtins.property
    def controller(self) -> typing.Optional[builtins.str]:
        '''Used to select the correct ESO controller (think: ingress.ingressClassName) The ESO controller is instantiated with a specific controller name and filters VDS based on this property.

        :schema: FakeSpec#controller
        '''
        result = self._values.get("controller")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def data(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Data defines the static data returned by this generator.

        :schema: FakeSpec#data
        '''
        result = self._values.get("data")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "FakeSpec(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class GcrAccessToken(
    _cdk8s_d3d9af27.ApiObject,
    metaclass=jsii.JSIIMeta,
    jsii_type="ioexternal-secretsgenerators.GcrAccessToken",
):
    '''GCRAccessToken generates an GCP access token that can be used to authenticate with GCR.

    :schema: GCRAccessToken
    '''

    def __init__(
        self,
        scope: _constructs_77d1e7e8.Construct,
        id: builtins.str,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["GcrAccessTokenSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Defines a "GCRAccessToken" API object.

        :param scope: the scope in which to define this object.
        :param id: a scope-local name for the object.
        :param metadata: 
        :param spec: 
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__b80007d0392365dc569ce8bd4015fe900acd943c3d36aa66178ec2ac84597b7f)
            check_type(argname="argument scope", value=scope, expected_type=type_hints["scope"])
            check_type(argname="argument id", value=id, expected_type=type_hints["id"])
        props = GcrAccessTokenProps(metadata=metadata, spec=spec)

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="manifest")
    @builtins.classmethod
    def manifest(
        cls,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["GcrAccessTokenSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> typing.Any:
        '''Renders a Kubernetes manifest for "GCRAccessToken".

        This can be used to inline resource manifests inside other objects (e.g. as templates).

        :param metadata: 
        :param spec: 
        '''
        props = GcrAccessTokenProps(metadata=metadata, spec=spec)

        return typing.cast(typing.Any, jsii.sinvoke(cls, "manifest", [props]))

    @jsii.member(jsii_name="toJson")
    def to_json(self) -> typing.Any:
        '''Renders the object to Kubernetes JSON.'''
        return typing.cast(typing.Any, jsii.invoke(self, "toJson", []))

    @jsii.python.classproperty
    @jsii.member(jsii_name="GVK")
    def GVK(cls) -> _cdk8s_d3d9af27.GroupVersionKind:
        '''Returns the apiVersion and kind for "GCRAccessToken".'''
        return typing.cast(_cdk8s_d3d9af27.GroupVersionKind, jsii.sget(cls, "GVK"))


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.GcrAccessTokenProps",
    jsii_struct_bases=[],
    name_mapping={"metadata": "metadata", "spec": "spec"},
)
class GcrAccessTokenProps:
    def __init__(
        self,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["GcrAccessTokenSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''GCRAccessToken generates an GCP access token that can be used to authenticate with GCR.

        :param metadata: 
        :param spec: 

        :schema: GCRAccessToken
        '''
        if isinstance(metadata, dict):
            metadata = _cdk8s_d3d9af27.ApiObjectMetadata(**metadata)
        if isinstance(spec, dict):
            spec = GcrAccessTokenSpec(**spec)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__1ebf58f1879563b8440f47f35b33c5f08df60cc497c53708ec8773b08a2c3b3c)
            check_type(argname="argument metadata", value=metadata, expected_type=type_hints["metadata"])
            check_type(argname="argument spec", value=spec, expected_type=type_hints["spec"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if metadata is not None:
            self._values["metadata"] = metadata
        if spec is not None:
            self._values["spec"] = spec

    @builtins.property
    def metadata(self) -> typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata]:
        '''
        :schema: GCRAccessToken#metadata
        '''
        result = self._values.get("metadata")
        return typing.cast(typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata], result)

    @builtins.property
    def spec(self) -> typing.Optional["GcrAccessTokenSpec"]:
        '''
        :schema: GCRAccessToken#spec
        '''
        result = self._values.get("spec")
        return typing.cast(typing.Optional["GcrAccessTokenSpec"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "GcrAccessTokenProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.GcrAccessTokenSpec",
    jsii_struct_bases=[],
    name_mapping={"auth": "auth", "project_id": "projectId"},
)
class GcrAccessTokenSpec:
    def __init__(
        self,
        *,
        auth: typing.Union["GcrAccessTokenSpecAuth", typing.Dict[builtins.str, typing.Any]],
        project_id: builtins.str,
    ) -> None:
        '''
        :param auth: Auth defines the means for authenticating with GCP.
        :param project_id: ProjectID defines which project to use to authenticate with.

        :schema: GcrAccessTokenSpec
        '''
        if isinstance(auth, dict):
            auth = GcrAccessTokenSpecAuth(**auth)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__a01287b24f44728bc8b80776e9475534ab7affaf0f4524cbf7addab8e431089e)
            check_type(argname="argument auth", value=auth, expected_type=type_hints["auth"])
            check_type(argname="argument project_id", value=project_id, expected_type=type_hints["project_id"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "auth": auth,
            "project_id": project_id,
        }

    @builtins.property
    def auth(self) -> "GcrAccessTokenSpecAuth":
        '''Auth defines the means for authenticating with GCP.

        :schema: GcrAccessTokenSpec#auth
        '''
        result = self._values.get("auth")
        assert result is not None, "Required property 'auth' is missing"
        return typing.cast("GcrAccessTokenSpecAuth", result)

    @builtins.property
    def project_id(self) -> builtins.str:
        '''ProjectID defines which project to use to authenticate with.

        :schema: GcrAccessTokenSpec#projectID
        '''
        result = self._values.get("project_id")
        assert result is not None, "Required property 'project_id' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "GcrAccessTokenSpec(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.GcrAccessTokenSpecAuth",
    jsii_struct_bases=[],
    name_mapping={"secret_ref": "secretRef", "workload_identity": "workloadIdentity"},
)
class GcrAccessTokenSpecAuth:
    def __init__(
        self,
        *,
        secret_ref: typing.Optional[typing.Union["GcrAccessTokenSpecAuthSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
        workload_identity: typing.Optional[typing.Union["GcrAccessTokenSpecAuthWorkloadIdentity", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Auth defines the means for authenticating with GCP.

        :param secret_ref: 
        :param workload_identity: 

        :schema: GcrAccessTokenSpecAuth
        '''
        if isinstance(secret_ref, dict):
            secret_ref = GcrAccessTokenSpecAuthSecretRef(**secret_ref)
        if isinstance(workload_identity, dict):
            workload_identity = GcrAccessTokenSpecAuthWorkloadIdentity(**workload_identity)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__93eb12ae2068134fa04136f7c937cab838ac29d82534e5b5803842066fae6e48)
            check_type(argname="argument secret_ref", value=secret_ref, expected_type=type_hints["secret_ref"])
            check_type(argname="argument workload_identity", value=workload_identity, expected_type=type_hints["workload_identity"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if secret_ref is not None:
            self._values["secret_ref"] = secret_ref
        if workload_identity is not None:
            self._values["workload_identity"] = workload_identity

    @builtins.property
    def secret_ref(self) -> typing.Optional["GcrAccessTokenSpecAuthSecretRef"]:
        '''
        :schema: GcrAccessTokenSpecAuth#secretRef
        '''
        result = self._values.get("secret_ref")
        return typing.cast(typing.Optional["GcrAccessTokenSpecAuthSecretRef"], result)

    @builtins.property
    def workload_identity(
        self,
    ) -> typing.Optional["GcrAccessTokenSpecAuthWorkloadIdentity"]:
        '''
        :schema: GcrAccessTokenSpecAuth#workloadIdentity
        '''
        result = self._values.get("workload_identity")
        return typing.cast(typing.Optional["GcrAccessTokenSpecAuthWorkloadIdentity"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "GcrAccessTokenSpecAuth(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.GcrAccessTokenSpecAuthSecretRef",
    jsii_struct_bases=[],
    name_mapping={"secret_access_key_secret_ref": "secretAccessKeySecretRef"},
)
class GcrAccessTokenSpecAuthSecretRef:
    def __init__(
        self,
        *,
        secret_access_key_secret_ref: typing.Optional[typing.Union["GcrAccessTokenSpecAuthSecretRefSecretAccessKeySecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''
        :param secret_access_key_secret_ref: The SecretAccessKey is used for authentication.

        :schema: GcrAccessTokenSpecAuthSecretRef
        '''
        if isinstance(secret_access_key_secret_ref, dict):
            secret_access_key_secret_ref = GcrAccessTokenSpecAuthSecretRefSecretAccessKeySecretRef(**secret_access_key_secret_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__f65d1a322d6d23716a2925defeb951fc75b6741a65f92879df1e71df097441a8)
            check_type(argname="argument secret_access_key_secret_ref", value=secret_access_key_secret_ref, expected_type=type_hints["secret_access_key_secret_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if secret_access_key_secret_ref is not None:
            self._values["secret_access_key_secret_ref"] = secret_access_key_secret_ref

    @builtins.property
    def secret_access_key_secret_ref(
        self,
    ) -> typing.Optional["GcrAccessTokenSpecAuthSecretRefSecretAccessKeySecretRef"]:
        '''The SecretAccessKey is used for authentication.

        :schema: GcrAccessTokenSpecAuthSecretRef#secretAccessKeySecretRef
        '''
        result = self._values.get("secret_access_key_secret_ref")
        return typing.cast(typing.Optional["GcrAccessTokenSpecAuthSecretRefSecretAccessKeySecretRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "GcrAccessTokenSpecAuthSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.GcrAccessTokenSpecAuthSecretRefSecretAccessKeySecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class GcrAccessTokenSpecAuthSecretRefSecretAccessKeySecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''The SecretAccessKey is used for authentication.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: GcrAccessTokenSpecAuthSecretRefSecretAccessKeySecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__cbabefd39b46e713e4e457a716bfc18a7f475fccb20674d7eb3a5cdf17b09f7e)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: GcrAccessTokenSpecAuthSecretRefSecretAccessKeySecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: GcrAccessTokenSpecAuthSecretRefSecretAccessKeySecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: GcrAccessTokenSpecAuthSecretRefSecretAccessKeySecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "GcrAccessTokenSpecAuthSecretRefSecretAccessKeySecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.GcrAccessTokenSpecAuthWorkloadIdentity",
    jsii_struct_bases=[],
    name_mapping={
        "cluster_location": "clusterLocation",
        "cluster_name": "clusterName",
        "service_account_ref": "serviceAccountRef",
        "cluster_project_id": "clusterProjectId",
    },
)
class GcrAccessTokenSpecAuthWorkloadIdentity:
    def __init__(
        self,
        *,
        cluster_location: builtins.str,
        cluster_name: builtins.str,
        service_account_ref: typing.Union["GcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef", typing.Dict[builtins.str, typing.Any]],
        cluster_project_id: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param cluster_location: 
        :param cluster_name: 
        :param service_account_ref: A reference to a ServiceAccount resource.
        :param cluster_project_id: 

        :schema: GcrAccessTokenSpecAuthWorkloadIdentity
        '''
        if isinstance(service_account_ref, dict):
            service_account_ref = GcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef(**service_account_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__199ea61bce5117046e2f5da4c5a50856e146ebaa2773f338ff7d01e23079571f)
            check_type(argname="argument cluster_location", value=cluster_location, expected_type=type_hints["cluster_location"])
            check_type(argname="argument cluster_name", value=cluster_name, expected_type=type_hints["cluster_name"])
            check_type(argname="argument service_account_ref", value=service_account_ref, expected_type=type_hints["service_account_ref"])
            check_type(argname="argument cluster_project_id", value=cluster_project_id, expected_type=type_hints["cluster_project_id"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "cluster_location": cluster_location,
            "cluster_name": cluster_name,
            "service_account_ref": service_account_ref,
        }
        if cluster_project_id is not None:
            self._values["cluster_project_id"] = cluster_project_id

    @builtins.property
    def cluster_location(self) -> builtins.str:
        '''
        :schema: GcrAccessTokenSpecAuthWorkloadIdentity#clusterLocation
        '''
        result = self._values.get("cluster_location")
        assert result is not None, "Required property 'cluster_location' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def cluster_name(self) -> builtins.str:
        '''
        :schema: GcrAccessTokenSpecAuthWorkloadIdentity#clusterName
        '''
        result = self._values.get("cluster_name")
        assert result is not None, "Required property 'cluster_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def service_account_ref(
        self,
    ) -> "GcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef":
        '''A reference to a ServiceAccount resource.

        :schema: GcrAccessTokenSpecAuthWorkloadIdentity#serviceAccountRef
        '''
        result = self._values.get("service_account_ref")
        assert result is not None, "Required property 'service_account_ref' is missing"
        return typing.cast("GcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef", result)

    @builtins.property
    def cluster_project_id(self) -> typing.Optional[builtins.str]:
        '''
        :schema: GcrAccessTokenSpecAuthWorkloadIdentity#clusterProjectID
        '''
        result = self._values.get("cluster_project_id")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "GcrAccessTokenSpecAuthWorkloadIdentity(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.GcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "audiences": "audiences", "namespace": "namespace"},
)
class GcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef:
    def __init__(
        self,
        *,
        name: builtins.str,
        audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''A reference to a ServiceAccount resource.

        :param name: The name of the ServiceAccount resource being referred to.
        :param audiences: Audience specifies the ``aud`` claim for the service account token If the service account uses a well-known annotation for e.g. IRSA or GCP Workload Identity then this audiences will be appended to the list.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: GcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__4f74d21068366cc4deb9b1d016fb257384b4390cdceab57845386c22ae854561)
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument audiences", value=audiences, expected_type=type_hints["audiences"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "name": name,
        }
        if audiences is not None:
            self._values["audiences"] = audiences
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the ServiceAccount resource being referred to.

        :schema: GcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def audiences(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Audience specifies the ``aud`` claim for the service account token If the service account uses a well-known annotation for e.g. IRSA or GCP Workload Identity then this audiences will be appended to the list.

        :schema: GcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef#audiences
        '''
        result = self._values.get("audiences")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: GcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "GcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class GeneratorState(
    _cdk8s_d3d9af27.ApiObject,
    metaclass=jsii.JSIIMeta,
    jsii_type="ioexternal-secretsgenerators.GeneratorState",
):
    '''
    :schema: GeneratorState
    '''

    def __init__(
        self,
        scope: _constructs_77d1e7e8.Construct,
        id: builtins.str,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["GeneratorStateSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Defines a "GeneratorState" API object.

        :param scope: the scope in which to define this object.
        :param id: a scope-local name for the object.
        :param metadata: 
        :param spec: 
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__958486a855120fc7a31aee0ba4cca65a04bf9a182445fbe480e553b98ccd9036)
            check_type(argname="argument scope", value=scope, expected_type=type_hints["scope"])
            check_type(argname="argument id", value=id, expected_type=type_hints["id"])
        props = GeneratorStateProps(metadata=metadata, spec=spec)

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="manifest")
    @builtins.classmethod
    def manifest(
        cls,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["GeneratorStateSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> typing.Any:
        '''Renders a Kubernetes manifest for "GeneratorState".

        This can be used to inline resource manifests inside other objects (e.g. as templates).

        :param metadata: 
        :param spec: 
        '''
        props = GeneratorStateProps(metadata=metadata, spec=spec)

        return typing.cast(typing.Any, jsii.sinvoke(cls, "manifest", [props]))

    @jsii.member(jsii_name="toJson")
    def to_json(self) -> typing.Any:
        '''Renders the object to Kubernetes JSON.'''
        return typing.cast(typing.Any, jsii.invoke(self, "toJson", []))

    @jsii.python.classproperty
    @jsii.member(jsii_name="GVK")
    def GVK(cls) -> _cdk8s_d3d9af27.GroupVersionKind:
        '''Returns the apiVersion and kind for "GeneratorState".'''
        return typing.cast(_cdk8s_d3d9af27.GroupVersionKind, jsii.sget(cls, "GVK"))


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.GeneratorStateProps",
    jsii_struct_bases=[],
    name_mapping={"metadata": "metadata", "spec": "spec"},
)
class GeneratorStateProps:
    def __init__(
        self,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["GeneratorStateSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''
        :param metadata: 
        :param spec: 

        :schema: GeneratorState
        '''
        if isinstance(metadata, dict):
            metadata = _cdk8s_d3d9af27.ApiObjectMetadata(**metadata)
        if isinstance(spec, dict):
            spec = GeneratorStateSpec(**spec)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__64f82fa95da182d383bede8cfe8bee7ac5e64f879b5ea01270eecda15719f058)
            check_type(argname="argument metadata", value=metadata, expected_type=type_hints["metadata"])
            check_type(argname="argument spec", value=spec, expected_type=type_hints["spec"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if metadata is not None:
            self._values["metadata"] = metadata
        if spec is not None:
            self._values["spec"] = spec

    @builtins.property
    def metadata(self) -> typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata]:
        '''
        :schema: GeneratorState#metadata
        '''
        result = self._values.get("metadata")
        return typing.cast(typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata], result)

    @builtins.property
    def spec(self) -> typing.Optional["GeneratorStateSpec"]:
        '''
        :schema: GeneratorState#spec
        '''
        result = self._values.get("spec")
        return typing.cast(typing.Optional["GeneratorStateSpec"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "GeneratorStateProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.GeneratorStateSpec",
    jsii_struct_bases=[],
    name_mapping={
        "resource": "resource",
        "state": "state",
        "garbage_collection_deadline": "garbageCollectionDeadline",
    },
)
class GeneratorStateSpec:
    def __init__(
        self,
        *,
        resource: typing.Any,
        state: typing.Any,
        garbage_collection_deadline: typing.Optional[datetime.datetime] = None,
    ) -> None:
        '''
        :param resource: Resource is the generator manifest that produced the state. It is a snapshot of the generator manifest at the time the state was produced. This manifest will be used to delete the resource. Any configuration that is referenced in the manifest should be available at the time of garbage collection. If that is not the case deletion will be blocked by a finalizer.
        :param state: State is the state that was produced by the generator implementation.
        :param garbage_collection_deadline: GarbageCollectionDeadline is the time after which the generator state will be deleted. It is set by the controller which creates the generator state and can be set configured by the user. If the garbage collection deadline is not set the generator state will not be deleted.

        :schema: GeneratorStateSpec
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__5d80cd3e33b0c4a2ec892301c844aee6f41a860238c42c36e51455f76caf187a)
            check_type(argname="argument resource", value=resource, expected_type=type_hints["resource"])
            check_type(argname="argument state", value=state, expected_type=type_hints["state"])
            check_type(argname="argument garbage_collection_deadline", value=garbage_collection_deadline, expected_type=type_hints["garbage_collection_deadline"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "resource": resource,
            "state": state,
        }
        if garbage_collection_deadline is not None:
            self._values["garbage_collection_deadline"] = garbage_collection_deadline

    @builtins.property
    def resource(self) -> typing.Any:
        '''Resource is the generator manifest that produced the state.

        It is a snapshot of the generator manifest at the time the state was produced.
        This manifest will be used to delete the resource. Any configuration that is referenced
        in the manifest should be available at the time of garbage collection. If that is not the case deletion will
        be blocked by a finalizer.

        :schema: GeneratorStateSpec#resource
        '''
        result = self._values.get("resource")
        assert result is not None, "Required property 'resource' is missing"
        return typing.cast(typing.Any, result)

    @builtins.property
    def state(self) -> typing.Any:
        '''State is the state that was produced by the generator implementation.

        :schema: GeneratorStateSpec#state
        '''
        result = self._values.get("state")
        assert result is not None, "Required property 'state' is missing"
        return typing.cast(typing.Any, result)

    @builtins.property
    def garbage_collection_deadline(self) -> typing.Optional[datetime.datetime]:
        '''GarbageCollectionDeadline is the time after which the generator state will be deleted.

        It is set by the controller which creates the generator state and
        can be set configured by the user.
        If the garbage collection deadline is not set the generator state will not be deleted.

        :schema: GeneratorStateSpec#garbageCollectionDeadline
        '''
        result = self._values.get("garbage_collection_deadline")
        return typing.cast(typing.Optional[datetime.datetime], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "GeneratorStateSpec(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class GithubAccessToken(
    _cdk8s_d3d9af27.ApiObject,
    metaclass=jsii.JSIIMeta,
    jsii_type="ioexternal-secretsgenerators.GithubAccessToken",
):
    '''GithubAccessToken generates ghs_ accessToken.

    :schema: GithubAccessToken
    '''

    def __init__(
        self,
        scope: _constructs_77d1e7e8.Construct,
        id: builtins.str,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["GithubAccessTokenSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Defines a "GithubAccessToken" API object.

        :param scope: the scope in which to define this object.
        :param id: a scope-local name for the object.
        :param metadata: 
        :param spec: 
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__4a77570c44994c62f1495ca397b0a38a34f7359399b5a5c444421df203d8116b)
            check_type(argname="argument scope", value=scope, expected_type=type_hints["scope"])
            check_type(argname="argument id", value=id, expected_type=type_hints["id"])
        props = GithubAccessTokenProps(metadata=metadata, spec=spec)

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="manifest")
    @builtins.classmethod
    def manifest(
        cls,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["GithubAccessTokenSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> typing.Any:
        '''Renders a Kubernetes manifest for "GithubAccessToken".

        This can be used to inline resource manifests inside other objects (e.g. as templates).

        :param metadata: 
        :param spec: 
        '''
        props = GithubAccessTokenProps(metadata=metadata, spec=spec)

        return typing.cast(typing.Any, jsii.sinvoke(cls, "manifest", [props]))

    @jsii.member(jsii_name="toJson")
    def to_json(self) -> typing.Any:
        '''Renders the object to Kubernetes JSON.'''
        return typing.cast(typing.Any, jsii.invoke(self, "toJson", []))

    @jsii.python.classproperty
    @jsii.member(jsii_name="GVK")
    def GVK(cls) -> _cdk8s_d3d9af27.GroupVersionKind:
        '''Returns the apiVersion and kind for "GithubAccessToken".'''
        return typing.cast(_cdk8s_d3d9af27.GroupVersionKind, jsii.sget(cls, "GVK"))


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.GithubAccessTokenProps",
    jsii_struct_bases=[],
    name_mapping={"metadata": "metadata", "spec": "spec"},
)
class GithubAccessTokenProps:
    def __init__(
        self,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["GithubAccessTokenSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''GithubAccessToken generates ghs_ accessToken.

        :param metadata: 
        :param spec: 

        :schema: GithubAccessToken
        '''
        if isinstance(metadata, dict):
            metadata = _cdk8s_d3d9af27.ApiObjectMetadata(**metadata)
        if isinstance(spec, dict):
            spec = GithubAccessTokenSpec(**spec)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__03fef391cab2e0e91a690c6535a6c54804108aecbfe23f30906d896706375319)
            check_type(argname="argument metadata", value=metadata, expected_type=type_hints["metadata"])
            check_type(argname="argument spec", value=spec, expected_type=type_hints["spec"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if metadata is not None:
            self._values["metadata"] = metadata
        if spec is not None:
            self._values["spec"] = spec

    @builtins.property
    def metadata(self) -> typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata]:
        '''
        :schema: GithubAccessToken#metadata
        '''
        result = self._values.get("metadata")
        return typing.cast(typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata], result)

    @builtins.property
    def spec(self) -> typing.Optional["GithubAccessTokenSpec"]:
        '''
        :schema: GithubAccessToken#spec
        '''
        result = self._values.get("spec")
        return typing.cast(typing.Optional["GithubAccessTokenSpec"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "GithubAccessTokenProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.GithubAccessTokenSpec",
    jsii_struct_bases=[],
    name_mapping={
        "app_id": "appId",
        "auth": "auth",
        "install_id": "installId",
        "permissions": "permissions",
        "repositories": "repositories",
        "url": "url",
    },
)
class GithubAccessTokenSpec:
    def __init__(
        self,
        *,
        app_id: builtins.str,
        auth: typing.Union["GithubAccessTokenSpecAuth", typing.Dict[builtins.str, typing.Any]],
        install_id: builtins.str,
        permissions: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        repositories: typing.Optional[typing.Sequence[builtins.str]] = None,
        url: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param app_id: 
        :param auth: Auth configures how ESO authenticates with a Github instance.
        :param install_id: 
        :param permissions: Map of permissions the token will have. If omitted, defaults to all permissions the GitHub App has.
        :param repositories: List of repositories the token will have access to. If omitted, defaults to all repositories the GitHub App is installed to.
        :param url: URL configures the Github instance URL. Defaults to https://github.com/. Default: https://github.com/.

        :schema: GithubAccessTokenSpec
        '''
        if isinstance(auth, dict):
            auth = GithubAccessTokenSpecAuth(**auth)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__7de89f6322b407b1d8de8e9206a8daa3d6a9aeefc3facc2b15cd3f2343d619bb)
            check_type(argname="argument app_id", value=app_id, expected_type=type_hints["app_id"])
            check_type(argname="argument auth", value=auth, expected_type=type_hints["auth"])
            check_type(argname="argument install_id", value=install_id, expected_type=type_hints["install_id"])
            check_type(argname="argument permissions", value=permissions, expected_type=type_hints["permissions"])
            check_type(argname="argument repositories", value=repositories, expected_type=type_hints["repositories"])
            check_type(argname="argument url", value=url, expected_type=type_hints["url"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "app_id": app_id,
            "auth": auth,
            "install_id": install_id,
        }
        if permissions is not None:
            self._values["permissions"] = permissions
        if repositories is not None:
            self._values["repositories"] = repositories
        if url is not None:
            self._values["url"] = url

    @builtins.property
    def app_id(self) -> builtins.str:
        '''
        :schema: GithubAccessTokenSpec#appID
        '''
        result = self._values.get("app_id")
        assert result is not None, "Required property 'app_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def auth(self) -> "GithubAccessTokenSpecAuth":
        '''Auth configures how ESO authenticates with a Github instance.

        :schema: GithubAccessTokenSpec#auth
        '''
        result = self._values.get("auth")
        assert result is not None, "Required property 'auth' is missing"
        return typing.cast("GithubAccessTokenSpecAuth", result)

    @builtins.property
    def install_id(self) -> builtins.str:
        '''
        :schema: GithubAccessTokenSpec#installID
        '''
        result = self._values.get("install_id")
        assert result is not None, "Required property 'install_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def permissions(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Map of permissions the token will have.

        If omitted, defaults to all permissions the GitHub App has.

        :schema: GithubAccessTokenSpec#permissions
        '''
        result = self._values.get("permissions")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def repositories(self) -> typing.Optional[typing.List[builtins.str]]:
        '''List of repositories the token will have access to.

        If omitted, defaults to all repositories the GitHub App
        is installed to.

        :schema: GithubAccessTokenSpec#repositories
        '''
        result = self._values.get("repositories")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def url(self) -> typing.Optional[builtins.str]:
        '''URL configures the Github instance URL.

        Defaults to https://github.com/.

        :default: https://github.com/.

        :schema: GithubAccessTokenSpec#url
        '''
        result = self._values.get("url")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "GithubAccessTokenSpec(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.GithubAccessTokenSpecAuth",
    jsii_struct_bases=[],
    name_mapping={"private_key": "privateKey"},
)
class GithubAccessTokenSpecAuth:
    def __init__(
        self,
        *,
        private_key: typing.Union["GithubAccessTokenSpecAuthPrivateKey", typing.Dict[builtins.str, typing.Any]],
    ) -> None:
        '''Auth configures how ESO authenticates with a Github instance.

        :param private_key: 

        :schema: GithubAccessTokenSpecAuth
        '''
        if isinstance(private_key, dict):
            private_key = GithubAccessTokenSpecAuthPrivateKey(**private_key)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__eb19f408f5f81b80adaeb0752891235a4de94e26ecf80e23ae76b0df8fce09e1)
            check_type(argname="argument private_key", value=private_key, expected_type=type_hints["private_key"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "private_key": private_key,
        }

    @builtins.property
    def private_key(self) -> "GithubAccessTokenSpecAuthPrivateKey":
        '''
        :schema: GithubAccessTokenSpecAuth#privateKey
        '''
        result = self._values.get("private_key")
        assert result is not None, "Required property 'private_key' is missing"
        return typing.cast("GithubAccessTokenSpecAuthPrivateKey", result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "GithubAccessTokenSpecAuth(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.GithubAccessTokenSpecAuthPrivateKey",
    jsii_struct_bases=[],
    name_mapping={"secret_ref": "secretRef"},
)
class GithubAccessTokenSpecAuthPrivateKey:
    def __init__(
        self,
        *,
        secret_ref: typing.Union["GithubAccessTokenSpecAuthPrivateKeySecretRef", typing.Dict[builtins.str, typing.Any]],
    ) -> None:
        '''
        :param secret_ref: A reference to a specific 'key' within a Secret resource. In some instances, ``key`` is a required field.

        :schema: GithubAccessTokenSpecAuthPrivateKey
        '''
        if isinstance(secret_ref, dict):
            secret_ref = GithubAccessTokenSpecAuthPrivateKeySecretRef(**secret_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__cb39af0e0f51b28201dc29bc178b9febff7228412f055e9c07142114da340837)
            check_type(argname="argument secret_ref", value=secret_ref, expected_type=type_hints["secret_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "secret_ref": secret_ref,
        }

    @builtins.property
    def secret_ref(self) -> "GithubAccessTokenSpecAuthPrivateKeySecretRef":
        '''A reference to a specific 'key' within a Secret resource.

        In some instances, ``key`` is a required field.

        :schema: GithubAccessTokenSpecAuthPrivateKey#secretRef
        '''
        result = self._values.get("secret_ref")
        assert result is not None, "Required property 'secret_ref' is missing"
        return typing.cast("GithubAccessTokenSpecAuthPrivateKeySecretRef", result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "GithubAccessTokenSpecAuthPrivateKey(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.GithubAccessTokenSpecAuthPrivateKeySecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class GithubAccessTokenSpecAuthPrivateKeySecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''A reference to a specific 'key' within a Secret resource.

        In some instances, ``key`` is a required field.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: GithubAccessTokenSpecAuthPrivateKeySecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__f44ce4532c26c546f28a977216d68c41dc675e15baa70c2618c40a1fd97f8e6b)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: GithubAccessTokenSpecAuthPrivateKeySecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: GithubAccessTokenSpecAuthPrivateKeySecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: GithubAccessTokenSpecAuthPrivateKeySecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "GithubAccessTokenSpecAuthPrivateKeySecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class Grafana(
    _cdk8s_d3d9af27.ApiObject,
    metaclass=jsii.JSIIMeta,
    jsii_type="ioexternal-secretsgenerators.Grafana",
):
    '''
    :schema: Grafana
    '''

    def __init__(
        self,
        scope: _constructs_77d1e7e8.Construct,
        id: builtins.str,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["GrafanaSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Defines a "Grafana" API object.

        :param scope: the scope in which to define this object.
        :param id: a scope-local name for the object.
        :param metadata: 
        :param spec: GrafanaSpec controls the behavior of the grafana generator.
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__d80f5795b34eebd4414d453e74364019631d46df1d6f77332167900032b31ac2)
            check_type(argname="argument scope", value=scope, expected_type=type_hints["scope"])
            check_type(argname="argument id", value=id, expected_type=type_hints["id"])
        props = GrafanaProps(metadata=metadata, spec=spec)

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="manifest")
    @builtins.classmethod
    def manifest(
        cls,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["GrafanaSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> typing.Any:
        '''Renders a Kubernetes manifest for "Grafana".

        This can be used to inline resource manifests inside other objects (e.g. as templates).

        :param metadata: 
        :param spec: GrafanaSpec controls the behavior of the grafana generator.
        '''
        props = GrafanaProps(metadata=metadata, spec=spec)

        return typing.cast(typing.Any, jsii.sinvoke(cls, "manifest", [props]))

    @jsii.member(jsii_name="toJson")
    def to_json(self) -> typing.Any:
        '''Renders the object to Kubernetes JSON.'''
        return typing.cast(typing.Any, jsii.invoke(self, "toJson", []))

    @jsii.python.classproperty
    @jsii.member(jsii_name="GVK")
    def GVK(cls) -> _cdk8s_d3d9af27.GroupVersionKind:
        '''Returns the apiVersion and kind for "Grafana".'''
        return typing.cast(_cdk8s_d3d9af27.GroupVersionKind, jsii.sget(cls, "GVK"))


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.GrafanaProps",
    jsii_struct_bases=[],
    name_mapping={"metadata": "metadata", "spec": "spec"},
)
class GrafanaProps:
    def __init__(
        self,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["GrafanaSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''
        :param metadata: 
        :param spec: GrafanaSpec controls the behavior of the grafana generator.

        :schema: Grafana
        '''
        if isinstance(metadata, dict):
            metadata = _cdk8s_d3d9af27.ApiObjectMetadata(**metadata)
        if isinstance(spec, dict):
            spec = GrafanaSpec(**spec)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__653972c42261a54dd717de914b7983783972daddb15fd7d6225a1b5875a8244e)
            check_type(argname="argument metadata", value=metadata, expected_type=type_hints["metadata"])
            check_type(argname="argument spec", value=spec, expected_type=type_hints["spec"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if metadata is not None:
            self._values["metadata"] = metadata
        if spec is not None:
            self._values["spec"] = spec

    @builtins.property
    def metadata(self) -> typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata]:
        '''
        :schema: Grafana#metadata
        '''
        result = self._values.get("metadata")
        return typing.cast(typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata], result)

    @builtins.property
    def spec(self) -> typing.Optional["GrafanaSpec"]:
        '''GrafanaSpec controls the behavior of the grafana generator.

        :schema: Grafana#spec
        '''
        result = self._values.get("spec")
        return typing.cast(typing.Optional["GrafanaSpec"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "GrafanaProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.GrafanaSpec",
    jsii_struct_bases=[],
    name_mapping={"auth": "auth", "service_account": "serviceAccount", "url": "url"},
)
class GrafanaSpec:
    def __init__(
        self,
        *,
        auth: typing.Union["GrafanaSpecAuth", typing.Dict[builtins.str, typing.Any]],
        service_account: typing.Union["GrafanaSpecServiceAccount", typing.Dict[builtins.str, typing.Any]],
        url: builtins.str,
    ) -> None:
        '''GrafanaSpec controls the behavior of the grafana generator.

        :param auth: Auth is the authentication configuration to authenticate against the Grafana instance.
        :param service_account: ServiceAccount is the configuration for the service account that is supposed to be generated by the generator.
        :param url: URL is the URL of the Grafana instance.

        :schema: GrafanaSpec
        '''
        if isinstance(auth, dict):
            auth = GrafanaSpecAuth(**auth)
        if isinstance(service_account, dict):
            service_account = GrafanaSpecServiceAccount(**service_account)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__6625fbfd4423ace39404bc8b275e8825a4e344ae14018a39aa1fad007fdc9a36)
            check_type(argname="argument auth", value=auth, expected_type=type_hints["auth"])
            check_type(argname="argument service_account", value=service_account, expected_type=type_hints["service_account"])
            check_type(argname="argument url", value=url, expected_type=type_hints["url"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "auth": auth,
            "service_account": service_account,
            "url": url,
        }

    @builtins.property
    def auth(self) -> "GrafanaSpecAuth":
        '''Auth is the authentication configuration to authenticate against the Grafana instance.

        :schema: GrafanaSpec#auth
        '''
        result = self._values.get("auth")
        assert result is not None, "Required property 'auth' is missing"
        return typing.cast("GrafanaSpecAuth", result)

    @builtins.property
    def service_account(self) -> "GrafanaSpecServiceAccount":
        '''ServiceAccount is the configuration for the service account that is supposed to be generated by the generator.

        :schema: GrafanaSpec#serviceAccount
        '''
        result = self._values.get("service_account")
        assert result is not None, "Required property 'service_account' is missing"
        return typing.cast("GrafanaSpecServiceAccount", result)

    @builtins.property
    def url(self) -> builtins.str:
        '''URL is the URL of the Grafana instance.

        :schema: GrafanaSpec#url
        '''
        result = self._values.get("url")
        assert result is not None, "Required property 'url' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "GrafanaSpec(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.GrafanaSpecAuth",
    jsii_struct_bases=[],
    name_mapping={"basic": "basic", "token": "token"},
)
class GrafanaSpecAuth:
    def __init__(
        self,
        *,
        basic: typing.Optional[typing.Union["GrafanaSpecAuthBasic", typing.Dict[builtins.str, typing.Any]]] = None,
        token: typing.Optional[typing.Union["GrafanaSpecAuthToken", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Auth is the authentication configuration to authenticate against the Grafana instance.

        :param basic: Basic auth credentials used to authenticate against the Grafana instance. Note: you need a token which has elevated permissions to create service accounts. See here for the documentation on basic roles offered by Grafana: https://grafana.com/docs/grafana/latest/administration/roles-and-permissions/access-control/rbac-fixed-basic-role-definitions/
        :param token: A service account token used to authenticate against the Grafana instance. Note: you need a token which has elevated permissions to create service accounts. See here for the documentation on basic roles offered by Grafana: https://grafana.com/docs/grafana/latest/administration/roles-and-permissions/access-control/rbac-fixed-basic-role-definitions/

        :schema: GrafanaSpecAuth
        '''
        if isinstance(basic, dict):
            basic = GrafanaSpecAuthBasic(**basic)
        if isinstance(token, dict):
            token = GrafanaSpecAuthToken(**token)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__5bfaa65d8f432f88a0afafe11fd84a114db79a53e66f959629a253eaadfc36e4)
            check_type(argname="argument basic", value=basic, expected_type=type_hints["basic"])
            check_type(argname="argument token", value=token, expected_type=type_hints["token"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if basic is not None:
            self._values["basic"] = basic
        if token is not None:
            self._values["token"] = token

    @builtins.property
    def basic(self) -> typing.Optional["GrafanaSpecAuthBasic"]:
        '''Basic auth credentials used to authenticate against the Grafana instance.

        Note: you need a token which has elevated permissions to create service accounts.
        See here for the documentation on basic roles offered by Grafana:
        https://grafana.com/docs/grafana/latest/administration/roles-and-permissions/access-control/rbac-fixed-basic-role-definitions/

        :schema: GrafanaSpecAuth#basic
        '''
        result = self._values.get("basic")
        return typing.cast(typing.Optional["GrafanaSpecAuthBasic"], result)

    @builtins.property
    def token(self) -> typing.Optional["GrafanaSpecAuthToken"]:
        '''A service account token used to authenticate against the Grafana instance.

        Note: you need a token which has elevated permissions to create service accounts.
        See here for the documentation on basic roles offered by Grafana:
        https://grafana.com/docs/grafana/latest/administration/roles-and-permissions/access-control/rbac-fixed-basic-role-definitions/

        :schema: GrafanaSpecAuth#token
        '''
        result = self._values.get("token")
        return typing.cast(typing.Optional["GrafanaSpecAuthToken"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "GrafanaSpecAuth(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.GrafanaSpecAuthBasic",
    jsii_struct_bases=[],
    name_mapping={"password": "password", "username": "username"},
)
class GrafanaSpecAuthBasic:
    def __init__(
        self,
        *,
        password: typing.Union["GrafanaSpecAuthBasicPassword", typing.Dict[builtins.str, typing.Any]],
        username: builtins.str,
    ) -> None:
        '''Basic auth credentials used to authenticate against the Grafana instance.

        Note: you need a token which has elevated permissions to create service accounts.
        See here for the documentation on basic roles offered by Grafana:
        https://grafana.com/docs/grafana/latest/administration/roles-and-permissions/access-control/rbac-fixed-basic-role-definitions/

        :param password: A basic auth password used to authenticate against the Grafana instance.
        :param username: A basic auth username used to authenticate against the Grafana instance.

        :schema: GrafanaSpecAuthBasic
        '''
        if isinstance(password, dict):
            password = GrafanaSpecAuthBasicPassword(**password)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__0542f077ce34199f3ffc66976e46e28ec5e0917422dc9b25348d809fce646abb)
            check_type(argname="argument password", value=password, expected_type=type_hints["password"])
            check_type(argname="argument username", value=username, expected_type=type_hints["username"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "password": password,
            "username": username,
        }

    @builtins.property
    def password(self) -> "GrafanaSpecAuthBasicPassword":
        '''A basic auth password used to authenticate against the Grafana instance.

        :schema: GrafanaSpecAuthBasic#password
        '''
        result = self._values.get("password")
        assert result is not None, "Required property 'password' is missing"
        return typing.cast("GrafanaSpecAuthBasicPassword", result)

    @builtins.property
    def username(self) -> builtins.str:
        '''A basic auth username used to authenticate against the Grafana instance.

        :schema: GrafanaSpecAuthBasic#username
        '''
        result = self._values.get("username")
        assert result is not None, "Required property 'username' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "GrafanaSpecAuthBasic(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.GrafanaSpecAuthBasicPassword",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name"},
)
class GrafanaSpecAuthBasicPassword:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''A basic auth password used to authenticate against the Grafana instance.

        :param key: The key where the token is found.
        :param name: The name of the Secret resource being referred to.

        :schema: GrafanaSpecAuthBasicPassword
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__378165568ab72ed346357c2af9813218ae826bea628ea6dcefbbbf7e29a79846)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''The key where the token is found.

        :schema: GrafanaSpecAuthBasicPassword#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: GrafanaSpecAuthBasicPassword#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "GrafanaSpecAuthBasicPassword(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.GrafanaSpecAuthToken",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name"},
)
class GrafanaSpecAuthToken:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''A service account token used to authenticate against the Grafana instance.

        Note: you need a token which has elevated permissions to create service accounts.
        See here for the documentation on basic roles offered by Grafana:
        https://grafana.com/docs/grafana/latest/administration/roles-and-permissions/access-control/rbac-fixed-basic-role-definitions/

        :param key: The key where the token is found.
        :param name: The name of the Secret resource being referred to.

        :schema: GrafanaSpecAuthToken
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__cff8454759fb223792b7471399e0c8d402d5677cb65b01c20b534a42a98a6aad)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''The key where the token is found.

        :schema: GrafanaSpecAuthToken#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: GrafanaSpecAuthToken#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "GrafanaSpecAuthToken(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.GrafanaSpecServiceAccount",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "role": "role"},
)
class GrafanaSpecServiceAccount:
    def __init__(self, *, name: builtins.str, role: builtins.str) -> None:
        '''ServiceAccount is the configuration for the service account that is supposed to be generated by the generator.

        :param name: Name is the name of the service account that will be created by ESO.
        :param role: Role is the role of the service account. See here for the documentation on basic roles offered by Grafana: https://grafana.com/docs/grafana/latest/administration/roles-and-permissions/access-control/rbac-fixed-basic-role-definitions/

        :schema: GrafanaSpecServiceAccount
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__0b90062b32e8b1dfb708e1e449e63bfe0aa427c431738c846dd6d11249ad0851)
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument role", value=role, expected_type=type_hints["role"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "name": name,
            "role": role,
        }

    @builtins.property
    def name(self) -> builtins.str:
        '''Name is the name of the service account that will be created by ESO.

        :schema: GrafanaSpecServiceAccount#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def role(self) -> builtins.str:
        '''Role is the role of the service account.

        See here for the documentation on basic roles offered by Grafana:
        https://grafana.com/docs/grafana/latest/administration/roles-and-permissions/access-control/rbac-fixed-basic-role-definitions/

        :schema: GrafanaSpecServiceAccount#role
        '''
        result = self._values.get("role")
        assert result is not None, "Required property 'role' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "GrafanaSpecServiceAccount(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class Password(
    _cdk8s_d3d9af27.ApiObject,
    metaclass=jsii.JSIIMeta,
    jsii_type="ioexternal-secretsgenerators.Password",
):
    '''Password generates a random password based on the configuration parameters in spec.

    You can specify the length, characterset and other attributes.

    :schema: Password
    '''

    def __init__(
        self,
        scope: _constructs_77d1e7e8.Construct,
        id: builtins.str,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["PasswordSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Defines a "Password" API object.

        :param scope: the scope in which to define this object.
        :param id: a scope-local name for the object.
        :param metadata: 
        :param spec: PasswordSpec controls the behavior of the password generator.
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__4c09e9ade3db32eebcba799d9623871d6d90ce0ae11f370436996ea869284e6d)
            check_type(argname="argument scope", value=scope, expected_type=type_hints["scope"])
            check_type(argname="argument id", value=id, expected_type=type_hints["id"])
        props = PasswordProps(metadata=metadata, spec=spec)

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="manifest")
    @builtins.classmethod
    def manifest(
        cls,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["PasswordSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> typing.Any:
        '''Renders a Kubernetes manifest for "Password".

        This can be used to inline resource manifests inside other objects (e.g. as templates).

        :param metadata: 
        :param spec: PasswordSpec controls the behavior of the password generator.
        '''
        props = PasswordProps(metadata=metadata, spec=spec)

        return typing.cast(typing.Any, jsii.sinvoke(cls, "manifest", [props]))

    @jsii.member(jsii_name="toJson")
    def to_json(self) -> typing.Any:
        '''Renders the object to Kubernetes JSON.'''
        return typing.cast(typing.Any, jsii.invoke(self, "toJson", []))

    @jsii.python.classproperty
    @jsii.member(jsii_name="GVK")
    def GVK(cls) -> _cdk8s_d3d9af27.GroupVersionKind:
        '''Returns the apiVersion and kind for "Password".'''
        return typing.cast(_cdk8s_d3d9af27.GroupVersionKind, jsii.sget(cls, "GVK"))


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.PasswordProps",
    jsii_struct_bases=[],
    name_mapping={"metadata": "metadata", "spec": "spec"},
)
class PasswordProps:
    def __init__(
        self,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["PasswordSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Password generates a random password based on the configuration parameters in spec.

        You can specify the length, characterset and other attributes.

        :param metadata: 
        :param spec: PasswordSpec controls the behavior of the password generator.

        :schema: Password
        '''
        if isinstance(metadata, dict):
            metadata = _cdk8s_d3d9af27.ApiObjectMetadata(**metadata)
        if isinstance(spec, dict):
            spec = PasswordSpec(**spec)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__1cb0c41f9ff3670a053eb5f508cb64ec2242beb083de7e7c652d4a5b7699e91c)
            check_type(argname="argument metadata", value=metadata, expected_type=type_hints["metadata"])
            check_type(argname="argument spec", value=spec, expected_type=type_hints["spec"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if metadata is not None:
            self._values["metadata"] = metadata
        if spec is not None:
            self._values["spec"] = spec

    @builtins.property
    def metadata(self) -> typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata]:
        '''
        :schema: Password#metadata
        '''
        result = self._values.get("metadata")
        return typing.cast(typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata], result)

    @builtins.property
    def spec(self) -> typing.Optional["PasswordSpec"]:
        '''PasswordSpec controls the behavior of the password generator.

        :schema: Password#spec
        '''
        result = self._values.get("spec")
        return typing.cast(typing.Optional["PasswordSpec"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "PasswordProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.PasswordSpec",
    jsii_struct_bases=[],
    name_mapping={
        "allow_repeat": "allowRepeat",
        "length": "length",
        "no_upper": "noUpper",
        "digits": "digits",
        "symbol_characters": "symbolCharacters",
        "symbols": "symbols",
    },
)
class PasswordSpec:
    def __init__(
        self,
        *,
        allow_repeat: builtins.bool,
        length: jsii.Number,
        no_upper: builtins.bool,
        digits: typing.Optional[jsii.Number] = None,
        symbol_characters: typing.Optional[builtins.str] = None,
        symbols: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''PasswordSpec controls the behavior of the password generator.

        :param allow_repeat: set AllowRepeat to true to allow repeating characters.
        :param length: Length of the password to be generated. Defaults to 24 Default: 24
        :param no_upper: Set NoUpper to disable uppercase characters.
        :param digits: Digits specifies the number of digits in the generated password. If omitted it defaults to 25% of the length of the password
        :param symbol_characters: SymbolCharacters specifies the special characters that should be used in the generated password.
        :param symbols: Symbols specifies the number of symbol characters in the generated password. If omitted it defaults to 25% of the length of the password

        :schema: PasswordSpec
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__b4393f1aed12b90dce27cf67a339b9404fe1de87a2e6dc07a755ffa39d6d1349)
            check_type(argname="argument allow_repeat", value=allow_repeat, expected_type=type_hints["allow_repeat"])
            check_type(argname="argument length", value=length, expected_type=type_hints["length"])
            check_type(argname="argument no_upper", value=no_upper, expected_type=type_hints["no_upper"])
            check_type(argname="argument digits", value=digits, expected_type=type_hints["digits"])
            check_type(argname="argument symbol_characters", value=symbol_characters, expected_type=type_hints["symbol_characters"])
            check_type(argname="argument symbols", value=symbols, expected_type=type_hints["symbols"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "allow_repeat": allow_repeat,
            "length": length,
            "no_upper": no_upper,
        }
        if digits is not None:
            self._values["digits"] = digits
        if symbol_characters is not None:
            self._values["symbol_characters"] = symbol_characters
        if symbols is not None:
            self._values["symbols"] = symbols

    @builtins.property
    def allow_repeat(self) -> builtins.bool:
        '''set AllowRepeat to true to allow repeating characters.

        :schema: PasswordSpec#allowRepeat
        '''
        result = self._values.get("allow_repeat")
        assert result is not None, "Required property 'allow_repeat' is missing"
        return typing.cast(builtins.bool, result)

    @builtins.property
    def length(self) -> jsii.Number:
        '''Length of the password to be generated.

        Defaults to 24

        :default: 24

        :schema: PasswordSpec#length
        '''
        result = self._values.get("length")
        assert result is not None, "Required property 'length' is missing"
        return typing.cast(jsii.Number, result)

    @builtins.property
    def no_upper(self) -> builtins.bool:
        '''Set NoUpper to disable uppercase characters.

        :schema: PasswordSpec#noUpper
        '''
        result = self._values.get("no_upper")
        assert result is not None, "Required property 'no_upper' is missing"
        return typing.cast(builtins.bool, result)

    @builtins.property
    def digits(self) -> typing.Optional[jsii.Number]:
        '''Digits specifies the number of digits in the generated password.

        If omitted it defaults to 25% of the length of the password

        :schema: PasswordSpec#digits
        '''
        result = self._values.get("digits")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def symbol_characters(self) -> typing.Optional[builtins.str]:
        '''SymbolCharacters specifies the special characters that should be used in the generated password.

        :schema: PasswordSpec#symbolCharacters
        '''
        result = self._values.get("symbol_characters")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def symbols(self) -> typing.Optional[jsii.Number]:
        '''Symbols specifies the number of symbol characters in the generated password.

        If omitted it defaults to 25% of the length of the password

        :schema: PasswordSpec#symbols
        '''
        result = self._values.get("symbols")
        return typing.cast(typing.Optional[jsii.Number], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "PasswordSpec(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class QuayAccessToken(
    _cdk8s_d3d9af27.ApiObject,
    metaclass=jsii.JSIIMeta,
    jsii_type="ioexternal-secretsgenerators.QuayAccessToken",
):
    '''QuayAccessToken generates Quay oauth token for pulling/pushing images.

    :schema: QuayAccessToken
    '''

    def __init__(
        self,
        scope: _constructs_77d1e7e8.Construct,
        id: builtins.str,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["QuayAccessTokenSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Defines a "QuayAccessToken" API object.

        :param scope: the scope in which to define this object.
        :param id: a scope-local name for the object.
        :param metadata: 
        :param spec: 
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__58971dea6308deeb2631c838ee3c6601a0b25893b80479dc4e945254f22274b6)
            check_type(argname="argument scope", value=scope, expected_type=type_hints["scope"])
            check_type(argname="argument id", value=id, expected_type=type_hints["id"])
        props = QuayAccessTokenProps(metadata=metadata, spec=spec)

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="manifest")
    @builtins.classmethod
    def manifest(
        cls,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["QuayAccessTokenSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> typing.Any:
        '''Renders a Kubernetes manifest for "QuayAccessToken".

        This can be used to inline resource manifests inside other objects (e.g. as templates).

        :param metadata: 
        :param spec: 
        '''
        props = QuayAccessTokenProps(metadata=metadata, spec=spec)

        return typing.cast(typing.Any, jsii.sinvoke(cls, "manifest", [props]))

    @jsii.member(jsii_name="toJson")
    def to_json(self) -> typing.Any:
        '''Renders the object to Kubernetes JSON.'''
        return typing.cast(typing.Any, jsii.invoke(self, "toJson", []))

    @jsii.python.classproperty
    @jsii.member(jsii_name="GVK")
    def GVK(cls) -> _cdk8s_d3d9af27.GroupVersionKind:
        '''Returns the apiVersion and kind for "QuayAccessToken".'''
        return typing.cast(_cdk8s_d3d9af27.GroupVersionKind, jsii.sget(cls, "GVK"))


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.QuayAccessTokenProps",
    jsii_struct_bases=[],
    name_mapping={"metadata": "metadata", "spec": "spec"},
)
class QuayAccessTokenProps:
    def __init__(
        self,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["QuayAccessTokenSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''QuayAccessToken generates Quay oauth token for pulling/pushing images.

        :param metadata: 
        :param spec: 

        :schema: QuayAccessToken
        '''
        if isinstance(metadata, dict):
            metadata = _cdk8s_d3d9af27.ApiObjectMetadata(**metadata)
        if isinstance(spec, dict):
            spec = QuayAccessTokenSpec(**spec)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__c1de6b6de8dac96a29a81c78e7a31cd2fe43fbcb8590f2510368200297fde71d)
            check_type(argname="argument metadata", value=metadata, expected_type=type_hints["metadata"])
            check_type(argname="argument spec", value=spec, expected_type=type_hints["spec"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if metadata is not None:
            self._values["metadata"] = metadata
        if spec is not None:
            self._values["spec"] = spec

    @builtins.property
    def metadata(self) -> typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata]:
        '''
        :schema: QuayAccessToken#metadata
        '''
        result = self._values.get("metadata")
        return typing.cast(typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata], result)

    @builtins.property
    def spec(self) -> typing.Optional["QuayAccessTokenSpec"]:
        '''
        :schema: QuayAccessToken#spec
        '''
        result = self._values.get("spec")
        return typing.cast(typing.Optional["QuayAccessTokenSpec"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "QuayAccessTokenProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.QuayAccessTokenSpec",
    jsii_struct_bases=[],
    name_mapping={
        "robot_account": "robotAccount",
        "service_account_ref": "serviceAccountRef",
        "url": "url",
    },
)
class QuayAccessTokenSpec:
    def __init__(
        self,
        *,
        robot_account: builtins.str,
        service_account_ref: typing.Union["QuayAccessTokenSpecServiceAccountRef", typing.Dict[builtins.str, typing.Any]],
        url: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param robot_account: Name of the robot account you are federating with.
        :param service_account_ref: Name of the service account you are federating with.
        :param url: URL configures the Quay instance URL. Defaults to quay.io. Default: quay.io.

        :schema: QuayAccessTokenSpec
        '''
        if isinstance(service_account_ref, dict):
            service_account_ref = QuayAccessTokenSpecServiceAccountRef(**service_account_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__f2f7947dd3ee6ff17129eb636fd5d530fa48f6d2fec09d2559cef20aa537a9d7)
            check_type(argname="argument robot_account", value=robot_account, expected_type=type_hints["robot_account"])
            check_type(argname="argument service_account_ref", value=service_account_ref, expected_type=type_hints["service_account_ref"])
            check_type(argname="argument url", value=url, expected_type=type_hints["url"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "robot_account": robot_account,
            "service_account_ref": service_account_ref,
        }
        if url is not None:
            self._values["url"] = url

    @builtins.property
    def robot_account(self) -> builtins.str:
        '''Name of the robot account you are federating with.

        :schema: QuayAccessTokenSpec#robotAccount
        '''
        result = self._values.get("robot_account")
        assert result is not None, "Required property 'robot_account' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def service_account_ref(self) -> "QuayAccessTokenSpecServiceAccountRef":
        '''Name of the service account you are federating with.

        :schema: QuayAccessTokenSpec#serviceAccountRef
        '''
        result = self._values.get("service_account_ref")
        assert result is not None, "Required property 'service_account_ref' is missing"
        return typing.cast("QuayAccessTokenSpecServiceAccountRef", result)

    @builtins.property
    def url(self) -> typing.Optional[builtins.str]:
        '''URL configures the Quay instance URL.

        Defaults to quay.io.

        :default: quay.io.

        :schema: QuayAccessTokenSpec#url
        '''
        result = self._values.get("url")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "QuayAccessTokenSpec(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.QuayAccessTokenSpecServiceAccountRef",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "audiences": "audiences", "namespace": "namespace"},
)
class QuayAccessTokenSpecServiceAccountRef:
    def __init__(
        self,
        *,
        name: builtins.str,
        audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Name of the service account you are federating with.

        :param name: The name of the ServiceAccount resource being referred to.
        :param audiences: Audience specifies the ``aud`` claim for the service account token If the service account uses a well-known annotation for e.g. IRSA or GCP Workload Identity then this audiences will be appended to the list.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: QuayAccessTokenSpecServiceAccountRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__3e1a2c5b1a9946bee470f5e44e7010f914a64be38e1bd6c83605261840dff854)
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument audiences", value=audiences, expected_type=type_hints["audiences"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "name": name,
        }
        if audiences is not None:
            self._values["audiences"] = audiences
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the ServiceAccount resource being referred to.

        :schema: QuayAccessTokenSpecServiceAccountRef#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def audiences(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Audience specifies the ``aud`` claim for the service account token If the service account uses a well-known annotation for e.g. IRSA or GCP Workload Identity then this audiences will be appended to the list.

        :schema: QuayAccessTokenSpecServiceAccountRef#audiences
        '''
        result = self._values.get("audiences")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: QuayAccessTokenSpecServiceAccountRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "QuayAccessTokenSpecServiceAccountRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class StsSessionToken(
    _cdk8s_d3d9af27.ApiObject,
    metaclass=jsii.JSIIMeta,
    jsii_type="ioexternal-secretsgenerators.StsSessionToken",
):
    '''STSSessionToken uses the GetSessionToken API to retrieve an authorization token.

    The authorization token is valid for 12 hours.
    The authorizationToken returned is a base64 encoded string that can be decoded.
    For more information, see GetSessionToken (https://docs.aws.amazon.com/STS/latest/APIReference/API_GetSessionToken.html).

    :schema: STSSessionToken
    '''

    def __init__(
        self,
        scope: _constructs_77d1e7e8.Construct,
        id: builtins.str,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["StsSessionTokenSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Defines a "STSSessionToken" API object.

        :param scope: the scope in which to define this object.
        :param id: a scope-local name for the object.
        :param metadata: 
        :param spec: 
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__6d24e2306191a5fd4c09bb6b3eba8a928429a33c1a208b4fa447525d2e6efb8e)
            check_type(argname="argument scope", value=scope, expected_type=type_hints["scope"])
            check_type(argname="argument id", value=id, expected_type=type_hints["id"])
        props = StsSessionTokenProps(metadata=metadata, spec=spec)

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="manifest")
    @builtins.classmethod
    def manifest(
        cls,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["StsSessionTokenSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> typing.Any:
        '''Renders a Kubernetes manifest for "STSSessionToken".

        This can be used to inline resource manifests inside other objects (e.g. as templates).

        :param metadata: 
        :param spec: 
        '''
        props = StsSessionTokenProps(metadata=metadata, spec=spec)

        return typing.cast(typing.Any, jsii.sinvoke(cls, "manifest", [props]))

    @jsii.member(jsii_name="toJson")
    def to_json(self) -> typing.Any:
        '''Renders the object to Kubernetes JSON.'''
        return typing.cast(typing.Any, jsii.invoke(self, "toJson", []))

    @jsii.python.classproperty
    @jsii.member(jsii_name="GVK")
    def GVK(cls) -> _cdk8s_d3d9af27.GroupVersionKind:
        '''Returns the apiVersion and kind for "STSSessionToken".'''
        return typing.cast(_cdk8s_d3d9af27.GroupVersionKind, jsii.sget(cls, "GVK"))


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.StsSessionTokenProps",
    jsii_struct_bases=[],
    name_mapping={"metadata": "metadata", "spec": "spec"},
)
class StsSessionTokenProps:
    def __init__(
        self,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["StsSessionTokenSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''STSSessionToken uses the GetSessionToken API to retrieve an authorization token.

        The authorization token is valid for 12 hours.
        The authorizationToken returned is a base64 encoded string that can be decoded.
        For more information, see GetSessionToken (https://docs.aws.amazon.com/STS/latest/APIReference/API_GetSessionToken.html).

        :param metadata: 
        :param spec: 

        :schema: STSSessionToken
        '''
        if isinstance(metadata, dict):
            metadata = _cdk8s_d3d9af27.ApiObjectMetadata(**metadata)
        if isinstance(spec, dict):
            spec = StsSessionTokenSpec(**spec)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__99ba1ef4df49f58515dd98da924e78ed1ebbe8d10714eea217cc4e293774bf3f)
            check_type(argname="argument metadata", value=metadata, expected_type=type_hints["metadata"])
            check_type(argname="argument spec", value=spec, expected_type=type_hints["spec"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if metadata is not None:
            self._values["metadata"] = metadata
        if spec is not None:
            self._values["spec"] = spec

    @builtins.property
    def metadata(self) -> typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata]:
        '''
        :schema: STSSessionToken#metadata
        '''
        result = self._values.get("metadata")
        return typing.cast(typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata], result)

    @builtins.property
    def spec(self) -> typing.Optional["StsSessionTokenSpec"]:
        '''
        :schema: STSSessionToken#spec
        '''
        result = self._values.get("spec")
        return typing.cast(typing.Optional["StsSessionTokenSpec"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StsSessionTokenProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.StsSessionTokenSpec",
    jsii_struct_bases=[],
    name_mapping={
        "region": "region",
        "auth": "auth",
        "request_parameters": "requestParameters",
        "role": "role",
    },
)
class StsSessionTokenSpec:
    def __init__(
        self,
        *,
        region: builtins.str,
        auth: typing.Optional[typing.Union["StsSessionTokenSpecAuth", typing.Dict[builtins.str, typing.Any]]] = None,
        request_parameters: typing.Optional[typing.Union["StsSessionTokenSpecRequestParameters", typing.Dict[builtins.str, typing.Any]]] = None,
        role: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param region: Region specifies the region to operate in.
        :param auth: Auth defines how to authenticate with AWS.
        :param request_parameters: RequestParameters contains parameters that can be passed to the STS service.
        :param role: You can assume a role before making calls to the desired AWS service.

        :schema: StsSessionTokenSpec
        '''
        if isinstance(auth, dict):
            auth = StsSessionTokenSpecAuth(**auth)
        if isinstance(request_parameters, dict):
            request_parameters = StsSessionTokenSpecRequestParameters(**request_parameters)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__57971c517b07bc88d332106d38b683b3192461b1e272956332f6a1e7a07ffd48)
            check_type(argname="argument region", value=region, expected_type=type_hints["region"])
            check_type(argname="argument auth", value=auth, expected_type=type_hints["auth"])
            check_type(argname="argument request_parameters", value=request_parameters, expected_type=type_hints["request_parameters"])
            check_type(argname="argument role", value=role, expected_type=type_hints["role"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "region": region,
        }
        if auth is not None:
            self._values["auth"] = auth
        if request_parameters is not None:
            self._values["request_parameters"] = request_parameters
        if role is not None:
            self._values["role"] = role

    @builtins.property
    def region(self) -> builtins.str:
        '''Region specifies the region to operate in.

        :schema: StsSessionTokenSpec#region
        '''
        result = self._values.get("region")
        assert result is not None, "Required property 'region' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def auth(self) -> typing.Optional["StsSessionTokenSpecAuth"]:
        '''Auth defines how to authenticate with AWS.

        :schema: StsSessionTokenSpec#auth
        '''
        result = self._values.get("auth")
        return typing.cast(typing.Optional["StsSessionTokenSpecAuth"], result)

    @builtins.property
    def request_parameters(
        self,
    ) -> typing.Optional["StsSessionTokenSpecRequestParameters"]:
        '''RequestParameters contains parameters that can be passed to the STS service.

        :schema: StsSessionTokenSpec#requestParameters
        '''
        result = self._values.get("request_parameters")
        return typing.cast(typing.Optional["StsSessionTokenSpecRequestParameters"], result)

    @builtins.property
    def role(self) -> typing.Optional[builtins.str]:
        '''You can assume a role before making calls to the desired AWS service.

        :schema: StsSessionTokenSpec#role
        '''
        result = self._values.get("role")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StsSessionTokenSpec(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.StsSessionTokenSpecAuth",
    jsii_struct_bases=[],
    name_mapping={"jwt": "jwt", "secret_ref": "secretRef"},
)
class StsSessionTokenSpecAuth:
    def __init__(
        self,
        *,
        jwt: typing.Optional[typing.Union["StsSessionTokenSpecAuthJwt", typing.Dict[builtins.str, typing.Any]]] = None,
        secret_ref: typing.Optional[typing.Union["StsSessionTokenSpecAuthSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Auth defines how to authenticate with AWS.

        :param jwt: Authenticate against AWS using service account tokens.
        :param secret_ref: AWSAuthSecretRef holds secret references for AWS credentials both AccessKeyID and SecretAccessKey must be defined in order to properly authenticate.

        :schema: StsSessionTokenSpecAuth
        '''
        if isinstance(jwt, dict):
            jwt = StsSessionTokenSpecAuthJwt(**jwt)
        if isinstance(secret_ref, dict):
            secret_ref = StsSessionTokenSpecAuthSecretRef(**secret_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__128238ae2232ebcc6bf164aa81bc2f0bce66e0e8323dc413175bb2d1cabededb)
            check_type(argname="argument jwt", value=jwt, expected_type=type_hints["jwt"])
            check_type(argname="argument secret_ref", value=secret_ref, expected_type=type_hints["secret_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if jwt is not None:
            self._values["jwt"] = jwt
        if secret_ref is not None:
            self._values["secret_ref"] = secret_ref

    @builtins.property
    def jwt(self) -> typing.Optional["StsSessionTokenSpecAuthJwt"]:
        '''Authenticate against AWS using service account tokens.

        :schema: StsSessionTokenSpecAuth#jwt
        '''
        result = self._values.get("jwt")
        return typing.cast(typing.Optional["StsSessionTokenSpecAuthJwt"], result)

    @builtins.property
    def secret_ref(self) -> typing.Optional["StsSessionTokenSpecAuthSecretRef"]:
        '''AWSAuthSecretRef holds secret references for AWS credentials both AccessKeyID and SecretAccessKey must be defined in order to properly authenticate.

        :schema: StsSessionTokenSpecAuth#secretRef
        '''
        result = self._values.get("secret_ref")
        return typing.cast(typing.Optional["StsSessionTokenSpecAuthSecretRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StsSessionTokenSpecAuth(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.StsSessionTokenSpecAuthJwt",
    jsii_struct_bases=[],
    name_mapping={"service_account_ref": "serviceAccountRef"},
)
class StsSessionTokenSpecAuthJwt:
    def __init__(
        self,
        *,
        service_account_ref: typing.Optional[typing.Union["StsSessionTokenSpecAuthJwtServiceAccountRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Authenticate against AWS using service account tokens.

        :param service_account_ref: A reference to a ServiceAccount resource.

        :schema: StsSessionTokenSpecAuthJwt
        '''
        if isinstance(service_account_ref, dict):
            service_account_ref = StsSessionTokenSpecAuthJwtServiceAccountRef(**service_account_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__0ef21507671ccea3e0d2148a2c99b012254c104057efec60f91b4f36ecbcbcd7)
            check_type(argname="argument service_account_ref", value=service_account_ref, expected_type=type_hints["service_account_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if service_account_ref is not None:
            self._values["service_account_ref"] = service_account_ref

    @builtins.property
    def service_account_ref(
        self,
    ) -> typing.Optional["StsSessionTokenSpecAuthJwtServiceAccountRef"]:
        '''A reference to a ServiceAccount resource.

        :schema: StsSessionTokenSpecAuthJwt#serviceAccountRef
        '''
        result = self._values.get("service_account_ref")
        return typing.cast(typing.Optional["StsSessionTokenSpecAuthJwtServiceAccountRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StsSessionTokenSpecAuthJwt(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.StsSessionTokenSpecAuthJwtServiceAccountRef",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "audiences": "audiences", "namespace": "namespace"},
)
class StsSessionTokenSpecAuthJwtServiceAccountRef:
    def __init__(
        self,
        *,
        name: builtins.str,
        audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''A reference to a ServiceAccount resource.

        :param name: The name of the ServiceAccount resource being referred to.
        :param audiences: Audience specifies the ``aud`` claim for the service account token If the service account uses a well-known annotation for e.g. IRSA or GCP Workload Identity then this audiences will be appended to the list.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: StsSessionTokenSpecAuthJwtServiceAccountRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__ef74d0e99a5dcb1aa1f95f0ef5e27a930a3ee6f122993effa5372a9f435d1af6)
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument audiences", value=audiences, expected_type=type_hints["audiences"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "name": name,
        }
        if audiences is not None:
            self._values["audiences"] = audiences
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the ServiceAccount resource being referred to.

        :schema: StsSessionTokenSpecAuthJwtServiceAccountRef#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def audiences(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Audience specifies the ``aud`` claim for the service account token If the service account uses a well-known annotation for e.g. IRSA or GCP Workload Identity then this audiences will be appended to the list.

        :schema: StsSessionTokenSpecAuthJwtServiceAccountRef#audiences
        '''
        result = self._values.get("audiences")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: StsSessionTokenSpecAuthJwtServiceAccountRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StsSessionTokenSpecAuthJwtServiceAccountRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.StsSessionTokenSpecAuthSecretRef",
    jsii_struct_bases=[],
    name_mapping={
        "access_key_id_secret_ref": "accessKeyIdSecretRef",
        "secret_access_key_secret_ref": "secretAccessKeySecretRef",
        "session_token_secret_ref": "sessionTokenSecretRef",
    },
)
class StsSessionTokenSpecAuthSecretRef:
    def __init__(
        self,
        *,
        access_key_id_secret_ref: typing.Optional[typing.Union["StsSessionTokenSpecAuthSecretRefAccessKeyIdSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
        secret_access_key_secret_ref: typing.Optional[typing.Union["StsSessionTokenSpecAuthSecretRefSecretAccessKeySecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
        session_token_secret_ref: typing.Optional[typing.Union["StsSessionTokenSpecAuthSecretRefSessionTokenSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''AWSAuthSecretRef holds secret references for AWS credentials both AccessKeyID and SecretAccessKey must be defined in order to properly authenticate.

        :param access_key_id_secret_ref: The AccessKeyID is used for authentication.
        :param secret_access_key_secret_ref: The SecretAccessKey is used for authentication.
        :param session_token_secret_ref: The SessionToken used for authentication This must be defined if AccessKeyID and SecretAccessKey are temporary credentials see: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html.

        :schema: StsSessionTokenSpecAuthSecretRef
        '''
        if isinstance(access_key_id_secret_ref, dict):
            access_key_id_secret_ref = StsSessionTokenSpecAuthSecretRefAccessKeyIdSecretRef(**access_key_id_secret_ref)
        if isinstance(secret_access_key_secret_ref, dict):
            secret_access_key_secret_ref = StsSessionTokenSpecAuthSecretRefSecretAccessKeySecretRef(**secret_access_key_secret_ref)
        if isinstance(session_token_secret_ref, dict):
            session_token_secret_ref = StsSessionTokenSpecAuthSecretRefSessionTokenSecretRef(**session_token_secret_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__1aa5ae84249fdfd41ca7b653dd80ec4600c5aac7fcdecbbdfd9861138e87de1c)
            check_type(argname="argument access_key_id_secret_ref", value=access_key_id_secret_ref, expected_type=type_hints["access_key_id_secret_ref"])
            check_type(argname="argument secret_access_key_secret_ref", value=secret_access_key_secret_ref, expected_type=type_hints["secret_access_key_secret_ref"])
            check_type(argname="argument session_token_secret_ref", value=session_token_secret_ref, expected_type=type_hints["session_token_secret_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if access_key_id_secret_ref is not None:
            self._values["access_key_id_secret_ref"] = access_key_id_secret_ref
        if secret_access_key_secret_ref is not None:
            self._values["secret_access_key_secret_ref"] = secret_access_key_secret_ref
        if session_token_secret_ref is not None:
            self._values["session_token_secret_ref"] = session_token_secret_ref

    @builtins.property
    def access_key_id_secret_ref(
        self,
    ) -> typing.Optional["StsSessionTokenSpecAuthSecretRefAccessKeyIdSecretRef"]:
        '''The AccessKeyID is used for authentication.

        :schema: StsSessionTokenSpecAuthSecretRef#accessKeyIDSecretRef
        '''
        result = self._values.get("access_key_id_secret_ref")
        return typing.cast(typing.Optional["StsSessionTokenSpecAuthSecretRefAccessKeyIdSecretRef"], result)

    @builtins.property
    def secret_access_key_secret_ref(
        self,
    ) -> typing.Optional["StsSessionTokenSpecAuthSecretRefSecretAccessKeySecretRef"]:
        '''The SecretAccessKey is used for authentication.

        :schema: StsSessionTokenSpecAuthSecretRef#secretAccessKeySecretRef
        '''
        result = self._values.get("secret_access_key_secret_ref")
        return typing.cast(typing.Optional["StsSessionTokenSpecAuthSecretRefSecretAccessKeySecretRef"], result)

    @builtins.property
    def session_token_secret_ref(
        self,
    ) -> typing.Optional["StsSessionTokenSpecAuthSecretRefSessionTokenSecretRef"]:
        '''The SessionToken used for authentication This must be defined if AccessKeyID and SecretAccessKey are temporary credentials see: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html.

        :schema: StsSessionTokenSpecAuthSecretRef#sessionTokenSecretRef
        '''
        result = self._values.get("session_token_secret_ref")
        return typing.cast(typing.Optional["StsSessionTokenSpecAuthSecretRefSessionTokenSecretRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StsSessionTokenSpecAuthSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.StsSessionTokenSpecAuthSecretRefAccessKeyIdSecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class StsSessionTokenSpecAuthSecretRefAccessKeyIdSecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''The AccessKeyID is used for authentication.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: StsSessionTokenSpecAuthSecretRefAccessKeyIdSecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__26880547e4d6d107f93525a8b3ddb6deab003815cab7d5a836b60408c97ce22e)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: StsSessionTokenSpecAuthSecretRefAccessKeyIdSecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: StsSessionTokenSpecAuthSecretRefAccessKeyIdSecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: StsSessionTokenSpecAuthSecretRefAccessKeyIdSecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StsSessionTokenSpecAuthSecretRefAccessKeyIdSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.StsSessionTokenSpecAuthSecretRefSecretAccessKeySecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class StsSessionTokenSpecAuthSecretRefSecretAccessKeySecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''The SecretAccessKey is used for authentication.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: StsSessionTokenSpecAuthSecretRefSecretAccessKeySecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__25d67dc291615d535958749787fed9be52d1ba3e3c32ee47f076021cc75f627f)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: StsSessionTokenSpecAuthSecretRefSecretAccessKeySecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: StsSessionTokenSpecAuthSecretRefSecretAccessKeySecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: StsSessionTokenSpecAuthSecretRefSecretAccessKeySecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StsSessionTokenSpecAuthSecretRefSecretAccessKeySecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.StsSessionTokenSpecAuthSecretRefSessionTokenSecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class StsSessionTokenSpecAuthSecretRefSessionTokenSecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''The SessionToken used for authentication This must be defined if AccessKeyID and SecretAccessKey are temporary credentials see: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: StsSessionTokenSpecAuthSecretRefSessionTokenSecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__a802177567d2d782534f3eef4692d36d73e0a214f1a16b8229f4715ad33d029b)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: StsSessionTokenSpecAuthSecretRefSessionTokenSecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: StsSessionTokenSpecAuthSecretRefSessionTokenSecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: StsSessionTokenSpecAuthSecretRefSessionTokenSecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StsSessionTokenSpecAuthSecretRefSessionTokenSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.StsSessionTokenSpecRequestParameters",
    jsii_struct_bases=[],
    name_mapping={
        "serial_number": "serialNumber",
        "session_duration": "sessionDuration",
        "token_code": "tokenCode",
    },
)
class StsSessionTokenSpecRequestParameters:
    def __init__(
        self,
        *,
        serial_number: typing.Optional[builtins.str] = None,
        session_duration: typing.Optional[jsii.Number] = None,
        token_code: typing.Optional[builtins.str] = None,
    ) -> None:
        '''RequestParameters contains parameters that can be passed to the STS service.

        :param serial_number: SerialNumber is the identification number of the MFA device that is associated with the IAM user who is making the GetSessionToken call. Possible values: hardware device (such as GAHT12345678) or an Amazon Resource Name (ARN) for a virtual device (such as arn:aws:iam::123456789012:mfa/user)
        :param session_duration: SessionDuration The duration, in seconds, that the credentials should remain valid. Acceptable durations for IAM user sessions range from 900 seconds (15 minutes) to 129,600 seconds (36 hours), with 43,200 seconds (12 hours) as the default.
        :param token_code: TokenCode is the value provided by the MFA device, if MFA is required.

        :schema: StsSessionTokenSpecRequestParameters
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__e77302456aefbef13fda79e9d9c8914e610c8325ae579419712258b0bd06c96f)
            check_type(argname="argument serial_number", value=serial_number, expected_type=type_hints["serial_number"])
            check_type(argname="argument session_duration", value=session_duration, expected_type=type_hints["session_duration"])
            check_type(argname="argument token_code", value=token_code, expected_type=type_hints["token_code"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if serial_number is not None:
            self._values["serial_number"] = serial_number
        if session_duration is not None:
            self._values["session_duration"] = session_duration
        if token_code is not None:
            self._values["token_code"] = token_code

    @builtins.property
    def serial_number(self) -> typing.Optional[builtins.str]:
        '''SerialNumber is the identification number of the MFA device that is associated with the IAM user who is making the GetSessionToken call.

        Possible values: hardware device (such as GAHT12345678) or an Amazon Resource Name (ARN) for a virtual device
        (such as arn:aws:iam::123456789012:mfa/user)

        :schema: StsSessionTokenSpecRequestParameters#serialNumber
        '''
        result = self._values.get("serial_number")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def session_duration(self) -> typing.Optional[jsii.Number]:
        '''SessionDuration The duration, in seconds, that the credentials should remain valid.

        Acceptable durations for
        IAM user sessions range from 900 seconds (15 minutes) to 129,600 seconds (36 hours), with 43,200 seconds
        (12 hours) as the default.

        :schema: StsSessionTokenSpecRequestParameters#sessionDuration
        '''
        result = self._values.get("session_duration")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def token_code(self) -> typing.Optional[builtins.str]:
        '''TokenCode is the value provided by the MFA device, if MFA is required.

        :schema: StsSessionTokenSpecRequestParameters#tokenCode
        '''
        result = self._values.get("token_code")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StsSessionTokenSpecRequestParameters(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class Uuid(
    _cdk8s_d3d9af27.ApiObject,
    metaclass=jsii.JSIIMeta,
    jsii_type="ioexternal-secretsgenerators.Uuid",
):
    '''UUID generates a version 1 UUID (e56657e3-764f-11ef-a397-65231a88c216).

    :schema: UUID
    '''

    def __init__(
        self,
        scope: _constructs_77d1e7e8.Construct,
        id: builtins.str,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Any = None,
    ) -> None:
        '''Defines a "UUID" API object.

        :param scope: the scope in which to define this object.
        :param id: a scope-local name for the object.
        :param metadata: 
        :param spec: UUIDSpec controls the behavior of the uuid generator.
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__dabeb65c195f530626cc8b53a636523447b50d239eac35855f228858208d7100)
            check_type(argname="argument scope", value=scope, expected_type=type_hints["scope"])
            check_type(argname="argument id", value=id, expected_type=type_hints["id"])
        props = UuidProps(metadata=metadata, spec=spec)

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="manifest")
    @builtins.classmethod
    def manifest(
        cls,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Any = None,
    ) -> typing.Any:
        '''Renders a Kubernetes manifest for "UUID".

        This can be used to inline resource manifests inside other objects (e.g. as templates).

        :param metadata: 
        :param spec: UUIDSpec controls the behavior of the uuid generator.
        '''
        props = UuidProps(metadata=metadata, spec=spec)

        return typing.cast(typing.Any, jsii.sinvoke(cls, "manifest", [props]))

    @jsii.member(jsii_name="toJson")
    def to_json(self) -> typing.Any:
        '''Renders the object to Kubernetes JSON.'''
        return typing.cast(typing.Any, jsii.invoke(self, "toJson", []))

    @jsii.python.classproperty
    @jsii.member(jsii_name="GVK")
    def GVK(cls) -> _cdk8s_d3d9af27.GroupVersionKind:
        '''Returns the apiVersion and kind for "UUID".'''
        return typing.cast(_cdk8s_d3d9af27.GroupVersionKind, jsii.sget(cls, "GVK"))


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.UuidProps",
    jsii_struct_bases=[],
    name_mapping={"metadata": "metadata", "spec": "spec"},
)
class UuidProps:
    def __init__(
        self,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Any = None,
    ) -> None:
        '''UUID generates a version 1 UUID (e56657e3-764f-11ef-a397-65231a88c216).

        :param metadata: 
        :param spec: UUIDSpec controls the behavior of the uuid generator.

        :schema: UUID
        '''
        if isinstance(metadata, dict):
            metadata = _cdk8s_d3d9af27.ApiObjectMetadata(**metadata)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__fc6f47b832cfa3206b7deedb2a4d4629cc00198a598cb3fa553cf5757efd0465)
            check_type(argname="argument metadata", value=metadata, expected_type=type_hints["metadata"])
            check_type(argname="argument spec", value=spec, expected_type=type_hints["spec"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if metadata is not None:
            self._values["metadata"] = metadata
        if spec is not None:
            self._values["spec"] = spec

    @builtins.property
    def metadata(self) -> typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata]:
        '''
        :schema: UUID#metadata
        '''
        result = self._values.get("metadata")
        return typing.cast(typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata], result)

    @builtins.property
    def spec(self) -> typing.Any:
        '''UUIDSpec controls the behavior of the uuid generator.

        :schema: UUID#spec
        '''
        result = self._values.get("spec")
        return typing.cast(typing.Any, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "UuidProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class VaultDynamicSecret(
    _cdk8s_d3d9af27.ApiObject,
    metaclass=jsii.JSIIMeta,
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecret",
):
    '''
    :schema: VaultDynamicSecret
    '''

    def __init__(
        self,
        scope: _constructs_77d1e7e8.Construct,
        id: builtins.str,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["VaultDynamicSecretSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Defines a "VaultDynamicSecret" API object.

        :param scope: the scope in which to define this object.
        :param id: a scope-local name for the object.
        :param metadata: 
        :param spec: 
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__9de7ad29b743a3478314c6a17debdf2b449820754873f9353e2c8fe6fefb8e48)
            check_type(argname="argument scope", value=scope, expected_type=type_hints["scope"])
            check_type(argname="argument id", value=id, expected_type=type_hints["id"])
        props = VaultDynamicSecretProps(metadata=metadata, spec=spec)

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="manifest")
    @builtins.classmethod
    def manifest(
        cls,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["VaultDynamicSecretSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> typing.Any:
        '''Renders a Kubernetes manifest for "VaultDynamicSecret".

        This can be used to inline resource manifests inside other objects (e.g. as templates).

        :param metadata: 
        :param spec: 
        '''
        props = VaultDynamicSecretProps(metadata=metadata, spec=spec)

        return typing.cast(typing.Any, jsii.sinvoke(cls, "manifest", [props]))

    @jsii.member(jsii_name="toJson")
    def to_json(self) -> typing.Any:
        '''Renders the object to Kubernetes JSON.'''
        return typing.cast(typing.Any, jsii.invoke(self, "toJson", []))

    @jsii.python.classproperty
    @jsii.member(jsii_name="GVK")
    def GVK(cls) -> _cdk8s_d3d9af27.GroupVersionKind:
        '''Returns the apiVersion and kind for "VaultDynamicSecret".'''
        return typing.cast(_cdk8s_d3d9af27.GroupVersionKind, jsii.sget(cls, "GVK"))


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretProps",
    jsii_struct_bases=[],
    name_mapping={"metadata": "metadata", "spec": "spec"},
)
class VaultDynamicSecretProps:
    def __init__(
        self,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["VaultDynamicSecretSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''
        :param metadata: 
        :param spec: 

        :schema: VaultDynamicSecret
        '''
        if isinstance(metadata, dict):
            metadata = _cdk8s_d3d9af27.ApiObjectMetadata(**metadata)
        if isinstance(spec, dict):
            spec = VaultDynamicSecretSpec(**spec)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__31b50742f6e2bf3e29bb865c2a67519a6015bd8c040719626d607b2f4f05787f)
            check_type(argname="argument metadata", value=metadata, expected_type=type_hints["metadata"])
            check_type(argname="argument spec", value=spec, expected_type=type_hints["spec"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if metadata is not None:
            self._values["metadata"] = metadata
        if spec is not None:
            self._values["spec"] = spec

    @builtins.property
    def metadata(self) -> typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata]:
        '''
        :schema: VaultDynamicSecret#metadata
        '''
        result = self._values.get("metadata")
        return typing.cast(typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata], result)

    @builtins.property
    def spec(self) -> typing.Optional["VaultDynamicSecretSpec"]:
        '''
        :schema: VaultDynamicSecret#spec
        '''
        result = self._values.get("spec")
        return typing.cast(typing.Optional["VaultDynamicSecretSpec"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpec",
    jsii_struct_bases=[],
    name_mapping={
        "path": "path",
        "provider": "provider",
        "allow_empty_response": "allowEmptyResponse",
        "controller": "controller",
        "method": "method",
        "parameters": "parameters",
        "result_type": "resultType",
        "retry_settings": "retrySettings",
    },
)
class VaultDynamicSecretSpec:
    def __init__(
        self,
        *,
        path: builtins.str,
        provider: typing.Union["VaultDynamicSecretSpecProvider", typing.Dict[builtins.str, typing.Any]],
        allow_empty_response: typing.Optional[builtins.bool] = None,
        controller: typing.Optional[builtins.str] = None,
        method: typing.Optional[builtins.str] = None,
        parameters: typing.Any = None,
        result_type: typing.Optional["VaultDynamicSecretSpecResultType"] = None,
        retry_settings: typing.Optional[typing.Union["VaultDynamicSecretSpecRetrySettings", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''
        :param path: Vault path to obtain the dynamic secret from.
        :param provider: Vault provider common spec.
        :param allow_empty_response: Do not fail if no secrets are found. Useful for requests where no data is expected.
        :param controller: Used to select the correct ESO controller (think: ingress.ingressClassName) The ESO controller is instantiated with a specific controller name and filters VDS based on this property.
        :param method: Vault API method to use (GET/POST/other).
        :param parameters: Parameters to pass to Vault write (for non-GET methods).
        :param result_type: Result type defines which data is returned from the generator. By default it is the "data" section of the Vault API response. When using e.g. /auth/token/create the "data" section is empty but the "auth" section contains the generated token. Please refer to the vault docs regarding the result data structure. Additionally, accessing the raw response is possibly by using "Raw" result type.
        :param retry_settings: Used to configure http retries if failed.

        :schema: VaultDynamicSecretSpec
        '''
        if isinstance(provider, dict):
            provider = VaultDynamicSecretSpecProvider(**provider)
        if isinstance(retry_settings, dict):
            retry_settings = VaultDynamicSecretSpecRetrySettings(**retry_settings)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__c88f3beb5eebe3642bd7625e948d35a224c53cc7572853ef902f398263266288)
            check_type(argname="argument path", value=path, expected_type=type_hints["path"])
            check_type(argname="argument provider", value=provider, expected_type=type_hints["provider"])
            check_type(argname="argument allow_empty_response", value=allow_empty_response, expected_type=type_hints["allow_empty_response"])
            check_type(argname="argument controller", value=controller, expected_type=type_hints["controller"])
            check_type(argname="argument method", value=method, expected_type=type_hints["method"])
            check_type(argname="argument parameters", value=parameters, expected_type=type_hints["parameters"])
            check_type(argname="argument result_type", value=result_type, expected_type=type_hints["result_type"])
            check_type(argname="argument retry_settings", value=retry_settings, expected_type=type_hints["retry_settings"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "path": path,
            "provider": provider,
        }
        if allow_empty_response is not None:
            self._values["allow_empty_response"] = allow_empty_response
        if controller is not None:
            self._values["controller"] = controller
        if method is not None:
            self._values["method"] = method
        if parameters is not None:
            self._values["parameters"] = parameters
        if result_type is not None:
            self._values["result_type"] = result_type
        if retry_settings is not None:
            self._values["retry_settings"] = retry_settings

    @builtins.property
    def path(self) -> builtins.str:
        '''Vault path to obtain the dynamic secret from.

        :schema: VaultDynamicSecretSpec#path
        '''
        result = self._values.get("path")
        assert result is not None, "Required property 'path' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def provider(self) -> "VaultDynamicSecretSpecProvider":
        '''Vault provider common spec.

        :schema: VaultDynamicSecretSpec#provider
        '''
        result = self._values.get("provider")
        assert result is not None, "Required property 'provider' is missing"
        return typing.cast("VaultDynamicSecretSpecProvider", result)

    @builtins.property
    def allow_empty_response(self) -> typing.Optional[builtins.bool]:
        '''Do not fail if no secrets are found.

        Useful for requests where no data is expected.

        :schema: VaultDynamicSecretSpec#allowEmptyResponse
        '''
        result = self._values.get("allow_empty_response")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def controller(self) -> typing.Optional[builtins.str]:
        '''Used to select the correct ESO controller (think: ingress.ingressClassName) The ESO controller is instantiated with a specific controller name and filters VDS based on this property.

        :schema: VaultDynamicSecretSpec#controller
        '''
        result = self._values.get("controller")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def method(self) -> typing.Optional[builtins.str]:
        '''Vault API method to use (GET/POST/other).

        :schema: VaultDynamicSecretSpec#method
        '''
        result = self._values.get("method")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def parameters(self) -> typing.Any:
        '''Parameters to pass to Vault write (for non-GET methods).

        :schema: VaultDynamicSecretSpec#parameters
        '''
        result = self._values.get("parameters")
        return typing.cast(typing.Any, result)

    @builtins.property
    def result_type(self) -> typing.Optional["VaultDynamicSecretSpecResultType"]:
        '''Result type defines which data is returned from the generator.

        By default it is the "data" section of the Vault API response.
        When using e.g. /auth/token/create the "data" section is empty but
        the "auth" section contains the generated token.
        Please refer to the vault docs regarding the result data structure.
        Additionally, accessing the raw response is possibly by using "Raw" result type.

        :schema: VaultDynamicSecretSpec#resultType
        '''
        result = self._values.get("result_type")
        return typing.cast(typing.Optional["VaultDynamicSecretSpecResultType"], result)

    @builtins.property
    def retry_settings(self) -> typing.Optional["VaultDynamicSecretSpecRetrySettings"]:
        '''Used to configure http retries if failed.

        :schema: VaultDynamicSecretSpec#retrySettings
        '''
        result = self._values.get("retry_settings")
        return typing.cast(typing.Optional["VaultDynamicSecretSpecRetrySettings"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretSpec(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProvider",
    jsii_struct_bases=[],
    name_mapping={
        "server": "server",
        "auth": "auth",
        "ca_bundle": "caBundle",
        "ca_provider": "caProvider",
        "forward_inconsistent": "forwardInconsistent",
        "headers": "headers",
        "namespace": "namespace",
        "path": "path",
        "read_your_writes": "readYourWrites",
        "tls": "tls",
        "version": "version",
    },
)
class VaultDynamicSecretSpecProvider:
    def __init__(
        self,
        *,
        server: builtins.str,
        auth: typing.Optional[typing.Union["VaultDynamicSecretSpecProviderAuth", typing.Dict[builtins.str, typing.Any]]] = None,
        ca_bundle: typing.Optional[builtins.str] = None,
        ca_provider: typing.Optional[typing.Union["VaultDynamicSecretSpecProviderCaProvider", typing.Dict[builtins.str, typing.Any]]] = None,
        forward_inconsistent: typing.Optional[builtins.bool] = None,
        headers: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        namespace: typing.Optional[builtins.str] = None,
        path: typing.Optional[builtins.str] = None,
        read_your_writes: typing.Optional[builtins.bool] = None,
        tls: typing.Optional[typing.Union["VaultDynamicSecretSpecProviderTls", typing.Dict[builtins.str, typing.Any]]] = None,
        version: typing.Optional["VaultDynamicSecretSpecProviderVersion"] = None,
    ) -> None:
        '''Vault provider common spec.

        :param server: Server is the connection address for the Vault server, e.g: "https://vault.example.com:8200".
        :param auth: Auth configures how secret-manager authenticates with the Vault server.
        :param ca_bundle: PEM encoded CA bundle used to validate Vault server certificate. Only used if the Server URL is using HTTPS protocol. This parameter is ignored for plain HTTP protocol connection. If not set the system root certificates are used to validate the TLS connection.
        :param ca_provider: The provider for the CA bundle to use to validate Vault server certificate.
        :param forward_inconsistent: ForwardInconsistent tells Vault to forward read-after-write requests to the Vault leader instead of simply retrying within a loop. This can increase performance if the option is enabled serverside. https://www.vaultproject.io/docs/configuration/replication#allow_forwarding_via_header
        :param headers: Headers to be added in Vault request.
        :param namespace: Name of the vault namespace. Namespaces is a set of features within Vault Enterprise that allows Vault environments to support Secure Multi-tenancy. e.g: "ns1". More about namespaces can be found here https://www.vaultproject.io/docs/enterprise/namespaces
        :param path: Path is the mount path of the Vault KV backend endpoint, e.g: "secret". The v2 KV secret engine version specific "/data" path suffix for fetching secrets from Vault is optional and will be appended if not present in specified path.
        :param read_your_writes: ReadYourWrites ensures isolated read-after-write semantics by providing discovered cluster replication states in each request. More information about eventual consistency in Vault can be found here https://www.vaultproject.io/docs/enterprise/consistency
        :param tls: The configuration used for client side related TLS communication, when the Vault server requires mutual authentication. Only used if the Server URL is using HTTPS protocol. This parameter is ignored for plain HTTP protocol connection. It's worth noting this configuration is different from the "TLS certificates auth method", which is available under the ``auth.cert`` section.
        :param version: Version is the Vault KV secret engine version. This can be either "v1" or "v2". Version defaults to "v2".

        :schema: VaultDynamicSecretSpecProvider
        '''
        if isinstance(auth, dict):
            auth = VaultDynamicSecretSpecProviderAuth(**auth)
        if isinstance(ca_provider, dict):
            ca_provider = VaultDynamicSecretSpecProviderCaProvider(**ca_provider)
        if isinstance(tls, dict):
            tls = VaultDynamicSecretSpecProviderTls(**tls)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__99bb9f6b265462d6cb37ae7c7ac1a897af8d4eca0e046b25280a6a5eb0ddf60a)
            check_type(argname="argument server", value=server, expected_type=type_hints["server"])
            check_type(argname="argument auth", value=auth, expected_type=type_hints["auth"])
            check_type(argname="argument ca_bundle", value=ca_bundle, expected_type=type_hints["ca_bundle"])
            check_type(argname="argument ca_provider", value=ca_provider, expected_type=type_hints["ca_provider"])
            check_type(argname="argument forward_inconsistent", value=forward_inconsistent, expected_type=type_hints["forward_inconsistent"])
            check_type(argname="argument headers", value=headers, expected_type=type_hints["headers"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
            check_type(argname="argument path", value=path, expected_type=type_hints["path"])
            check_type(argname="argument read_your_writes", value=read_your_writes, expected_type=type_hints["read_your_writes"])
            check_type(argname="argument tls", value=tls, expected_type=type_hints["tls"])
            check_type(argname="argument version", value=version, expected_type=type_hints["version"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "server": server,
        }
        if auth is not None:
            self._values["auth"] = auth
        if ca_bundle is not None:
            self._values["ca_bundle"] = ca_bundle
        if ca_provider is not None:
            self._values["ca_provider"] = ca_provider
        if forward_inconsistent is not None:
            self._values["forward_inconsistent"] = forward_inconsistent
        if headers is not None:
            self._values["headers"] = headers
        if namespace is not None:
            self._values["namespace"] = namespace
        if path is not None:
            self._values["path"] = path
        if read_your_writes is not None:
            self._values["read_your_writes"] = read_your_writes
        if tls is not None:
            self._values["tls"] = tls
        if version is not None:
            self._values["version"] = version

    @builtins.property
    def server(self) -> builtins.str:
        '''Server is the connection address for the Vault server, e.g: "https://vault.example.com:8200".

        :schema: VaultDynamicSecretSpecProvider#server
        '''
        result = self._values.get("server")
        assert result is not None, "Required property 'server' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def auth(self) -> typing.Optional["VaultDynamicSecretSpecProviderAuth"]:
        '''Auth configures how secret-manager authenticates with the Vault server.

        :schema: VaultDynamicSecretSpecProvider#auth
        '''
        result = self._values.get("auth")
        return typing.cast(typing.Optional["VaultDynamicSecretSpecProviderAuth"], result)

    @builtins.property
    def ca_bundle(self) -> typing.Optional[builtins.str]:
        '''PEM encoded CA bundle used to validate Vault server certificate.

        Only used
        if the Server URL is using HTTPS protocol. This parameter is ignored for
        plain HTTP protocol connection. If not set the system root certificates
        are used to validate the TLS connection.

        :schema: VaultDynamicSecretSpecProvider#caBundle
        '''
        result = self._values.get("ca_bundle")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ca_provider(
        self,
    ) -> typing.Optional["VaultDynamicSecretSpecProviderCaProvider"]:
        '''The provider for the CA bundle to use to validate Vault server certificate.

        :schema: VaultDynamicSecretSpecProvider#caProvider
        '''
        result = self._values.get("ca_provider")
        return typing.cast(typing.Optional["VaultDynamicSecretSpecProviderCaProvider"], result)

    @builtins.property
    def forward_inconsistent(self) -> typing.Optional[builtins.bool]:
        '''ForwardInconsistent tells Vault to forward read-after-write requests to the Vault leader instead of simply retrying within a loop.

        This can increase performance if
        the option is enabled serverside.
        https://www.vaultproject.io/docs/configuration/replication#allow_forwarding_via_header

        :schema: VaultDynamicSecretSpecProvider#forwardInconsistent
        '''
        result = self._values.get("forward_inconsistent")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def headers(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Headers to be added in Vault request.

        :schema: VaultDynamicSecretSpecProvider#headers
        '''
        result = self._values.get("headers")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''Name of the vault namespace.

        Namespaces is a set of features within Vault Enterprise that allows
        Vault environments to support Secure Multi-tenancy. e.g: "ns1".
        More about namespaces can be found here https://www.vaultproject.io/docs/enterprise/namespaces

        :schema: VaultDynamicSecretSpecProvider#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def path(self) -> typing.Optional[builtins.str]:
        '''Path is the mount path of the Vault KV backend endpoint, e.g: "secret". The v2 KV secret engine version specific "/data" path suffix for fetching secrets from Vault is optional and will be appended if not present in specified path.

        :schema: VaultDynamicSecretSpecProvider#path
        '''
        result = self._values.get("path")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def read_your_writes(self) -> typing.Optional[builtins.bool]:
        '''ReadYourWrites ensures isolated read-after-write semantics by providing discovered cluster replication states in each request.

        More information about eventual consistency in Vault can be found here
        https://www.vaultproject.io/docs/enterprise/consistency

        :schema: VaultDynamicSecretSpecProvider#readYourWrites
        '''
        result = self._values.get("read_your_writes")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def tls(self) -> typing.Optional["VaultDynamicSecretSpecProviderTls"]:
        '''The configuration used for client side related TLS communication, when the Vault server requires mutual authentication.

        Only used if the Server URL is using HTTPS protocol.
        This parameter is ignored for plain HTTP protocol connection.
        It's worth noting this configuration is different from the "TLS certificates auth method",
        which is available under the ``auth.cert`` section.

        :schema: VaultDynamicSecretSpecProvider#tls
        '''
        result = self._values.get("tls")
        return typing.cast(typing.Optional["VaultDynamicSecretSpecProviderTls"], result)

    @builtins.property
    def version(self) -> typing.Optional["VaultDynamicSecretSpecProviderVersion"]:
        '''Version is the Vault KV secret engine version.

        This can be either "v1" or
        "v2". Version defaults to "v2".

        :schema: VaultDynamicSecretSpecProvider#version
        '''
        result = self._values.get("version")
        return typing.cast(typing.Optional["VaultDynamicSecretSpecProviderVersion"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretSpecProvider(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProviderAuth",
    jsii_struct_bases=[],
    name_mapping={
        "app_role": "appRole",
        "cert": "cert",
        "iam": "iam",
        "jwt": "jwt",
        "kubernetes": "kubernetes",
        "ldap": "ldap",
        "namespace": "namespace",
        "token_secret_ref": "tokenSecretRef",
        "user_pass": "userPass",
    },
)
class VaultDynamicSecretSpecProviderAuth:
    def __init__(
        self,
        *,
        app_role: typing.Optional[typing.Union["VaultDynamicSecretSpecProviderAuthAppRole", typing.Dict[builtins.str, typing.Any]]] = None,
        cert: typing.Optional[typing.Union["VaultDynamicSecretSpecProviderAuthCert", typing.Dict[builtins.str, typing.Any]]] = None,
        iam: typing.Optional[typing.Union["VaultDynamicSecretSpecProviderAuthIam", typing.Dict[builtins.str, typing.Any]]] = None,
        jwt: typing.Optional[typing.Union["VaultDynamicSecretSpecProviderAuthJwt", typing.Dict[builtins.str, typing.Any]]] = None,
        kubernetes: typing.Optional[typing.Union["VaultDynamicSecretSpecProviderAuthKubernetes", typing.Dict[builtins.str, typing.Any]]] = None,
        ldap: typing.Optional[typing.Union["VaultDynamicSecretSpecProviderAuthLdap", typing.Dict[builtins.str, typing.Any]]] = None,
        namespace: typing.Optional[builtins.str] = None,
        token_secret_ref: typing.Optional[typing.Union["VaultDynamicSecretSpecProviderAuthTokenSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
        user_pass: typing.Optional[typing.Union["VaultDynamicSecretSpecProviderAuthUserPass", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Auth configures how secret-manager authenticates with the Vault server.

        :param app_role: AppRole authenticates with Vault using the App Role auth mechanism, with the role and secret stored in a Kubernetes Secret resource.
        :param cert: Cert authenticates with TLS Certificates by passing client certificate, private key and ca certificate Cert authentication method.
        :param iam: Iam authenticates with vault by passing a special AWS request signed with AWS IAM credentials AWS IAM authentication method.
        :param jwt: Jwt authenticates with Vault by passing role and JWT token using the JWT/OIDC authentication method.
        :param kubernetes: Kubernetes authenticates with Vault by passing the ServiceAccount token stored in the named Secret resource to the Vault server.
        :param ldap: Ldap authenticates with Vault by passing username/password pair using the LDAP authentication method.
        :param namespace: Name of the vault namespace to authenticate to. This can be different than the namespace your secret is in. Namespaces is a set of features within Vault Enterprise that allows Vault environments to support Secure Multi-tenancy. e.g: "ns1". More about namespaces can be found here https://www.vaultproject.io/docs/enterprise/namespaces This will default to Vault.Namespace field if set, or empty otherwise
        :param token_secret_ref: TokenSecretRef authenticates with Vault by presenting a token.
        :param user_pass: UserPass authenticates with Vault by passing username/password pair.

        :schema: VaultDynamicSecretSpecProviderAuth
        '''
        if isinstance(app_role, dict):
            app_role = VaultDynamicSecretSpecProviderAuthAppRole(**app_role)
        if isinstance(cert, dict):
            cert = VaultDynamicSecretSpecProviderAuthCert(**cert)
        if isinstance(iam, dict):
            iam = VaultDynamicSecretSpecProviderAuthIam(**iam)
        if isinstance(jwt, dict):
            jwt = VaultDynamicSecretSpecProviderAuthJwt(**jwt)
        if isinstance(kubernetes, dict):
            kubernetes = VaultDynamicSecretSpecProviderAuthKubernetes(**kubernetes)
        if isinstance(ldap, dict):
            ldap = VaultDynamicSecretSpecProviderAuthLdap(**ldap)
        if isinstance(token_secret_ref, dict):
            token_secret_ref = VaultDynamicSecretSpecProviderAuthTokenSecretRef(**token_secret_ref)
        if isinstance(user_pass, dict):
            user_pass = VaultDynamicSecretSpecProviderAuthUserPass(**user_pass)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__f1db161975aac815c821c159e465d76a46225986d5820ef576591b42b9f95fc1)
            check_type(argname="argument app_role", value=app_role, expected_type=type_hints["app_role"])
            check_type(argname="argument cert", value=cert, expected_type=type_hints["cert"])
            check_type(argname="argument iam", value=iam, expected_type=type_hints["iam"])
            check_type(argname="argument jwt", value=jwt, expected_type=type_hints["jwt"])
            check_type(argname="argument kubernetes", value=kubernetes, expected_type=type_hints["kubernetes"])
            check_type(argname="argument ldap", value=ldap, expected_type=type_hints["ldap"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
            check_type(argname="argument token_secret_ref", value=token_secret_ref, expected_type=type_hints["token_secret_ref"])
            check_type(argname="argument user_pass", value=user_pass, expected_type=type_hints["user_pass"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if app_role is not None:
            self._values["app_role"] = app_role
        if cert is not None:
            self._values["cert"] = cert
        if iam is not None:
            self._values["iam"] = iam
        if jwt is not None:
            self._values["jwt"] = jwt
        if kubernetes is not None:
            self._values["kubernetes"] = kubernetes
        if ldap is not None:
            self._values["ldap"] = ldap
        if namespace is not None:
            self._values["namespace"] = namespace
        if token_secret_ref is not None:
            self._values["token_secret_ref"] = token_secret_ref
        if user_pass is not None:
            self._values["user_pass"] = user_pass

    @builtins.property
    def app_role(self) -> typing.Optional["VaultDynamicSecretSpecProviderAuthAppRole"]:
        '''AppRole authenticates with Vault using the App Role auth mechanism, with the role and secret stored in a Kubernetes Secret resource.

        :schema: VaultDynamicSecretSpecProviderAuth#appRole
        '''
        result = self._values.get("app_role")
        return typing.cast(typing.Optional["VaultDynamicSecretSpecProviderAuthAppRole"], result)

    @builtins.property
    def cert(self) -> typing.Optional["VaultDynamicSecretSpecProviderAuthCert"]:
        '''Cert authenticates with TLS Certificates by passing client certificate, private key and ca certificate Cert authentication method.

        :schema: VaultDynamicSecretSpecProviderAuth#cert
        '''
        result = self._values.get("cert")
        return typing.cast(typing.Optional["VaultDynamicSecretSpecProviderAuthCert"], result)

    @builtins.property
    def iam(self) -> typing.Optional["VaultDynamicSecretSpecProviderAuthIam"]:
        '''Iam authenticates with vault by passing a special AWS request signed with AWS IAM credentials AWS IAM authentication method.

        :schema: VaultDynamicSecretSpecProviderAuth#iam
        '''
        result = self._values.get("iam")
        return typing.cast(typing.Optional["VaultDynamicSecretSpecProviderAuthIam"], result)

    @builtins.property
    def jwt(self) -> typing.Optional["VaultDynamicSecretSpecProviderAuthJwt"]:
        '''Jwt authenticates with Vault by passing role and JWT token using the JWT/OIDC authentication method.

        :schema: VaultDynamicSecretSpecProviderAuth#jwt
        '''
        result = self._values.get("jwt")
        return typing.cast(typing.Optional["VaultDynamicSecretSpecProviderAuthJwt"], result)

    @builtins.property
    def kubernetes(
        self,
    ) -> typing.Optional["VaultDynamicSecretSpecProviderAuthKubernetes"]:
        '''Kubernetes authenticates with Vault by passing the ServiceAccount token stored in the named Secret resource to the Vault server.

        :schema: VaultDynamicSecretSpecProviderAuth#kubernetes
        '''
        result = self._values.get("kubernetes")
        return typing.cast(typing.Optional["VaultDynamicSecretSpecProviderAuthKubernetes"], result)

    @builtins.property
    def ldap(self) -> typing.Optional["VaultDynamicSecretSpecProviderAuthLdap"]:
        '''Ldap authenticates with Vault by passing username/password pair using the LDAP authentication method.

        :schema: VaultDynamicSecretSpecProviderAuth#ldap
        '''
        result = self._values.get("ldap")
        return typing.cast(typing.Optional["VaultDynamicSecretSpecProviderAuthLdap"], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''Name of the vault namespace to authenticate to.

        This can be different than the namespace your secret is in.
        Namespaces is a set of features within Vault Enterprise that allows
        Vault environments to support Secure Multi-tenancy. e.g: "ns1".
        More about namespaces can be found here https://www.vaultproject.io/docs/enterprise/namespaces
        This will default to Vault.Namespace field if set, or empty otherwise

        :schema: VaultDynamicSecretSpecProviderAuth#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def token_secret_ref(
        self,
    ) -> typing.Optional["VaultDynamicSecretSpecProviderAuthTokenSecretRef"]:
        '''TokenSecretRef authenticates with Vault by presenting a token.

        :schema: VaultDynamicSecretSpecProviderAuth#tokenSecretRef
        '''
        result = self._values.get("token_secret_ref")
        return typing.cast(typing.Optional["VaultDynamicSecretSpecProviderAuthTokenSecretRef"], result)

    @builtins.property
    def user_pass(
        self,
    ) -> typing.Optional["VaultDynamicSecretSpecProviderAuthUserPass"]:
        '''UserPass authenticates with Vault by passing username/password pair.

        :schema: VaultDynamicSecretSpecProviderAuth#userPass
        '''
        result = self._values.get("user_pass")
        return typing.cast(typing.Optional["VaultDynamicSecretSpecProviderAuthUserPass"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretSpecProviderAuth(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProviderAuthAppRole",
    jsii_struct_bases=[],
    name_mapping={
        "path": "path",
        "secret_ref": "secretRef",
        "role_id": "roleId",
        "role_ref": "roleRef",
    },
)
class VaultDynamicSecretSpecProviderAuthAppRole:
    def __init__(
        self,
        *,
        path: builtins.str,
        secret_ref: typing.Union["VaultDynamicSecretSpecProviderAuthAppRoleSecretRef", typing.Dict[builtins.str, typing.Any]],
        role_id: typing.Optional[builtins.str] = None,
        role_ref: typing.Optional[typing.Union["VaultDynamicSecretSpecProviderAuthAppRoleRoleRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''AppRole authenticates with Vault using the App Role auth mechanism, with the role and secret stored in a Kubernetes Secret resource.

        :param path: Path where the App Role authentication backend is mounted in Vault, e.g: "approle".
        :param secret_ref: Reference to a key in a Secret that contains the App Role secret used to authenticate with Vault. The ``key`` field must be specified and denotes which entry within the Secret resource is used as the app role secret.
        :param role_id: RoleID configured in the App Role authentication backend when setting up the authentication backend in Vault.
        :param role_ref: Reference to a key in a Secret that contains the App Role ID used to authenticate with Vault. The ``key`` field must be specified and denotes which entry within the Secret resource is used as the app role id.

        :schema: VaultDynamicSecretSpecProviderAuthAppRole
        '''
        if isinstance(secret_ref, dict):
            secret_ref = VaultDynamicSecretSpecProviderAuthAppRoleSecretRef(**secret_ref)
        if isinstance(role_ref, dict):
            role_ref = VaultDynamicSecretSpecProviderAuthAppRoleRoleRef(**role_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__694b810088d74c88cb73306a438e0a284a0bdb9de47b1cb32eaa3818cdce846b)
            check_type(argname="argument path", value=path, expected_type=type_hints["path"])
            check_type(argname="argument secret_ref", value=secret_ref, expected_type=type_hints["secret_ref"])
            check_type(argname="argument role_id", value=role_id, expected_type=type_hints["role_id"])
            check_type(argname="argument role_ref", value=role_ref, expected_type=type_hints["role_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "path": path,
            "secret_ref": secret_ref,
        }
        if role_id is not None:
            self._values["role_id"] = role_id
        if role_ref is not None:
            self._values["role_ref"] = role_ref

    @builtins.property
    def path(self) -> builtins.str:
        '''Path where the App Role authentication backend is mounted in Vault, e.g: "approle".

        :schema: VaultDynamicSecretSpecProviderAuthAppRole#path
        '''
        result = self._values.get("path")
        assert result is not None, "Required property 'path' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def secret_ref(self) -> "VaultDynamicSecretSpecProviderAuthAppRoleSecretRef":
        '''Reference to a key in a Secret that contains the App Role secret used to authenticate with Vault.

        The ``key`` field must be specified and denotes which entry within the Secret
        resource is used as the app role secret.

        :schema: VaultDynamicSecretSpecProviderAuthAppRole#secretRef
        '''
        result = self._values.get("secret_ref")
        assert result is not None, "Required property 'secret_ref' is missing"
        return typing.cast("VaultDynamicSecretSpecProviderAuthAppRoleSecretRef", result)

    @builtins.property
    def role_id(self) -> typing.Optional[builtins.str]:
        '''RoleID configured in the App Role authentication backend when setting up the authentication backend in Vault.

        :schema: VaultDynamicSecretSpecProviderAuthAppRole#roleId
        '''
        result = self._values.get("role_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def role_ref(
        self,
    ) -> typing.Optional["VaultDynamicSecretSpecProviderAuthAppRoleRoleRef"]:
        '''Reference to a key in a Secret that contains the App Role ID used to authenticate with Vault.

        The ``key`` field must be specified and denotes which entry within the Secret
        resource is used as the app role id.

        :schema: VaultDynamicSecretSpecProviderAuthAppRole#roleRef
        '''
        result = self._values.get("role_ref")
        return typing.cast(typing.Optional["VaultDynamicSecretSpecProviderAuthAppRoleRoleRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretSpecProviderAuthAppRole(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProviderAuthAppRoleRoleRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class VaultDynamicSecretSpecProviderAuthAppRoleRoleRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Reference to a key in a Secret that contains the App Role ID used to authenticate with Vault.

        The ``key`` field must be specified and denotes which entry within the Secret
        resource is used as the app role id.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderAuthAppRoleRoleRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__9a99fb0e822f1799fd218437bfc9f0467860abc0b235c8c0ec53c1588fa7694c)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: VaultDynamicSecretSpecProviderAuthAppRoleRoleRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: VaultDynamicSecretSpecProviderAuthAppRoleRoleRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderAuthAppRoleRoleRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretSpecProviderAuthAppRoleRoleRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProviderAuthAppRoleSecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class VaultDynamicSecretSpecProviderAuthAppRoleSecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Reference to a key in a Secret that contains the App Role secret used to authenticate with Vault.

        The ``key`` field must be specified and denotes which entry within the Secret
        resource is used as the app role secret.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderAuthAppRoleSecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__06f75a4d6e7bdddfad29285d9805b199b2095b6b69e37f08c865b2d156007b9e)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: VaultDynamicSecretSpecProviderAuthAppRoleSecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: VaultDynamicSecretSpecProviderAuthAppRoleSecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderAuthAppRoleSecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretSpecProviderAuthAppRoleSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProviderAuthCert",
    jsii_struct_bases=[],
    name_mapping={"client_cert": "clientCert", "secret_ref": "secretRef"},
)
class VaultDynamicSecretSpecProviderAuthCert:
    def __init__(
        self,
        *,
        client_cert: typing.Optional[typing.Union["VaultDynamicSecretSpecProviderAuthCertClientCert", typing.Dict[builtins.str, typing.Any]]] = None,
        secret_ref: typing.Optional[typing.Union["VaultDynamicSecretSpecProviderAuthCertSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Cert authenticates with TLS Certificates by passing client certificate, private key and ca certificate Cert authentication method.

        :param client_cert: ClientCert is a certificate to authenticate using the Cert Vault authentication method.
        :param secret_ref: SecretRef to a key in a Secret resource containing client private key to authenticate with Vault using the Cert authentication method.

        :schema: VaultDynamicSecretSpecProviderAuthCert
        '''
        if isinstance(client_cert, dict):
            client_cert = VaultDynamicSecretSpecProviderAuthCertClientCert(**client_cert)
        if isinstance(secret_ref, dict):
            secret_ref = VaultDynamicSecretSpecProviderAuthCertSecretRef(**secret_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__397dacbf5d6cbf9d8bfbc50e753f1950aee0b37fec712f2c76630a0668f3e146)
            check_type(argname="argument client_cert", value=client_cert, expected_type=type_hints["client_cert"])
            check_type(argname="argument secret_ref", value=secret_ref, expected_type=type_hints["secret_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if client_cert is not None:
            self._values["client_cert"] = client_cert
        if secret_ref is not None:
            self._values["secret_ref"] = secret_ref

    @builtins.property
    def client_cert(
        self,
    ) -> typing.Optional["VaultDynamicSecretSpecProviderAuthCertClientCert"]:
        '''ClientCert is a certificate to authenticate using the Cert Vault authentication method.

        :schema: VaultDynamicSecretSpecProviderAuthCert#clientCert
        '''
        result = self._values.get("client_cert")
        return typing.cast(typing.Optional["VaultDynamicSecretSpecProviderAuthCertClientCert"], result)

    @builtins.property
    def secret_ref(
        self,
    ) -> typing.Optional["VaultDynamicSecretSpecProviderAuthCertSecretRef"]:
        '''SecretRef to a key in a Secret resource containing client private key to authenticate with Vault using the Cert authentication method.

        :schema: VaultDynamicSecretSpecProviderAuthCert#secretRef
        '''
        result = self._values.get("secret_ref")
        return typing.cast(typing.Optional["VaultDynamicSecretSpecProviderAuthCertSecretRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretSpecProviderAuthCert(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProviderAuthCertClientCert",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class VaultDynamicSecretSpecProviderAuthCertClientCert:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''ClientCert is a certificate to authenticate using the Cert Vault authentication method.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderAuthCertClientCert
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__b58294432d7c518baeb64f016bfac88a09ffd8adf9b8ca535499fa3213151182)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: VaultDynamicSecretSpecProviderAuthCertClientCert#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: VaultDynamicSecretSpecProviderAuthCertClientCert#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderAuthCertClientCert#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretSpecProviderAuthCertClientCert(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProviderAuthCertSecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class VaultDynamicSecretSpecProviderAuthCertSecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''SecretRef to a key in a Secret resource containing client private key to authenticate with Vault using the Cert authentication method.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderAuthCertSecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__68ed331536c95241f0ddad3378cad046ddd93e6a48174ce994cb1df3a464d36a)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: VaultDynamicSecretSpecProviderAuthCertSecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: VaultDynamicSecretSpecProviderAuthCertSecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderAuthCertSecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretSpecProviderAuthCertSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProviderAuthIam",
    jsii_struct_bases=[],
    name_mapping={
        "vault_role": "vaultRole",
        "external_id": "externalId",
        "jwt": "jwt",
        "path": "path",
        "region": "region",
        "role": "role",
        "secret_ref": "secretRef",
        "vault_aws_iam_server_id": "vaultAwsIamServerId",
    },
)
class VaultDynamicSecretSpecProviderAuthIam:
    def __init__(
        self,
        *,
        vault_role: builtins.str,
        external_id: typing.Optional[builtins.str] = None,
        jwt: typing.Optional[typing.Union["VaultDynamicSecretSpecProviderAuthIamJwt", typing.Dict[builtins.str, typing.Any]]] = None,
        path: typing.Optional[builtins.str] = None,
        region: typing.Optional[builtins.str] = None,
        role: typing.Optional[builtins.str] = None,
        secret_ref: typing.Optional[typing.Union["VaultDynamicSecretSpecProviderAuthIamSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
        vault_aws_iam_server_id: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Iam authenticates with vault by passing a special AWS request signed with AWS IAM credentials AWS IAM authentication method.

        :param vault_role: Vault Role. In vault, a role describes an identity with a set of permissions, groups, or policies you want to attach a user of the secrets engine
        :param external_id: AWS External ID set on assumed IAM roles.
        :param jwt: Specify a service account with IRSA enabled.
        :param path: Path where the AWS auth method is enabled in Vault, e.g: "aws".
        :param region: AWS region.
        :param role: This is the AWS role to be assumed before talking to vault.
        :param secret_ref: Specify credentials in a Secret object.
        :param vault_aws_iam_server_id: X-Vault-AWS-IAM-Server-ID is an additional header used by Vault IAM auth method to mitigate against different types of replay attacks. More details here: https://developer.hashicorp.com/vault/docs/auth/aws

        :schema: VaultDynamicSecretSpecProviderAuthIam
        '''
        if isinstance(jwt, dict):
            jwt = VaultDynamicSecretSpecProviderAuthIamJwt(**jwt)
        if isinstance(secret_ref, dict):
            secret_ref = VaultDynamicSecretSpecProviderAuthIamSecretRef(**secret_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__5af38260f87760cdeb000f50b6301f4794251e13a7b1b9767e70922eb3c2176c)
            check_type(argname="argument vault_role", value=vault_role, expected_type=type_hints["vault_role"])
            check_type(argname="argument external_id", value=external_id, expected_type=type_hints["external_id"])
            check_type(argname="argument jwt", value=jwt, expected_type=type_hints["jwt"])
            check_type(argname="argument path", value=path, expected_type=type_hints["path"])
            check_type(argname="argument region", value=region, expected_type=type_hints["region"])
            check_type(argname="argument role", value=role, expected_type=type_hints["role"])
            check_type(argname="argument secret_ref", value=secret_ref, expected_type=type_hints["secret_ref"])
            check_type(argname="argument vault_aws_iam_server_id", value=vault_aws_iam_server_id, expected_type=type_hints["vault_aws_iam_server_id"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "vault_role": vault_role,
        }
        if external_id is not None:
            self._values["external_id"] = external_id
        if jwt is not None:
            self._values["jwt"] = jwt
        if path is not None:
            self._values["path"] = path
        if region is not None:
            self._values["region"] = region
        if role is not None:
            self._values["role"] = role
        if secret_ref is not None:
            self._values["secret_ref"] = secret_ref
        if vault_aws_iam_server_id is not None:
            self._values["vault_aws_iam_server_id"] = vault_aws_iam_server_id

    @builtins.property
    def vault_role(self) -> builtins.str:
        '''Vault Role.

        In vault, a role describes an identity with a set of permissions, groups, or policies you want to attach a user of the secrets engine

        :schema: VaultDynamicSecretSpecProviderAuthIam#vaultRole
        '''
        result = self._values.get("vault_role")
        assert result is not None, "Required property 'vault_role' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def external_id(self) -> typing.Optional[builtins.str]:
        '''AWS External ID set on assumed IAM roles.

        :schema: VaultDynamicSecretSpecProviderAuthIam#externalID
        '''
        result = self._values.get("external_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def jwt(self) -> typing.Optional["VaultDynamicSecretSpecProviderAuthIamJwt"]:
        '''Specify a service account with IRSA enabled.

        :schema: VaultDynamicSecretSpecProviderAuthIam#jwt
        '''
        result = self._values.get("jwt")
        return typing.cast(typing.Optional["VaultDynamicSecretSpecProviderAuthIamJwt"], result)

    @builtins.property
    def path(self) -> typing.Optional[builtins.str]:
        '''Path where the AWS auth method is enabled in Vault, e.g: "aws".

        :schema: VaultDynamicSecretSpecProviderAuthIam#path
        '''
        result = self._values.get("path")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def region(self) -> typing.Optional[builtins.str]:
        '''AWS region.

        :schema: VaultDynamicSecretSpecProviderAuthIam#region
        '''
        result = self._values.get("region")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def role(self) -> typing.Optional[builtins.str]:
        '''This is the AWS role to be assumed before talking to vault.

        :schema: VaultDynamicSecretSpecProviderAuthIam#role
        '''
        result = self._values.get("role")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def secret_ref(
        self,
    ) -> typing.Optional["VaultDynamicSecretSpecProviderAuthIamSecretRef"]:
        '''Specify credentials in a Secret object.

        :schema: VaultDynamicSecretSpecProviderAuthIam#secretRef
        '''
        result = self._values.get("secret_ref")
        return typing.cast(typing.Optional["VaultDynamicSecretSpecProviderAuthIamSecretRef"], result)

    @builtins.property
    def vault_aws_iam_server_id(self) -> typing.Optional[builtins.str]:
        '''X-Vault-AWS-IAM-Server-ID is an additional header used by Vault IAM auth method to mitigate against different types of replay attacks.

        More details here: https://developer.hashicorp.com/vault/docs/auth/aws

        :schema: VaultDynamicSecretSpecProviderAuthIam#vaultAwsIamServerID
        '''
        result = self._values.get("vault_aws_iam_server_id")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretSpecProviderAuthIam(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProviderAuthIamJwt",
    jsii_struct_bases=[],
    name_mapping={"service_account_ref": "serviceAccountRef"},
)
class VaultDynamicSecretSpecProviderAuthIamJwt:
    def __init__(
        self,
        *,
        service_account_ref: typing.Optional[typing.Union["VaultDynamicSecretSpecProviderAuthIamJwtServiceAccountRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Specify a service account with IRSA enabled.

        :param service_account_ref: A reference to a ServiceAccount resource.

        :schema: VaultDynamicSecretSpecProviderAuthIamJwt
        '''
        if isinstance(service_account_ref, dict):
            service_account_ref = VaultDynamicSecretSpecProviderAuthIamJwtServiceAccountRef(**service_account_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__755f376ef48f4b35fd53ce85e0facd33028f6681920cd7f29db5b5f121234af7)
            check_type(argname="argument service_account_ref", value=service_account_ref, expected_type=type_hints["service_account_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if service_account_ref is not None:
            self._values["service_account_ref"] = service_account_ref

    @builtins.property
    def service_account_ref(
        self,
    ) -> typing.Optional["VaultDynamicSecretSpecProviderAuthIamJwtServiceAccountRef"]:
        '''A reference to a ServiceAccount resource.

        :schema: VaultDynamicSecretSpecProviderAuthIamJwt#serviceAccountRef
        '''
        result = self._values.get("service_account_ref")
        return typing.cast(typing.Optional["VaultDynamicSecretSpecProviderAuthIamJwtServiceAccountRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretSpecProviderAuthIamJwt(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProviderAuthIamJwtServiceAccountRef",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "audiences": "audiences", "namespace": "namespace"},
)
class VaultDynamicSecretSpecProviderAuthIamJwtServiceAccountRef:
    def __init__(
        self,
        *,
        name: builtins.str,
        audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''A reference to a ServiceAccount resource.

        :param name: The name of the ServiceAccount resource being referred to.
        :param audiences: Audience specifies the ``aud`` claim for the service account token If the service account uses a well-known annotation for e.g. IRSA or GCP Workload Identity then this audiences will be appended to the list.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderAuthIamJwtServiceAccountRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__70d3aeb75a438d9acdf35b597530aafe9dafff05ff3c888b3299b63fd7af2508)
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument audiences", value=audiences, expected_type=type_hints["audiences"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "name": name,
        }
        if audiences is not None:
            self._values["audiences"] = audiences
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the ServiceAccount resource being referred to.

        :schema: VaultDynamicSecretSpecProviderAuthIamJwtServiceAccountRef#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def audiences(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Audience specifies the ``aud`` claim for the service account token If the service account uses a well-known annotation for e.g. IRSA or GCP Workload Identity then this audiences will be appended to the list.

        :schema: VaultDynamicSecretSpecProviderAuthIamJwtServiceAccountRef#audiences
        '''
        result = self._values.get("audiences")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderAuthIamJwtServiceAccountRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretSpecProviderAuthIamJwtServiceAccountRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProviderAuthIamSecretRef",
    jsii_struct_bases=[],
    name_mapping={
        "access_key_id_secret_ref": "accessKeyIdSecretRef",
        "secret_access_key_secret_ref": "secretAccessKeySecretRef",
        "session_token_secret_ref": "sessionTokenSecretRef",
    },
)
class VaultDynamicSecretSpecProviderAuthIamSecretRef:
    def __init__(
        self,
        *,
        access_key_id_secret_ref: typing.Optional[typing.Union["VaultDynamicSecretSpecProviderAuthIamSecretRefAccessKeyIdSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
        secret_access_key_secret_ref: typing.Optional[typing.Union["VaultDynamicSecretSpecProviderAuthIamSecretRefSecretAccessKeySecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
        session_token_secret_ref: typing.Optional[typing.Union["VaultDynamicSecretSpecProviderAuthIamSecretRefSessionTokenSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Specify credentials in a Secret object.

        :param access_key_id_secret_ref: The AccessKeyID is used for authentication.
        :param secret_access_key_secret_ref: The SecretAccessKey is used for authentication.
        :param session_token_secret_ref: The SessionToken used for authentication This must be defined if AccessKeyID and SecretAccessKey are temporary credentials see: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html.

        :schema: VaultDynamicSecretSpecProviderAuthIamSecretRef
        '''
        if isinstance(access_key_id_secret_ref, dict):
            access_key_id_secret_ref = VaultDynamicSecretSpecProviderAuthIamSecretRefAccessKeyIdSecretRef(**access_key_id_secret_ref)
        if isinstance(secret_access_key_secret_ref, dict):
            secret_access_key_secret_ref = VaultDynamicSecretSpecProviderAuthIamSecretRefSecretAccessKeySecretRef(**secret_access_key_secret_ref)
        if isinstance(session_token_secret_ref, dict):
            session_token_secret_ref = VaultDynamicSecretSpecProviderAuthIamSecretRefSessionTokenSecretRef(**session_token_secret_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__942078f327579ee2ec8352e78815d24d32aedc6349eeaad52e0b478df1304bf8)
            check_type(argname="argument access_key_id_secret_ref", value=access_key_id_secret_ref, expected_type=type_hints["access_key_id_secret_ref"])
            check_type(argname="argument secret_access_key_secret_ref", value=secret_access_key_secret_ref, expected_type=type_hints["secret_access_key_secret_ref"])
            check_type(argname="argument session_token_secret_ref", value=session_token_secret_ref, expected_type=type_hints["session_token_secret_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if access_key_id_secret_ref is not None:
            self._values["access_key_id_secret_ref"] = access_key_id_secret_ref
        if secret_access_key_secret_ref is not None:
            self._values["secret_access_key_secret_ref"] = secret_access_key_secret_ref
        if session_token_secret_ref is not None:
            self._values["session_token_secret_ref"] = session_token_secret_ref

    @builtins.property
    def access_key_id_secret_ref(
        self,
    ) -> typing.Optional["VaultDynamicSecretSpecProviderAuthIamSecretRefAccessKeyIdSecretRef"]:
        '''The AccessKeyID is used for authentication.

        :schema: VaultDynamicSecretSpecProviderAuthIamSecretRef#accessKeyIDSecretRef
        '''
        result = self._values.get("access_key_id_secret_ref")
        return typing.cast(typing.Optional["VaultDynamicSecretSpecProviderAuthIamSecretRefAccessKeyIdSecretRef"], result)

    @builtins.property
    def secret_access_key_secret_ref(
        self,
    ) -> typing.Optional["VaultDynamicSecretSpecProviderAuthIamSecretRefSecretAccessKeySecretRef"]:
        '''The SecretAccessKey is used for authentication.

        :schema: VaultDynamicSecretSpecProviderAuthIamSecretRef#secretAccessKeySecretRef
        '''
        result = self._values.get("secret_access_key_secret_ref")
        return typing.cast(typing.Optional["VaultDynamicSecretSpecProviderAuthIamSecretRefSecretAccessKeySecretRef"], result)

    @builtins.property
    def session_token_secret_ref(
        self,
    ) -> typing.Optional["VaultDynamicSecretSpecProviderAuthIamSecretRefSessionTokenSecretRef"]:
        '''The SessionToken used for authentication This must be defined if AccessKeyID and SecretAccessKey are temporary credentials see: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html.

        :schema: VaultDynamicSecretSpecProviderAuthIamSecretRef#sessionTokenSecretRef
        '''
        result = self._values.get("session_token_secret_ref")
        return typing.cast(typing.Optional["VaultDynamicSecretSpecProviderAuthIamSecretRefSessionTokenSecretRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretSpecProviderAuthIamSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProviderAuthIamSecretRefAccessKeyIdSecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class VaultDynamicSecretSpecProviderAuthIamSecretRefAccessKeyIdSecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''The AccessKeyID is used for authentication.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderAuthIamSecretRefAccessKeyIdSecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__5128dcc7b1f2fef664f57aac1b83767c24bc218f9a13360f6d462313905b3e3c)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: VaultDynamicSecretSpecProviderAuthIamSecretRefAccessKeyIdSecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: VaultDynamicSecretSpecProviderAuthIamSecretRefAccessKeyIdSecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderAuthIamSecretRefAccessKeyIdSecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretSpecProviderAuthIamSecretRefAccessKeyIdSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProviderAuthIamSecretRefSecretAccessKeySecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class VaultDynamicSecretSpecProviderAuthIamSecretRefSecretAccessKeySecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''The SecretAccessKey is used for authentication.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderAuthIamSecretRefSecretAccessKeySecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__62ce9ed6591f09b9ad3bf3cb73b21f380e308f0578147c37cf827dca58235336)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: VaultDynamicSecretSpecProviderAuthIamSecretRefSecretAccessKeySecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: VaultDynamicSecretSpecProviderAuthIamSecretRefSecretAccessKeySecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderAuthIamSecretRefSecretAccessKeySecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretSpecProviderAuthIamSecretRefSecretAccessKeySecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProviderAuthIamSecretRefSessionTokenSecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class VaultDynamicSecretSpecProviderAuthIamSecretRefSessionTokenSecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''The SessionToken used for authentication This must be defined if AccessKeyID and SecretAccessKey are temporary credentials see: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderAuthIamSecretRefSessionTokenSecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__5237a9d2f5bbe28b8e8561982178657c137001b1fd187bcdf16b179626d3a617)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: VaultDynamicSecretSpecProviderAuthIamSecretRefSessionTokenSecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: VaultDynamicSecretSpecProviderAuthIamSecretRefSessionTokenSecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderAuthIamSecretRefSessionTokenSecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretSpecProviderAuthIamSecretRefSessionTokenSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProviderAuthJwt",
    jsii_struct_bases=[],
    name_mapping={
        "path": "path",
        "kubernetes_service_account_token": "kubernetesServiceAccountToken",
        "role": "role",
        "secret_ref": "secretRef",
    },
)
class VaultDynamicSecretSpecProviderAuthJwt:
    def __init__(
        self,
        *,
        path: builtins.str,
        kubernetes_service_account_token: typing.Optional[typing.Union["VaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountToken", typing.Dict[builtins.str, typing.Any]]] = None,
        role: typing.Optional[builtins.str] = None,
        secret_ref: typing.Optional[typing.Union["VaultDynamicSecretSpecProviderAuthJwtSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Jwt authenticates with Vault by passing role and JWT token using the JWT/OIDC authentication method.

        :param path: Path where the JWT authentication backend is mounted in Vault, e.g: "jwt".
        :param kubernetes_service_account_token: Optional ServiceAccountToken specifies the Kubernetes service account for which to request a token for with the ``TokenRequest`` API.
        :param role: Role is a JWT role to authenticate using the JWT/OIDC Vault authentication method.
        :param secret_ref: Optional SecretRef that refers to a key in a Secret resource containing JWT token to authenticate with Vault using the JWT/OIDC authentication method.

        :schema: VaultDynamicSecretSpecProviderAuthJwt
        '''
        if isinstance(kubernetes_service_account_token, dict):
            kubernetes_service_account_token = VaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountToken(**kubernetes_service_account_token)
        if isinstance(secret_ref, dict):
            secret_ref = VaultDynamicSecretSpecProviderAuthJwtSecretRef(**secret_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__545c29132ebf0518d8533ffee2e4c0a83e6074c0d9b2e21fcae009be46669414)
            check_type(argname="argument path", value=path, expected_type=type_hints["path"])
            check_type(argname="argument kubernetes_service_account_token", value=kubernetes_service_account_token, expected_type=type_hints["kubernetes_service_account_token"])
            check_type(argname="argument role", value=role, expected_type=type_hints["role"])
            check_type(argname="argument secret_ref", value=secret_ref, expected_type=type_hints["secret_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "path": path,
        }
        if kubernetes_service_account_token is not None:
            self._values["kubernetes_service_account_token"] = kubernetes_service_account_token
        if role is not None:
            self._values["role"] = role
        if secret_ref is not None:
            self._values["secret_ref"] = secret_ref

    @builtins.property
    def path(self) -> builtins.str:
        '''Path where the JWT authentication backend is mounted in Vault, e.g: "jwt".

        :schema: VaultDynamicSecretSpecProviderAuthJwt#path
        '''
        result = self._values.get("path")
        assert result is not None, "Required property 'path' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def kubernetes_service_account_token(
        self,
    ) -> typing.Optional["VaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountToken"]:
        '''Optional ServiceAccountToken specifies the Kubernetes service account for which to request a token for with the ``TokenRequest`` API.

        :schema: VaultDynamicSecretSpecProviderAuthJwt#kubernetesServiceAccountToken
        '''
        result = self._values.get("kubernetes_service_account_token")
        return typing.cast(typing.Optional["VaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountToken"], result)

    @builtins.property
    def role(self) -> typing.Optional[builtins.str]:
        '''Role is a JWT role to authenticate using the JWT/OIDC Vault authentication method.

        :schema: VaultDynamicSecretSpecProviderAuthJwt#role
        '''
        result = self._values.get("role")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def secret_ref(
        self,
    ) -> typing.Optional["VaultDynamicSecretSpecProviderAuthJwtSecretRef"]:
        '''Optional SecretRef that refers to a key in a Secret resource containing JWT token to authenticate with Vault using the JWT/OIDC authentication method.

        :schema: VaultDynamicSecretSpecProviderAuthJwt#secretRef
        '''
        result = self._values.get("secret_ref")
        return typing.cast(typing.Optional["VaultDynamicSecretSpecProviderAuthJwtSecretRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretSpecProviderAuthJwt(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountToken",
    jsii_struct_bases=[],
    name_mapping={
        "service_account_ref": "serviceAccountRef",
        "audiences": "audiences",
        "expiration_seconds": "expirationSeconds",
    },
)
class VaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountToken:
    def __init__(
        self,
        *,
        service_account_ref: typing.Union["VaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountTokenServiceAccountRef", typing.Dict[builtins.str, typing.Any]],
        audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
        expiration_seconds: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''Optional ServiceAccountToken specifies the Kubernetes service account for which to request a token for with the ``TokenRequest`` API.

        :param service_account_ref: Service account field containing the name of a kubernetes ServiceAccount.
        :param audiences: Optional audiences field that will be used to request a temporary Kubernetes service account token for the service account referenced by ``serviceAccountRef``. Defaults to a single audience ``vault`` it not specified. Deprecated: use serviceAccountRef.Audiences instead Default: a single audience ``vault`` it not specified.
        :param expiration_seconds: Optional expiration time in seconds that will be used to request a temporary Kubernetes service account token for the service account referenced by ``serviceAccountRef``. Deprecated: this will be removed in the future. Defaults to 10 minutes. Default: 10 minutes.

        :schema: VaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountToken
        '''
        if isinstance(service_account_ref, dict):
            service_account_ref = VaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountTokenServiceAccountRef(**service_account_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__4b475f364551889cfe113a71ba131461697147bf11041280bcba648eb628dd33)
            check_type(argname="argument service_account_ref", value=service_account_ref, expected_type=type_hints["service_account_ref"])
            check_type(argname="argument audiences", value=audiences, expected_type=type_hints["audiences"])
            check_type(argname="argument expiration_seconds", value=expiration_seconds, expected_type=type_hints["expiration_seconds"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "service_account_ref": service_account_ref,
        }
        if audiences is not None:
            self._values["audiences"] = audiences
        if expiration_seconds is not None:
            self._values["expiration_seconds"] = expiration_seconds

    @builtins.property
    def service_account_ref(
        self,
    ) -> "VaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountTokenServiceAccountRef":
        '''Service account field containing the name of a kubernetes ServiceAccount.

        :schema: VaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountToken#serviceAccountRef
        '''
        result = self._values.get("service_account_ref")
        assert result is not None, "Required property 'service_account_ref' is missing"
        return typing.cast("VaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountTokenServiceAccountRef", result)

    @builtins.property
    def audiences(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Optional audiences field that will be used to request a temporary Kubernetes service account token for the service account referenced by ``serviceAccountRef``.

        Defaults to a single audience ``vault`` it not specified.
        Deprecated: use serviceAccountRef.Audiences instead

        :default: a single audience ``vault`` it not specified.

        :schema: VaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountToken#audiences
        '''
        result = self._values.get("audiences")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def expiration_seconds(self) -> typing.Optional[jsii.Number]:
        '''Optional expiration time in seconds that will be used to request a temporary Kubernetes service account token for the service account referenced by ``serviceAccountRef``.

        Deprecated: this will be removed in the future.
        Defaults to 10 minutes.

        :default: 10 minutes.

        :schema: VaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountToken#expirationSeconds
        '''
        result = self._values.get("expiration_seconds")
        return typing.cast(typing.Optional[jsii.Number], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountToken(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountTokenServiceAccountRef",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "audiences": "audiences", "namespace": "namespace"},
)
class VaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountTokenServiceAccountRef:
    def __init__(
        self,
        *,
        name: builtins.str,
        audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Service account field containing the name of a kubernetes ServiceAccount.

        :param name: The name of the ServiceAccount resource being referred to.
        :param audiences: Audience specifies the ``aud`` claim for the service account token If the service account uses a well-known annotation for e.g. IRSA or GCP Workload Identity then this audiences will be appended to the list.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountTokenServiceAccountRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__3333e3e748041d6297548bda5b350634919c0f92240514def8d1409b096751e4)
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument audiences", value=audiences, expected_type=type_hints["audiences"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "name": name,
        }
        if audiences is not None:
            self._values["audiences"] = audiences
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the ServiceAccount resource being referred to.

        :schema: VaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountTokenServiceAccountRef#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def audiences(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Audience specifies the ``aud`` claim for the service account token If the service account uses a well-known annotation for e.g. IRSA or GCP Workload Identity then this audiences will be appended to the list.

        :schema: VaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountTokenServiceAccountRef#audiences
        '''
        result = self._values.get("audiences")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountTokenServiceAccountRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountTokenServiceAccountRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProviderAuthJwtSecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class VaultDynamicSecretSpecProviderAuthJwtSecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Optional SecretRef that refers to a key in a Secret resource containing JWT token to authenticate with Vault using the JWT/OIDC authentication method.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderAuthJwtSecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__96abba540513ab928fe5e7f6062f3c8143e07eda734654ef2b33e1c29b7385e0)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: VaultDynamicSecretSpecProviderAuthJwtSecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: VaultDynamicSecretSpecProviderAuthJwtSecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderAuthJwtSecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretSpecProviderAuthJwtSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProviderAuthKubernetes",
    jsii_struct_bases=[],
    name_mapping={
        "mount_path": "mountPath",
        "role": "role",
        "secret_ref": "secretRef",
        "service_account_ref": "serviceAccountRef",
    },
)
class VaultDynamicSecretSpecProviderAuthKubernetes:
    def __init__(
        self,
        *,
        mount_path: builtins.str,
        role: builtins.str,
        secret_ref: typing.Optional[typing.Union["VaultDynamicSecretSpecProviderAuthKubernetesSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
        service_account_ref: typing.Optional[typing.Union["VaultDynamicSecretSpecProviderAuthKubernetesServiceAccountRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Kubernetes authenticates with Vault by passing the ServiceAccount token stored in the named Secret resource to the Vault server.

        :param mount_path: Path where the Kubernetes authentication backend is mounted in Vault, e.g: "kubernetes".
        :param role: A required field containing the Vault Role to assume. A Role binds a Kubernetes ServiceAccount with a set of Vault policies.
        :param secret_ref: Optional secret field containing a Kubernetes ServiceAccount JWT used for authenticating with Vault. If a name is specified without a key, ``token`` is the default. If one is not specified, the one bound to the controller will be used.
        :param service_account_ref: Optional service account field containing the name of a kubernetes ServiceAccount. If the service account is specified, the service account secret token JWT will be used for authenticating with Vault. If the service account selector is not supplied, the secretRef will be used instead.

        :schema: VaultDynamicSecretSpecProviderAuthKubernetes
        '''
        if isinstance(secret_ref, dict):
            secret_ref = VaultDynamicSecretSpecProviderAuthKubernetesSecretRef(**secret_ref)
        if isinstance(service_account_ref, dict):
            service_account_ref = VaultDynamicSecretSpecProviderAuthKubernetesServiceAccountRef(**service_account_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__3db9409bf746179327f1a68ae92cdef6ac3c5d1763ce35ba2f77b0afaa281ada)
            check_type(argname="argument mount_path", value=mount_path, expected_type=type_hints["mount_path"])
            check_type(argname="argument role", value=role, expected_type=type_hints["role"])
            check_type(argname="argument secret_ref", value=secret_ref, expected_type=type_hints["secret_ref"])
            check_type(argname="argument service_account_ref", value=service_account_ref, expected_type=type_hints["service_account_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "mount_path": mount_path,
            "role": role,
        }
        if secret_ref is not None:
            self._values["secret_ref"] = secret_ref
        if service_account_ref is not None:
            self._values["service_account_ref"] = service_account_ref

    @builtins.property
    def mount_path(self) -> builtins.str:
        '''Path where the Kubernetes authentication backend is mounted in Vault, e.g: "kubernetes".

        :schema: VaultDynamicSecretSpecProviderAuthKubernetes#mountPath
        '''
        result = self._values.get("mount_path")
        assert result is not None, "Required property 'mount_path' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def role(self) -> builtins.str:
        '''A required field containing the Vault Role to assume.

        A Role binds a
        Kubernetes ServiceAccount with a set of Vault policies.

        :schema: VaultDynamicSecretSpecProviderAuthKubernetes#role
        '''
        result = self._values.get("role")
        assert result is not None, "Required property 'role' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def secret_ref(
        self,
    ) -> typing.Optional["VaultDynamicSecretSpecProviderAuthKubernetesSecretRef"]:
        '''Optional secret field containing a Kubernetes ServiceAccount JWT used for authenticating with Vault.

        If a name is specified without a key,
        ``token`` is the default. If one is not specified, the one bound to
        the controller will be used.

        :schema: VaultDynamicSecretSpecProviderAuthKubernetes#secretRef
        '''
        result = self._values.get("secret_ref")
        return typing.cast(typing.Optional["VaultDynamicSecretSpecProviderAuthKubernetesSecretRef"], result)

    @builtins.property
    def service_account_ref(
        self,
    ) -> typing.Optional["VaultDynamicSecretSpecProviderAuthKubernetesServiceAccountRef"]:
        '''Optional service account field containing the name of a kubernetes ServiceAccount.

        If the service account is specified, the service account secret token JWT will be used
        for authenticating with Vault. If the service account selector is not supplied,
        the secretRef will be used instead.

        :schema: VaultDynamicSecretSpecProviderAuthKubernetes#serviceAccountRef
        '''
        result = self._values.get("service_account_ref")
        return typing.cast(typing.Optional["VaultDynamicSecretSpecProviderAuthKubernetesServiceAccountRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretSpecProviderAuthKubernetes(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProviderAuthKubernetesSecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class VaultDynamicSecretSpecProviderAuthKubernetesSecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Optional secret field containing a Kubernetes ServiceAccount JWT used for authenticating with Vault.

        If a name is specified without a key,
        ``token`` is the default. If one is not specified, the one bound to
        the controller will be used.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderAuthKubernetesSecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__4659bfab53d9dc36348d33a718d9e8ecfbe2bb88a426d276713dd23a457e62ff)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: VaultDynamicSecretSpecProviderAuthKubernetesSecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: VaultDynamicSecretSpecProviderAuthKubernetesSecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderAuthKubernetesSecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretSpecProviderAuthKubernetesSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProviderAuthKubernetesServiceAccountRef",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "audiences": "audiences", "namespace": "namespace"},
)
class VaultDynamicSecretSpecProviderAuthKubernetesServiceAccountRef:
    def __init__(
        self,
        *,
        name: builtins.str,
        audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Optional service account field containing the name of a kubernetes ServiceAccount.

        If the service account is specified, the service account secret token JWT will be used
        for authenticating with Vault. If the service account selector is not supplied,
        the secretRef will be used instead.

        :param name: The name of the ServiceAccount resource being referred to.
        :param audiences: Audience specifies the ``aud`` claim for the service account token If the service account uses a well-known annotation for e.g. IRSA or GCP Workload Identity then this audiences will be appended to the list.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderAuthKubernetesServiceAccountRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__86ab795d10d532e2cd677194c623dfd1c44794f096c0fdf250be3c75cbbfcea3)
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument audiences", value=audiences, expected_type=type_hints["audiences"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "name": name,
        }
        if audiences is not None:
            self._values["audiences"] = audiences
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the ServiceAccount resource being referred to.

        :schema: VaultDynamicSecretSpecProviderAuthKubernetesServiceAccountRef#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def audiences(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Audience specifies the ``aud`` claim for the service account token If the service account uses a well-known annotation for e.g. IRSA or GCP Workload Identity then this audiences will be appended to the list.

        :schema: VaultDynamicSecretSpecProviderAuthKubernetesServiceAccountRef#audiences
        '''
        result = self._values.get("audiences")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderAuthKubernetesServiceAccountRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretSpecProviderAuthKubernetesServiceAccountRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProviderAuthLdap",
    jsii_struct_bases=[],
    name_mapping={"path": "path", "username": "username", "secret_ref": "secretRef"},
)
class VaultDynamicSecretSpecProviderAuthLdap:
    def __init__(
        self,
        *,
        path: builtins.str,
        username: builtins.str,
        secret_ref: typing.Optional[typing.Union["VaultDynamicSecretSpecProviderAuthLdapSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Ldap authenticates with Vault by passing username/password pair using the LDAP authentication method.

        :param path: Path where the LDAP authentication backend is mounted in Vault, e.g: "ldap".
        :param username: Username is an LDAP username used to authenticate using the LDAP Vault authentication method.
        :param secret_ref: SecretRef to a key in a Secret resource containing password for the LDAP user used to authenticate with Vault using the LDAP authentication method.

        :schema: VaultDynamicSecretSpecProviderAuthLdap
        '''
        if isinstance(secret_ref, dict):
            secret_ref = VaultDynamicSecretSpecProviderAuthLdapSecretRef(**secret_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__5b0220345616dc96fe17373542b0e0479cd49c760f894b3c8b2b9a7d1bee1b52)
            check_type(argname="argument path", value=path, expected_type=type_hints["path"])
            check_type(argname="argument username", value=username, expected_type=type_hints["username"])
            check_type(argname="argument secret_ref", value=secret_ref, expected_type=type_hints["secret_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "path": path,
            "username": username,
        }
        if secret_ref is not None:
            self._values["secret_ref"] = secret_ref

    @builtins.property
    def path(self) -> builtins.str:
        '''Path where the LDAP authentication backend is mounted in Vault, e.g: "ldap".

        :schema: VaultDynamicSecretSpecProviderAuthLdap#path
        '''
        result = self._values.get("path")
        assert result is not None, "Required property 'path' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def username(self) -> builtins.str:
        '''Username is an LDAP username used to authenticate using the LDAP Vault authentication method.

        :schema: VaultDynamicSecretSpecProviderAuthLdap#username
        '''
        result = self._values.get("username")
        assert result is not None, "Required property 'username' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def secret_ref(
        self,
    ) -> typing.Optional["VaultDynamicSecretSpecProviderAuthLdapSecretRef"]:
        '''SecretRef to a key in a Secret resource containing password for the LDAP user used to authenticate with Vault using the LDAP authentication method.

        :schema: VaultDynamicSecretSpecProviderAuthLdap#secretRef
        '''
        result = self._values.get("secret_ref")
        return typing.cast(typing.Optional["VaultDynamicSecretSpecProviderAuthLdapSecretRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretSpecProviderAuthLdap(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProviderAuthLdapSecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class VaultDynamicSecretSpecProviderAuthLdapSecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''SecretRef to a key in a Secret resource containing password for the LDAP user used to authenticate with Vault using the LDAP authentication method.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderAuthLdapSecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__60bc931306020a61804834bcc79bbcf49973e8f53d58f4ea39b0ae1754711b08)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: VaultDynamicSecretSpecProviderAuthLdapSecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: VaultDynamicSecretSpecProviderAuthLdapSecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderAuthLdapSecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretSpecProviderAuthLdapSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProviderAuthTokenSecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class VaultDynamicSecretSpecProviderAuthTokenSecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''TokenSecretRef authenticates with Vault by presenting a token.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderAuthTokenSecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__ed41facd1379b3f85556543534fb044320dbd0b59942324205b3985c4248bd36)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: VaultDynamicSecretSpecProviderAuthTokenSecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: VaultDynamicSecretSpecProviderAuthTokenSecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderAuthTokenSecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretSpecProviderAuthTokenSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProviderAuthUserPass",
    jsii_struct_bases=[],
    name_mapping={"path": "path", "username": "username", "secret_ref": "secretRef"},
)
class VaultDynamicSecretSpecProviderAuthUserPass:
    def __init__(
        self,
        *,
        path: builtins.str,
        username: builtins.str,
        secret_ref: typing.Optional[typing.Union["VaultDynamicSecretSpecProviderAuthUserPassSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''UserPass authenticates with Vault by passing username/password pair.

        :param path: Path where the UserPassword authentication backend is mounted in Vault, e.g: "userpass".
        :param username: Username is a username used to authenticate using the UserPass Vault authentication method.
        :param secret_ref: SecretRef to a key in a Secret resource containing password for the user used to authenticate with Vault using the UserPass authentication method.

        :schema: VaultDynamicSecretSpecProviderAuthUserPass
        '''
        if isinstance(secret_ref, dict):
            secret_ref = VaultDynamicSecretSpecProviderAuthUserPassSecretRef(**secret_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__958d4e7ec13747646d6801333810ae326b34bfd2eb12c19bf05f0c3bf7d89697)
            check_type(argname="argument path", value=path, expected_type=type_hints["path"])
            check_type(argname="argument username", value=username, expected_type=type_hints["username"])
            check_type(argname="argument secret_ref", value=secret_ref, expected_type=type_hints["secret_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "path": path,
            "username": username,
        }
        if secret_ref is not None:
            self._values["secret_ref"] = secret_ref

    @builtins.property
    def path(self) -> builtins.str:
        '''Path where the UserPassword authentication backend is mounted in Vault, e.g: "userpass".

        :schema: VaultDynamicSecretSpecProviderAuthUserPass#path
        '''
        result = self._values.get("path")
        assert result is not None, "Required property 'path' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def username(self) -> builtins.str:
        '''Username is a username used to authenticate using the UserPass Vault authentication method.

        :schema: VaultDynamicSecretSpecProviderAuthUserPass#username
        '''
        result = self._values.get("username")
        assert result is not None, "Required property 'username' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def secret_ref(
        self,
    ) -> typing.Optional["VaultDynamicSecretSpecProviderAuthUserPassSecretRef"]:
        '''SecretRef to a key in a Secret resource containing password for the user used to authenticate with Vault using the UserPass authentication method.

        :schema: VaultDynamicSecretSpecProviderAuthUserPass#secretRef
        '''
        result = self._values.get("secret_ref")
        return typing.cast(typing.Optional["VaultDynamicSecretSpecProviderAuthUserPassSecretRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretSpecProviderAuthUserPass(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProviderAuthUserPassSecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class VaultDynamicSecretSpecProviderAuthUserPassSecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''SecretRef to a key in a Secret resource containing password for the user used to authenticate with Vault using the UserPass authentication method.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderAuthUserPassSecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__216849c3808d37d2df1e879ee71aff23ac155adf219272b406f534e7b6943b73)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: VaultDynamicSecretSpecProviderAuthUserPassSecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: VaultDynamicSecretSpecProviderAuthUserPassSecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderAuthUserPassSecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretSpecProviderAuthUserPassSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProviderCaProvider",
    jsii_struct_bases=[],
    name_mapping={
        "name": "name",
        "type": "type",
        "key": "key",
        "namespace": "namespace",
    },
)
class VaultDynamicSecretSpecProviderCaProvider:
    def __init__(
        self,
        *,
        name: builtins.str,
        type: "VaultDynamicSecretSpecProviderCaProviderType",
        key: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''The provider for the CA bundle to use to validate Vault server certificate.

        :param name: The name of the object located at the provider type.
        :param type: The type of provider to use such as "Secret", or "ConfigMap".
        :param key: The key where the CA certificate can be found in the Secret or ConfigMap.
        :param namespace: The namespace the Provider type is in. Can only be defined when used in a ClusterSecretStore.

        :schema: VaultDynamicSecretSpecProviderCaProvider
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__47aa9e507cb3a56b1071f68782774cbb97be7b7e78095f1255b6540a57b48a2e)
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument type", value=type, expected_type=type_hints["type"])
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "name": name,
            "type": type,
        }
        if key is not None:
            self._values["key"] = key
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the object located at the provider type.

        :schema: VaultDynamicSecretSpecProviderCaProvider#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def type(self) -> "VaultDynamicSecretSpecProviderCaProviderType":
        '''The type of provider to use such as "Secret", or "ConfigMap".

        :schema: VaultDynamicSecretSpecProviderCaProvider#type
        '''
        result = self._values.get("type")
        assert result is not None, "Required property 'type' is missing"
        return typing.cast("VaultDynamicSecretSpecProviderCaProviderType", result)

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''The key where the CA certificate can be found in the Secret or ConfigMap.

        :schema: VaultDynamicSecretSpecProviderCaProvider#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace the Provider type is in.

        Can only be defined when used in a ClusterSecretStore.

        :schema: VaultDynamicSecretSpecProviderCaProvider#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretSpecProviderCaProvider(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProviderCaProviderType"
)
class VaultDynamicSecretSpecProviderCaProviderType(enum.Enum):
    '''The type of provider to use such as "Secret", or "ConfigMap".

    :schema: VaultDynamicSecretSpecProviderCaProviderType
    '''

    SECRET = "SECRET"
    '''Secret.'''
    CONFIG_MAP = "CONFIG_MAP"
    '''ConfigMap.'''


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProviderTls",
    jsii_struct_bases=[],
    name_mapping={
        "cert_secret_ref": "certSecretRef",
        "key_secret_ref": "keySecretRef",
    },
)
class VaultDynamicSecretSpecProviderTls:
    def __init__(
        self,
        *,
        cert_secret_ref: typing.Optional[typing.Union["VaultDynamicSecretSpecProviderTlsCertSecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
        key_secret_ref: typing.Optional[typing.Union["VaultDynamicSecretSpecProviderTlsKeySecretRef", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''The configuration used for client side related TLS communication, when the Vault server requires mutual authentication.

        Only used if the Server URL is using HTTPS protocol.
        This parameter is ignored for plain HTTP protocol connection.
        It's worth noting this configuration is different from the "TLS certificates auth method",
        which is available under the ``auth.cert`` section.

        :param cert_secret_ref: CertSecretRef is a certificate added to the transport layer when communicating with the Vault server. If no key for the Secret is specified, external-secret will default to 'tls.crt'.
        :param key_secret_ref: KeySecretRef to a key in a Secret resource containing client private key added to the transport layer when communicating with the Vault server. If no key for the Secret is specified, external-secret will default to 'tls.key'.

        :schema: VaultDynamicSecretSpecProviderTls
        '''
        if isinstance(cert_secret_ref, dict):
            cert_secret_ref = VaultDynamicSecretSpecProviderTlsCertSecretRef(**cert_secret_ref)
        if isinstance(key_secret_ref, dict):
            key_secret_ref = VaultDynamicSecretSpecProviderTlsKeySecretRef(**key_secret_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__4c359e9ca0ed96202a7b48da939ccca9ad838ac2a1792e970ccc859acc513b5e)
            check_type(argname="argument cert_secret_ref", value=cert_secret_ref, expected_type=type_hints["cert_secret_ref"])
            check_type(argname="argument key_secret_ref", value=key_secret_ref, expected_type=type_hints["key_secret_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if cert_secret_ref is not None:
            self._values["cert_secret_ref"] = cert_secret_ref
        if key_secret_ref is not None:
            self._values["key_secret_ref"] = key_secret_ref

    @builtins.property
    def cert_secret_ref(
        self,
    ) -> typing.Optional["VaultDynamicSecretSpecProviderTlsCertSecretRef"]:
        '''CertSecretRef is a certificate added to the transport layer when communicating with the Vault server.

        If no key for the Secret is specified, external-secret will default to 'tls.crt'.

        :schema: VaultDynamicSecretSpecProviderTls#certSecretRef
        '''
        result = self._values.get("cert_secret_ref")
        return typing.cast(typing.Optional["VaultDynamicSecretSpecProviderTlsCertSecretRef"], result)

    @builtins.property
    def key_secret_ref(
        self,
    ) -> typing.Optional["VaultDynamicSecretSpecProviderTlsKeySecretRef"]:
        '''KeySecretRef to a key in a Secret resource containing client private key added to the transport layer when communicating with the Vault server.

        If no key for the Secret is specified, external-secret will default to 'tls.key'.

        :schema: VaultDynamicSecretSpecProviderTls#keySecretRef
        '''
        result = self._values.get("key_secret_ref")
        return typing.cast(typing.Optional["VaultDynamicSecretSpecProviderTlsKeySecretRef"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretSpecProviderTls(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProviderTlsCertSecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class VaultDynamicSecretSpecProviderTlsCertSecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''CertSecretRef is a certificate added to the transport layer when communicating with the Vault server.

        If no key for the Secret is specified, external-secret will default to 'tls.crt'.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderTlsCertSecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__599cbaf122859dd7f009e3ed451c225503a46650ac59351333ec8c7e1ebdbeae)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: VaultDynamicSecretSpecProviderTlsCertSecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: VaultDynamicSecretSpecProviderTlsCertSecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderTlsCertSecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretSpecProviderTlsCertSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProviderTlsKeySecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class VaultDynamicSecretSpecProviderTlsKeySecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''KeySecretRef to a key in a Secret resource containing client private key added to the transport layer when communicating with the Vault server.

        If no key for the Secret is specified, external-secret will default to 'tls.key'.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderTlsKeySecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__bc5c0e299295a5a887aeb0ffd3b0c7b44ddedc0ba8c0a2218c5f3b3b4b61d977)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: VaultDynamicSecretSpecProviderTlsKeySecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: VaultDynamicSecretSpecProviderTlsKeySecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: VaultDynamicSecretSpecProviderTlsKeySecretRef#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretSpecProviderTlsKeySecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProviderVersion"
)
class VaultDynamicSecretSpecProviderVersion(enum.Enum):
    '''Version is the Vault KV secret engine version.

    This can be either "v1" or
    "v2". Version defaults to "v2".

    :schema: VaultDynamicSecretSpecProviderVersion
    '''

    V1 = "V1"
    '''v1.'''
    V2 = "V2"
    '''v2.'''


@jsii.enum(jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecResultType")
class VaultDynamicSecretSpecResultType(enum.Enum):
    '''Result type defines which data is returned from the generator.

    By default it is the "data" section of the Vault API response.
    When using e.g. /auth/token/create the "data" section is empty but
    the "auth" section contains the generated token.
    Please refer to the vault docs regarding the result data structure.
    Additionally, accessing the raw response is possibly by using "Raw" result type.

    :schema: VaultDynamicSecretSpecResultType
    '''

    DATA = "DATA"
    '''Data.'''
    AUTH = "AUTH"
    '''Auth.'''
    RAW = "RAW"
    '''Raw.'''


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecRetrySettings",
    jsii_struct_bases=[],
    name_mapping={"max_retries": "maxRetries", "retry_interval": "retryInterval"},
)
class VaultDynamicSecretSpecRetrySettings:
    def __init__(
        self,
        *,
        max_retries: typing.Optional[jsii.Number] = None,
        retry_interval: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Used to configure http retries if failed.

        :param max_retries: 
        :param retry_interval: 

        :schema: VaultDynamicSecretSpecRetrySettings
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__6ea2dadc111afddae5d1419fecc4fe0206d457921fd2b0454f3c8d16596207f4)
            check_type(argname="argument max_retries", value=max_retries, expected_type=type_hints["max_retries"])
            check_type(argname="argument retry_interval", value=retry_interval, expected_type=type_hints["retry_interval"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if max_retries is not None:
            self._values["max_retries"] = max_retries
        if retry_interval is not None:
            self._values["retry_interval"] = retry_interval

    @builtins.property
    def max_retries(self) -> typing.Optional[jsii.Number]:
        '''
        :schema: VaultDynamicSecretSpecRetrySettings#maxRetries
        '''
        result = self._values.get("max_retries")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def retry_interval(self) -> typing.Optional[builtins.str]:
        '''
        :schema: VaultDynamicSecretSpecRetrySettings#retryInterval
        '''
        result = self._values.get("retry_interval")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VaultDynamicSecretSpecRetrySettings(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class Webhook(
    _cdk8s_d3d9af27.ApiObject,
    metaclass=jsii.JSIIMeta,
    jsii_type="ioexternal-secretsgenerators.Webhook",
):
    '''Webhook connects to a third party API server to handle the secrets generation configuration parameters in spec.

    You can specify the server, the token, and additional body parameters.
    See documentation for the full API specification for requests and responses.

    :schema: Webhook
    '''

    def __init__(
        self,
        scope: _constructs_77d1e7e8.Construct,
        id: builtins.str,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["WebhookSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Defines a "Webhook" API object.

        :param scope: the scope in which to define this object.
        :param id: a scope-local name for the object.
        :param metadata: 
        :param spec: WebhookSpec controls the behavior of the external generator. Any body parameters should be passed to the server through the parameters field.
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__2b3398300afa4aac17177a7f5a19102c6ef4c1f09f44bd175a63555207914180)
            check_type(argname="argument scope", value=scope, expected_type=type_hints["scope"])
            check_type(argname="argument id", value=id, expected_type=type_hints["id"])
        props = WebhookProps(metadata=metadata, spec=spec)

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="manifest")
    @builtins.classmethod
    def manifest(
        cls,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["WebhookSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> typing.Any:
        '''Renders a Kubernetes manifest for "Webhook".

        This can be used to inline resource manifests inside other objects (e.g. as templates).

        :param metadata: 
        :param spec: WebhookSpec controls the behavior of the external generator. Any body parameters should be passed to the server through the parameters field.
        '''
        props = WebhookProps(metadata=metadata, spec=spec)

        return typing.cast(typing.Any, jsii.sinvoke(cls, "manifest", [props]))

    @jsii.member(jsii_name="toJson")
    def to_json(self) -> typing.Any:
        '''Renders the object to Kubernetes JSON.'''
        return typing.cast(typing.Any, jsii.invoke(self, "toJson", []))

    @jsii.python.classproperty
    @jsii.member(jsii_name="GVK")
    def GVK(cls) -> _cdk8s_d3d9af27.GroupVersionKind:
        '''Returns the apiVersion and kind for "Webhook".'''
        return typing.cast(_cdk8s_d3d9af27.GroupVersionKind, jsii.sget(cls, "GVK"))


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.WebhookProps",
    jsii_struct_bases=[],
    name_mapping={"metadata": "metadata", "spec": "spec"},
)
class WebhookProps:
    def __init__(
        self,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["WebhookSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Webhook connects to a third party API server to handle the secrets generation configuration parameters in spec.

        You can specify the server, the token, and additional body parameters.
        See documentation for the full API specification for requests and responses.

        :param metadata: 
        :param spec: WebhookSpec controls the behavior of the external generator. Any body parameters should be passed to the server through the parameters field.

        :schema: Webhook
        '''
        if isinstance(metadata, dict):
            metadata = _cdk8s_d3d9af27.ApiObjectMetadata(**metadata)
        if isinstance(spec, dict):
            spec = WebhookSpec(**spec)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__0b254d63d89ea234a5552305205259b657fc7bdae3ce04b66e322f35dde31921)
            check_type(argname="argument metadata", value=metadata, expected_type=type_hints["metadata"])
            check_type(argname="argument spec", value=spec, expected_type=type_hints["spec"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if metadata is not None:
            self._values["metadata"] = metadata
        if spec is not None:
            self._values["spec"] = spec

    @builtins.property
    def metadata(self) -> typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata]:
        '''
        :schema: Webhook#metadata
        '''
        result = self._values.get("metadata")
        return typing.cast(typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata], result)

    @builtins.property
    def spec(self) -> typing.Optional["WebhookSpec"]:
        '''WebhookSpec controls the behavior of the external generator.

        Any body parameters should be passed to the server through the parameters field.

        :schema: Webhook#spec
        '''
        result = self._values.get("spec")
        return typing.cast(typing.Optional["WebhookSpec"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "WebhookProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.WebhookSpec",
    jsii_struct_bases=[],
    name_mapping={
        "result": "result",
        "url": "url",
        "auth": "auth",
        "body": "body",
        "ca_bundle": "caBundle",
        "ca_provider": "caProvider",
        "headers": "headers",
        "method": "method",
        "secrets": "secrets",
        "timeout": "timeout",
    },
)
class WebhookSpec:
    def __init__(
        self,
        *,
        result: typing.Union["WebhookSpecResult", typing.Dict[builtins.str, typing.Any]],
        url: builtins.str,
        auth: typing.Optional[typing.Union["WebhookSpecAuth", typing.Dict[builtins.str, typing.Any]]] = None,
        body: typing.Optional[builtins.str] = None,
        ca_bundle: typing.Optional[builtins.str] = None,
        ca_provider: typing.Optional[typing.Union["WebhookSpecCaProvider", typing.Dict[builtins.str, typing.Any]]] = None,
        headers: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        method: typing.Optional[builtins.str] = None,
        secrets: typing.Optional[typing.Sequence[typing.Union["WebhookSpecSecrets", typing.Dict[builtins.str, typing.Any]]]] = None,
        timeout: typing.Optional[builtins.str] = None,
    ) -> None:
        '''WebhookSpec controls the behavior of the external generator.

        Any body parameters should be passed to the server through the parameters field.

        :param result: Result formatting.
        :param url: Webhook url to call.
        :param auth: Auth specifies a authorization protocol. Only one protocol may be set.
        :param body: Body.
        :param ca_bundle: PEM encoded CA bundle used to validate webhook server certificate. Only used if the Server URL is using HTTPS protocol. This parameter is ignored for plain HTTP protocol connection. If not set the system root certificates are used to validate the TLS connection.
        :param ca_provider: The provider for the CA bundle to use to validate webhook server certificate.
        :param headers: Headers.
        :param method: Webhook Method.
        :param secrets: Secrets to fill in templates These secrets will be passed to the templating function as key value pairs under the given name.
        :param timeout: Timeout.

        :schema: WebhookSpec
        '''
        if isinstance(result, dict):
            result = WebhookSpecResult(**result)
        if isinstance(auth, dict):
            auth = WebhookSpecAuth(**auth)
        if isinstance(ca_provider, dict):
            ca_provider = WebhookSpecCaProvider(**ca_provider)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__6ef020d87c0708a88abf8b30977911e976ff092427549278c6ce74edd91575ec)
            check_type(argname="argument result", value=result, expected_type=type_hints["result"])
            check_type(argname="argument url", value=url, expected_type=type_hints["url"])
            check_type(argname="argument auth", value=auth, expected_type=type_hints["auth"])
            check_type(argname="argument body", value=body, expected_type=type_hints["body"])
            check_type(argname="argument ca_bundle", value=ca_bundle, expected_type=type_hints["ca_bundle"])
            check_type(argname="argument ca_provider", value=ca_provider, expected_type=type_hints["ca_provider"])
            check_type(argname="argument headers", value=headers, expected_type=type_hints["headers"])
            check_type(argname="argument method", value=method, expected_type=type_hints["method"])
            check_type(argname="argument secrets", value=secrets, expected_type=type_hints["secrets"])
            check_type(argname="argument timeout", value=timeout, expected_type=type_hints["timeout"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "result": result,
            "url": url,
        }
        if auth is not None:
            self._values["auth"] = auth
        if body is not None:
            self._values["body"] = body
        if ca_bundle is not None:
            self._values["ca_bundle"] = ca_bundle
        if ca_provider is not None:
            self._values["ca_provider"] = ca_provider
        if headers is not None:
            self._values["headers"] = headers
        if method is not None:
            self._values["method"] = method
        if secrets is not None:
            self._values["secrets"] = secrets
        if timeout is not None:
            self._values["timeout"] = timeout

    @builtins.property
    def result(self) -> "WebhookSpecResult":
        '''Result formatting.

        :schema: WebhookSpec#result
        '''
        result = self._values.get("result")
        assert result is not None, "Required property 'result' is missing"
        return typing.cast("WebhookSpecResult", result)

    @builtins.property
    def url(self) -> builtins.str:
        '''Webhook url to call.

        :schema: WebhookSpec#url
        '''
        result = self._values.get("url")
        assert result is not None, "Required property 'url' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def auth(self) -> typing.Optional["WebhookSpecAuth"]:
        '''Auth specifies a authorization protocol.

        Only one protocol may be set.

        :schema: WebhookSpec#auth
        '''
        result = self._values.get("auth")
        return typing.cast(typing.Optional["WebhookSpecAuth"], result)

    @builtins.property
    def body(self) -> typing.Optional[builtins.str]:
        '''Body.

        :schema: WebhookSpec#body
        '''
        result = self._values.get("body")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ca_bundle(self) -> typing.Optional[builtins.str]:
        '''PEM encoded CA bundle used to validate webhook server certificate.

        Only used
        if the Server URL is using HTTPS protocol. This parameter is ignored for
        plain HTTP protocol connection. If not set the system root certificates
        are used to validate the TLS connection.

        :schema: WebhookSpec#caBundle
        '''
        result = self._values.get("ca_bundle")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ca_provider(self) -> typing.Optional["WebhookSpecCaProvider"]:
        '''The provider for the CA bundle to use to validate webhook server certificate.

        :schema: WebhookSpec#caProvider
        '''
        result = self._values.get("ca_provider")
        return typing.cast(typing.Optional["WebhookSpecCaProvider"], result)

    @builtins.property
    def headers(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Headers.

        :schema: WebhookSpec#headers
        '''
        result = self._values.get("headers")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def method(self) -> typing.Optional[builtins.str]:
        '''Webhook Method.

        :schema: WebhookSpec#method
        '''
        result = self._values.get("method")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def secrets(self) -> typing.Optional[typing.List["WebhookSpecSecrets"]]:
        '''Secrets to fill in templates These secrets will be passed to the templating function as key value pairs under the given name.

        :schema: WebhookSpec#secrets
        '''
        result = self._values.get("secrets")
        return typing.cast(typing.Optional[typing.List["WebhookSpecSecrets"]], result)

    @builtins.property
    def timeout(self) -> typing.Optional[builtins.str]:
        '''Timeout.

        :schema: WebhookSpec#timeout
        '''
        result = self._values.get("timeout")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "WebhookSpec(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.WebhookSpecAuth",
    jsii_struct_bases=[],
    name_mapping={"ntlm": "ntlm"},
)
class WebhookSpecAuth:
    def __init__(
        self,
        *,
        ntlm: typing.Optional[typing.Union["WebhookSpecAuthNtlm", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Auth specifies a authorization protocol.

        Only one protocol may be set.

        :param ntlm: NTLMProtocol configures the store to use NTLM for auth.

        :schema: WebhookSpecAuth
        '''
        if isinstance(ntlm, dict):
            ntlm = WebhookSpecAuthNtlm(**ntlm)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__78defe8d10b15821216ddfd3f988c664963f350cdd10aa5c48a1c5a5734905a6)
            check_type(argname="argument ntlm", value=ntlm, expected_type=type_hints["ntlm"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if ntlm is not None:
            self._values["ntlm"] = ntlm

    @builtins.property
    def ntlm(self) -> typing.Optional["WebhookSpecAuthNtlm"]:
        '''NTLMProtocol configures the store to use NTLM for auth.

        :schema: WebhookSpecAuth#ntlm
        '''
        result = self._values.get("ntlm")
        return typing.cast(typing.Optional["WebhookSpecAuthNtlm"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "WebhookSpecAuth(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.WebhookSpecAuthNtlm",
    jsii_struct_bases=[],
    name_mapping={
        "password_secret": "passwordSecret",
        "username_secret": "usernameSecret",
    },
)
class WebhookSpecAuthNtlm:
    def __init__(
        self,
        *,
        password_secret: typing.Union["WebhookSpecAuthNtlmPasswordSecret", typing.Dict[builtins.str, typing.Any]],
        username_secret: typing.Union["WebhookSpecAuthNtlmUsernameSecret", typing.Dict[builtins.str, typing.Any]],
    ) -> None:
        '''NTLMProtocol configures the store to use NTLM for auth.

        :param password_secret: A reference to a specific 'key' within a Secret resource. In some instances, ``key`` is a required field.
        :param username_secret: A reference to a specific 'key' within a Secret resource. In some instances, ``key`` is a required field.

        :schema: WebhookSpecAuthNtlm
        '''
        if isinstance(password_secret, dict):
            password_secret = WebhookSpecAuthNtlmPasswordSecret(**password_secret)
        if isinstance(username_secret, dict):
            username_secret = WebhookSpecAuthNtlmUsernameSecret(**username_secret)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__54f272261eb357770cbc8bfec20f2a259f0d7047b325a6c635ab4acecc21d863)
            check_type(argname="argument password_secret", value=password_secret, expected_type=type_hints["password_secret"])
            check_type(argname="argument username_secret", value=username_secret, expected_type=type_hints["username_secret"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "password_secret": password_secret,
            "username_secret": username_secret,
        }

    @builtins.property
    def password_secret(self) -> "WebhookSpecAuthNtlmPasswordSecret":
        '''A reference to a specific 'key' within a Secret resource.

        In some instances, ``key`` is a required field.

        :schema: WebhookSpecAuthNtlm#passwordSecret
        '''
        result = self._values.get("password_secret")
        assert result is not None, "Required property 'password_secret' is missing"
        return typing.cast("WebhookSpecAuthNtlmPasswordSecret", result)

    @builtins.property
    def username_secret(self) -> "WebhookSpecAuthNtlmUsernameSecret":
        '''A reference to a specific 'key' within a Secret resource.

        In some instances, ``key`` is a required field.

        :schema: WebhookSpecAuthNtlm#usernameSecret
        '''
        result = self._values.get("username_secret")
        assert result is not None, "Required property 'username_secret' is missing"
        return typing.cast("WebhookSpecAuthNtlmUsernameSecret", result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "WebhookSpecAuthNtlm(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.WebhookSpecAuthNtlmPasswordSecret",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class WebhookSpecAuthNtlmPasswordSecret:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''A reference to a specific 'key' within a Secret resource.

        In some instances, ``key`` is a required field.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: WebhookSpecAuthNtlmPasswordSecret
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__2deaaac4bc9b8850bb1260ca7fc7e46f31d6a7fd0b83be30603d96939c1a744c)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: WebhookSpecAuthNtlmPasswordSecret#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: WebhookSpecAuthNtlmPasswordSecret#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: WebhookSpecAuthNtlmPasswordSecret#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "WebhookSpecAuthNtlmPasswordSecret(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.WebhookSpecAuthNtlmUsernameSecret",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name", "namespace": "namespace"},
)
class WebhookSpecAuthNtlmUsernameSecret:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''A reference to a specific 'key' within a Secret resource.

        In some instances, ``key`` is a required field.

        :param key: A key in the referenced Secret. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: The namespace of the Secret resource being referred to. Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: WebhookSpecAuthNtlmUsernameSecret
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__c7a59ddd5e3704e4ca2730280bf8bd48570c20f65dafe99041e6a266f16c3e1a)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''A key in the referenced Secret.

        Some instances of this field may be defaulted, in others it may be required.

        :schema: WebhookSpecAuthNtlmUsernameSecret#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: WebhookSpecAuthNtlmUsernameSecret#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the Secret resource being referred to.

        Ignored if referent is not cluster-scoped, otherwise defaults to the namespace of the referent.

        :schema: WebhookSpecAuthNtlmUsernameSecret#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "WebhookSpecAuthNtlmUsernameSecret(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.WebhookSpecCaProvider",
    jsii_struct_bases=[],
    name_mapping={
        "name": "name",
        "type": "type",
        "key": "key",
        "namespace": "namespace",
    },
)
class WebhookSpecCaProvider:
    def __init__(
        self,
        *,
        name: builtins.str,
        type: "WebhookSpecCaProviderType",
        key: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''The provider for the CA bundle to use to validate webhook server certificate.

        :param name: The name of the object located at the provider type.
        :param type: The type of provider to use such as "Secret", or "ConfigMap".
        :param key: The key where the CA certificate can be found in the Secret or ConfigMap.
        :param namespace: The namespace the Provider type is in.

        :schema: WebhookSpecCaProvider
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__90b741732fca9bf2aae7312269add8c4a03df33524d5574edd943d60f2b4f152)
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument type", value=type, expected_type=type_hints["type"])
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "name": name,
            "type": type,
        }
        if key is not None:
            self._values["key"] = key
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the object located at the provider type.

        :schema: WebhookSpecCaProvider#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def type(self) -> "WebhookSpecCaProviderType":
        '''The type of provider to use such as "Secret", or "ConfigMap".

        :schema: WebhookSpecCaProvider#type
        '''
        result = self._values.get("type")
        assert result is not None, "Required property 'type' is missing"
        return typing.cast("WebhookSpecCaProviderType", result)

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''The key where the CA certificate can be found in the Secret or ConfigMap.

        :schema: WebhookSpecCaProvider#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace the Provider type is in.

        :schema: WebhookSpecCaProvider#namespace
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "WebhookSpecCaProvider(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="ioexternal-secretsgenerators.WebhookSpecCaProviderType")
class WebhookSpecCaProviderType(enum.Enum):
    '''The type of provider to use such as "Secret", or "ConfigMap".

    :schema: WebhookSpecCaProviderType
    '''

    SECRET = "SECRET"
    '''Secret.'''
    CONFIG_MAP = "CONFIG_MAP"
    '''ConfigMap.'''


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.WebhookSpecResult",
    jsii_struct_bases=[],
    name_mapping={"json_path": "jsonPath"},
)
class WebhookSpecResult:
    def __init__(self, *, json_path: typing.Optional[builtins.str] = None) -> None:
        '''Result formatting.

        :param json_path: Json path of return value.

        :schema: WebhookSpecResult
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__ca17a0cafac72c20c4b5371c2a40624b79067e28976caaef7d455a3af73b33b7)
            check_type(argname="argument json_path", value=json_path, expected_type=type_hints["json_path"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if json_path is not None:
            self._values["json_path"] = json_path

    @builtins.property
    def json_path(self) -> typing.Optional[builtins.str]:
        '''Json path of return value.

        :schema: WebhookSpecResult#jsonPath
        '''
        result = self._values.get("json_path")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "WebhookSpecResult(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.WebhookSpecSecrets",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "secret_ref": "secretRef"},
)
class WebhookSpecSecrets:
    def __init__(
        self,
        *,
        name: builtins.str,
        secret_ref: typing.Union["WebhookSpecSecretsSecretRef", typing.Dict[builtins.str, typing.Any]],
    ) -> None:
        '''
        :param name: Name of this secret in templates.
        :param secret_ref: Secret ref to fill in credentials.

        :schema: WebhookSpecSecrets
        '''
        if isinstance(secret_ref, dict):
            secret_ref = WebhookSpecSecretsSecretRef(**secret_ref)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__f6c624ae8cdb02a080db2665a395b8aab26b2f157404c3891b4e3195fc8dfc4a)
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument secret_ref", value=secret_ref, expected_type=type_hints["secret_ref"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "name": name,
            "secret_ref": secret_ref,
        }

    @builtins.property
    def name(self) -> builtins.str:
        '''Name of this secret in templates.

        :schema: WebhookSpecSecrets#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def secret_ref(self) -> "WebhookSpecSecretsSecretRef":
        '''Secret ref to fill in credentials.

        :schema: WebhookSpecSecrets#secretRef
        '''
        result = self._values.get("secret_ref")
        assert result is not None, "Required property 'secret_ref' is missing"
        return typing.cast("WebhookSpecSecretsSecretRef", result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "WebhookSpecSecrets(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="ioexternal-secretsgenerators.WebhookSpecSecretsSecretRef",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "name": "name"},
)
class WebhookSpecSecretsSecretRef:
    def __init__(
        self,
        *,
        key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Secret ref to fill in credentials.

        :param key: The key where the token is found.
        :param name: The name of the Secret resource being referred to.

        :schema: WebhookSpecSecretsSecretRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__da7206ccc0e7cc05ae6cece8b22e90df4f71703b449edd6dfd8a06e7de96daf9)
            check_type(argname="argument key", value=key, expected_type=type_hints["key"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if key is not None:
            self._values["key"] = key
        if name is not None:
            self._values["name"] = name

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''The key where the token is found.

        :schema: WebhookSpecSecretsSecretRef#key
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Secret resource being referred to.

        :schema: WebhookSpecSecretsSecretRef#name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "WebhookSpecSecretsSecretRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "AcrAccessToken",
    "AcrAccessTokenProps",
    "AcrAccessTokenSpec",
    "AcrAccessTokenSpecAuth",
    "AcrAccessTokenSpecAuthManagedIdentity",
    "AcrAccessTokenSpecAuthServicePrincipal",
    "AcrAccessTokenSpecAuthServicePrincipalSecretRef",
    "AcrAccessTokenSpecAuthServicePrincipalSecretRefClientId",
    "AcrAccessTokenSpecAuthServicePrincipalSecretRefClientSecret",
    "AcrAccessTokenSpecAuthWorkloadIdentity",
    "AcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef",
    "AcrAccessTokenSpecEnvironmentType",
    "ClusterGenerator",
    "ClusterGeneratorProps",
    "ClusterGeneratorSpec",
    "ClusterGeneratorSpecGenerator",
    "ClusterGeneratorSpecGeneratorAcrAccessTokenSpec",
    "ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuth",
    "ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthManagedIdentity",
    "ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipal",
    "ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRef",
    "ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRefClientId",
    "ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRefClientSecret",
    "ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthWorkloadIdentity",
    "ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef",
    "ClusterGeneratorSpecGeneratorAcrAccessTokenSpecEnvironmentType",
    "ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpec",
    "ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuth",
    "ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthJwt",
    "ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthJwtServiceAccountRef",
    "ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRef",
    "ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefAccessKeyIdSecretRef",
    "ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefSecretAccessKeySecretRef",
    "ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefSessionTokenSecretRef",
    "ClusterGeneratorSpecGeneratorFakeSpec",
    "ClusterGeneratorSpecGeneratorGcrAccessTokenSpec",
    "ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuth",
    "ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthSecretRef",
    "ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthSecretRefSecretAccessKeySecretRef",
    "ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthWorkloadIdentity",
    "ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef",
    "ClusterGeneratorSpecGeneratorGithubAccessTokenSpec",
    "ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuth",
    "ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuthPrivateKey",
    "ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuthPrivateKeySecretRef",
    "ClusterGeneratorSpecGeneratorGrafanaSpec",
    "ClusterGeneratorSpecGeneratorGrafanaSpecAuth",
    "ClusterGeneratorSpecGeneratorGrafanaSpecAuthBasic",
    "ClusterGeneratorSpecGeneratorGrafanaSpecAuthBasicPassword",
    "ClusterGeneratorSpecGeneratorGrafanaSpecAuthToken",
    "ClusterGeneratorSpecGeneratorGrafanaSpecServiceAccount",
    "ClusterGeneratorSpecGeneratorPasswordSpec",
    "ClusterGeneratorSpecGeneratorQuayAccessTokenSpec",
    "ClusterGeneratorSpecGeneratorQuayAccessTokenSpecServiceAccountRef",
    "ClusterGeneratorSpecGeneratorStsSessionTokenSpec",
    "ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuth",
    "ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthJwt",
    "ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthJwtServiceAccountRef",
    "ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRef",
    "ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefAccessKeyIdSecretRef",
    "ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefSecretAccessKeySecretRef",
    "ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefSessionTokenSecretRef",
    "ClusterGeneratorSpecGeneratorStsSessionTokenSpecRequestParameters",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpec",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProvider",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuth",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRole",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRoleRoleRef",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRoleSecretRef",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCert",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCertClientCert",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCertSecretRef",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIam",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamJwt",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamJwtServiceAccountRef",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRef",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefAccessKeyIdSecretRef",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefSecretAccessKeySecretRef",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefSessionTokenSecretRef",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwt",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountToken",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountTokenServiceAccountRef",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtSecretRef",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetes",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetesSecretRef",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetesServiceAccountRef",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthLdap",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthLdapSecretRef",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthTokenSecretRef",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthUserPass",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthUserPassSecretRef",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderCaProvider",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderCaProviderType",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTls",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTlsCertSecretRef",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTlsKeySecretRef",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderVersion",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecResultType",
    "ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecRetrySettings",
    "ClusterGeneratorSpecGeneratorWebhookSpec",
    "ClusterGeneratorSpecGeneratorWebhookSpecAuth",
    "ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlm",
    "ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlmPasswordSecret",
    "ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlmUsernameSecret",
    "ClusterGeneratorSpecGeneratorWebhookSpecCaProvider",
    "ClusterGeneratorSpecGeneratorWebhookSpecCaProviderType",
    "ClusterGeneratorSpecGeneratorWebhookSpecResult",
    "ClusterGeneratorSpecGeneratorWebhookSpecSecrets",
    "ClusterGeneratorSpecGeneratorWebhookSpecSecretsSecretRef",
    "ClusterGeneratorSpecKind",
    "EcrAuthorizationToken",
    "EcrAuthorizationTokenProps",
    "EcrAuthorizationTokenSpec",
    "EcrAuthorizationTokenSpecAuth",
    "EcrAuthorizationTokenSpecAuthJwt",
    "EcrAuthorizationTokenSpecAuthJwtServiceAccountRef",
    "EcrAuthorizationTokenSpecAuthSecretRef",
    "EcrAuthorizationTokenSpecAuthSecretRefAccessKeyIdSecretRef",
    "EcrAuthorizationTokenSpecAuthSecretRefSecretAccessKeySecretRef",
    "EcrAuthorizationTokenSpecAuthSecretRefSessionTokenSecretRef",
    "Fake",
    "FakeProps",
    "FakeSpec",
    "GcrAccessToken",
    "GcrAccessTokenProps",
    "GcrAccessTokenSpec",
    "GcrAccessTokenSpecAuth",
    "GcrAccessTokenSpecAuthSecretRef",
    "GcrAccessTokenSpecAuthSecretRefSecretAccessKeySecretRef",
    "GcrAccessTokenSpecAuthWorkloadIdentity",
    "GcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef",
    "GeneratorState",
    "GeneratorStateProps",
    "GeneratorStateSpec",
    "GithubAccessToken",
    "GithubAccessTokenProps",
    "GithubAccessTokenSpec",
    "GithubAccessTokenSpecAuth",
    "GithubAccessTokenSpecAuthPrivateKey",
    "GithubAccessTokenSpecAuthPrivateKeySecretRef",
    "Grafana",
    "GrafanaProps",
    "GrafanaSpec",
    "GrafanaSpecAuth",
    "GrafanaSpecAuthBasic",
    "GrafanaSpecAuthBasicPassword",
    "GrafanaSpecAuthToken",
    "GrafanaSpecServiceAccount",
    "Password",
    "PasswordProps",
    "PasswordSpec",
    "QuayAccessToken",
    "QuayAccessTokenProps",
    "QuayAccessTokenSpec",
    "QuayAccessTokenSpecServiceAccountRef",
    "StsSessionToken",
    "StsSessionTokenProps",
    "StsSessionTokenSpec",
    "StsSessionTokenSpecAuth",
    "StsSessionTokenSpecAuthJwt",
    "StsSessionTokenSpecAuthJwtServiceAccountRef",
    "StsSessionTokenSpecAuthSecretRef",
    "StsSessionTokenSpecAuthSecretRefAccessKeyIdSecretRef",
    "StsSessionTokenSpecAuthSecretRefSecretAccessKeySecretRef",
    "StsSessionTokenSpecAuthSecretRefSessionTokenSecretRef",
    "StsSessionTokenSpecRequestParameters",
    "Uuid",
    "UuidProps",
    "VaultDynamicSecret",
    "VaultDynamicSecretProps",
    "VaultDynamicSecretSpec",
    "VaultDynamicSecretSpecProvider",
    "VaultDynamicSecretSpecProviderAuth",
    "VaultDynamicSecretSpecProviderAuthAppRole",
    "VaultDynamicSecretSpecProviderAuthAppRoleRoleRef",
    "VaultDynamicSecretSpecProviderAuthAppRoleSecretRef",
    "VaultDynamicSecretSpecProviderAuthCert",
    "VaultDynamicSecretSpecProviderAuthCertClientCert",
    "VaultDynamicSecretSpecProviderAuthCertSecretRef",
    "VaultDynamicSecretSpecProviderAuthIam",
    "VaultDynamicSecretSpecProviderAuthIamJwt",
    "VaultDynamicSecretSpecProviderAuthIamJwtServiceAccountRef",
    "VaultDynamicSecretSpecProviderAuthIamSecretRef",
    "VaultDynamicSecretSpecProviderAuthIamSecretRefAccessKeyIdSecretRef",
    "VaultDynamicSecretSpecProviderAuthIamSecretRefSecretAccessKeySecretRef",
    "VaultDynamicSecretSpecProviderAuthIamSecretRefSessionTokenSecretRef",
    "VaultDynamicSecretSpecProviderAuthJwt",
    "VaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountToken",
    "VaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountTokenServiceAccountRef",
    "VaultDynamicSecretSpecProviderAuthJwtSecretRef",
    "VaultDynamicSecretSpecProviderAuthKubernetes",
    "VaultDynamicSecretSpecProviderAuthKubernetesSecretRef",
    "VaultDynamicSecretSpecProviderAuthKubernetesServiceAccountRef",
    "VaultDynamicSecretSpecProviderAuthLdap",
    "VaultDynamicSecretSpecProviderAuthLdapSecretRef",
    "VaultDynamicSecretSpecProviderAuthTokenSecretRef",
    "VaultDynamicSecretSpecProviderAuthUserPass",
    "VaultDynamicSecretSpecProviderAuthUserPassSecretRef",
    "VaultDynamicSecretSpecProviderCaProvider",
    "VaultDynamicSecretSpecProviderCaProviderType",
    "VaultDynamicSecretSpecProviderTls",
    "VaultDynamicSecretSpecProviderTlsCertSecretRef",
    "VaultDynamicSecretSpecProviderTlsKeySecretRef",
    "VaultDynamicSecretSpecProviderVersion",
    "VaultDynamicSecretSpecResultType",
    "VaultDynamicSecretSpecRetrySettings",
    "Webhook",
    "WebhookProps",
    "WebhookSpec",
    "WebhookSpecAuth",
    "WebhookSpecAuthNtlm",
    "WebhookSpecAuthNtlmPasswordSecret",
    "WebhookSpecAuthNtlmUsernameSecret",
    "WebhookSpecCaProvider",
    "WebhookSpecCaProviderType",
    "WebhookSpecResult",
    "WebhookSpecSecrets",
    "WebhookSpecSecretsSecretRef",
]

publication.publish()

def _typecheckingstub__b58469b24a4dd77e433bdd0894fb9acf8f428c176df20a9d7a18d63dc8d907f4(
    scope: _constructs_77d1e7e8.Construct,
    id: builtins.str,
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Optional[typing.Union[AcrAccessTokenSpec, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__780b658e8801c2a8877f481fd986fe4cdd0d99fbeb702002190f4aa500cbb559(
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Optional[typing.Union[AcrAccessTokenSpec, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__e1188e5929acfbbe541de058d5bdc0c3e6d440a2035d6ce86ae825d2b5970383(
    *,
    auth: typing.Union[AcrAccessTokenSpecAuth, typing.Dict[builtins.str, typing.Any]],
    registry: builtins.str,
    environment_type: typing.Optional[AcrAccessTokenSpecEnvironmentType] = None,
    scope: typing.Optional[builtins.str] = None,
    tenant_id: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__3a17eab72333c02296dc7f6307c29604ea9a40c1ce436bd269d4191d4709bb1d(
    *,
    managed_identity: typing.Optional[typing.Union[AcrAccessTokenSpecAuthManagedIdentity, typing.Dict[builtins.str, typing.Any]]] = None,
    service_principal: typing.Optional[typing.Union[AcrAccessTokenSpecAuthServicePrincipal, typing.Dict[builtins.str, typing.Any]]] = None,
    workload_identity: typing.Optional[typing.Union[AcrAccessTokenSpecAuthWorkloadIdentity, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__d3496f91014f90715c72e1d9c0fa20f3cfc6a3f8c9e3ac3235a69b7ccde7fbb8(
    *,
    identity_id: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__782de22c9a1e53cf71ef721256c452f555b4a87fa61fa3657699af35b2d4fc9c(
    *,
    secret_ref: typing.Union[AcrAccessTokenSpecAuthServicePrincipalSecretRef, typing.Dict[builtins.str, typing.Any]],
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__a984720a180e603b46cc0b78e2bed7f4b7631e98821965df9496bdb760e60e39(
    *,
    client_id: typing.Optional[typing.Union[AcrAccessTokenSpecAuthServicePrincipalSecretRefClientId, typing.Dict[builtins.str, typing.Any]]] = None,
    client_secret: typing.Optional[typing.Union[AcrAccessTokenSpecAuthServicePrincipalSecretRefClientSecret, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__0b79bca6f37947d2a7ae2c512a6aab77a20054adb9de54b29e1fb65eace7f4c5(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__59ab052d3221edb153fc5273b3020c1f9474bc5688618e2d67fe9c5f9141ec6e(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__75713e68e1305d61adc704c00bc5068c4d3765385d5bb9b2bd763d760a61d39c(
    *,
    service_account_ref: typing.Optional[typing.Union[AcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__ddf0afa1f998410811287e82c3097165fb87092b51d21d6220a7bd0ceedb8ebe(
    *,
    name: builtins.str,
    audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__9a344af75ed1cbccde2cb0736d9fd19650ccfcf8db8041ebef1f47376fdd8893(
    scope: _constructs_77d1e7e8.Construct,
    id: builtins.str,
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Optional[typing.Union[ClusterGeneratorSpec, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__207c380f932a7c6b5b9d3e0bbd7a5201b91f49ecb28f7e16c23097608f878a95(
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Optional[typing.Union[ClusterGeneratorSpec, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__64d7f76e7038ac114e970dfd5c153b3eb78c0bd1f509f47d2e2323fe85dee042(
    *,
    generator: typing.Union[ClusterGeneratorSpecGenerator, typing.Dict[builtins.str, typing.Any]],
    kind: ClusterGeneratorSpecKind,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__75697d100ce0404120222110ca16af3984f4ab31958e84b7756b37400e311f59(
    *,
    acr_access_token_spec: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorAcrAccessTokenSpec, typing.Dict[builtins.str, typing.Any]]] = None,
    ecr_authorization_token_spec: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpec, typing.Dict[builtins.str, typing.Any]]] = None,
    fake_spec: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorFakeSpec, typing.Dict[builtins.str, typing.Any]]] = None,
    gcr_access_token_spec: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorGcrAccessTokenSpec, typing.Dict[builtins.str, typing.Any]]] = None,
    github_access_token_spec: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorGithubAccessTokenSpec, typing.Dict[builtins.str, typing.Any]]] = None,
    grafana_spec: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorGrafanaSpec, typing.Dict[builtins.str, typing.Any]]] = None,
    password_spec: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorPasswordSpec, typing.Dict[builtins.str, typing.Any]]] = None,
    quay_access_token_spec: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorQuayAccessTokenSpec, typing.Dict[builtins.str, typing.Any]]] = None,
    sts_session_token_spec: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorStsSessionTokenSpec, typing.Dict[builtins.str, typing.Any]]] = None,
    uuid_spec: typing.Any = None,
    vault_dynamic_secret_spec: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpec, typing.Dict[builtins.str, typing.Any]]] = None,
    webhook_spec: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorWebhookSpec, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__32c3cfb77fca6e94afe340dbd2ce7fd362533690b4a5bb8be7f89eb9ffad6954(
    *,
    auth: typing.Union[ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuth, typing.Dict[builtins.str, typing.Any]],
    registry: builtins.str,
    environment_type: typing.Optional[ClusterGeneratorSpecGeneratorAcrAccessTokenSpecEnvironmentType] = None,
    scope: typing.Optional[builtins.str] = None,
    tenant_id: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__072c1a68bb9ff416e5ccefff762ee5c327b6c6de3469b1275eb05d997ced3f3c(
    *,
    managed_identity: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthManagedIdentity, typing.Dict[builtins.str, typing.Any]]] = None,
    service_principal: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipal, typing.Dict[builtins.str, typing.Any]]] = None,
    workload_identity: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthWorkloadIdentity, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__dd8060e4227f6226de189ed62d96d1dc8717d4afe6b8a4bc76056e4f094009e4(
    *,
    identity_id: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__225e6080231fd8bc5a63fd915cf9ab3f134297b9a067f5474ad283159e35a281(
    *,
    secret_ref: typing.Union[ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRef, typing.Dict[builtins.str, typing.Any]],
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__0576c090978772e2637761bf2418b1e576ad1ee0c6e30e25ce92dde0912a4403(
    *,
    client_id: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRefClientId, typing.Dict[builtins.str, typing.Any]]] = None,
    client_secret: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthServicePrincipalSecretRefClientSecret, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__e68cf16cb70f2ae0d8972eedac8e207caacf468d8b68461fac4d28c373642ec2(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__788ff2bccef6a0ebbe6b1098111be5ad2ba7eee98205a83d00e256cd60b90fe1(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__7a4acab66a42181590587e19c100a1d7003b65b1d598652c5f1488434a472fee(
    *,
    service_account_ref: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorAcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__2c68f57cbeb67b574e5a877d5e187c847dc30c3640b23c4c04763b2a37647017(
    *,
    name: builtins.str,
    audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__7feb236f7f8335245adcf0201e0e6420ddf651d09231a4e577189b005b5398b9(
    *,
    region: builtins.str,
    auth: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuth, typing.Dict[builtins.str, typing.Any]]] = None,
    role: typing.Optional[builtins.str] = None,
    scope: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__b49d7ee1addfbf6e7385a299a9ccc30c848df7b4a1e27f2bda288dd43265d0de(
    *,
    jwt: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthJwt, typing.Dict[builtins.str, typing.Any]]] = None,
    secret_ref: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__999087dd2add6c11bb5aebdfa9c03015b3c8b3e432c6c576b46596aac07d1c22(
    *,
    service_account_ref: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthJwtServiceAccountRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__544153e51088c5c19ab22ddfc28cae00e464ac73d8349a958d037764766cf9f8(
    *,
    name: builtins.str,
    audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__43a336479ba385edf417d5a66424a3fcf31b9f4115de62dc32d60ac5f316d383(
    *,
    access_key_id_secret_ref: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefAccessKeyIdSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
    secret_access_key_secret_ref: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefSecretAccessKeySecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
    session_token_secret_ref: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorEcrAuthorizationTokenSpecAuthSecretRefSessionTokenSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__f97c93efa15a9809bde63d0f97633067aff530a43ed949824dc7bc76e9871735(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__bde2f101525a2945490e3e868e0c47768925132383751c8fc136c6399674bdba(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__7a4a61094821c7569683a2f537b0248ded8e4d034dbd5066ed28c9e88da147e4(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__2c86832ce77d47f397dde092dc8227f1703d1315bd5a48a4515d7255dd73a887(
    *,
    controller: typing.Optional[builtins.str] = None,
    data: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__6b9360ae269e38195de96ddce27de70ca878354be107a7d7c5e7f7f3a5ff18c8(
    *,
    auth: typing.Union[ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuth, typing.Dict[builtins.str, typing.Any]],
    project_id: builtins.str,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__5c8999aeefd932f01d9db846a206c060725cfe557132891c96a281dd55eb65cb(
    *,
    secret_ref: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
    workload_identity: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthWorkloadIdentity, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__69d2db6600643f3c5fa4f842ad2a5bbebaa2fb26b7dafa8012171b5e49d181b3(
    *,
    secret_access_key_secret_ref: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthSecretRefSecretAccessKeySecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__34a05f31abd31deb2dcbf758e0186bd7aecddb446e8f2b2fa7d99ea3d9e87bdd(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__887b623b0239bbb2317604070f1fb61930a4e755b022243ffbd63f615a93873a(
    *,
    cluster_location: builtins.str,
    cluster_name: builtins.str,
    service_account_ref: typing.Union[ClusterGeneratorSpecGeneratorGcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef, typing.Dict[builtins.str, typing.Any]],
    cluster_project_id: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__5414094787b3664e12f165e43a7b615bd19ef1a0e2034f3d3c910a2379cdce1d(
    *,
    name: builtins.str,
    audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__292ec9b435c52ded2f9e1a3fc879dc60a480c74153810bcd8257587046e66853(
    *,
    app_id: builtins.str,
    auth: typing.Union[ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuth, typing.Dict[builtins.str, typing.Any]],
    install_id: builtins.str,
    permissions: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    repositories: typing.Optional[typing.Sequence[builtins.str]] = None,
    url: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__1110b3599256f7705731d088240f75aee915ccf9f75505751961559d4cea83e0(
    *,
    private_key: typing.Union[ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuthPrivateKey, typing.Dict[builtins.str, typing.Any]],
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__337db2c2fa34849a191d608439f90fac159f2d703d407a4522719e4df8609142(
    *,
    secret_ref: typing.Union[ClusterGeneratorSpecGeneratorGithubAccessTokenSpecAuthPrivateKeySecretRef, typing.Dict[builtins.str, typing.Any]],
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__9f5225114d04258c4451905d0b8fab6c9f168173f252619ec0e7e3456af07f4c(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__a03b1f0e454b3b76e179e25c68ac74f11bb9cebe3337ab374b3f2ed4d9ed2181(
    *,
    auth: typing.Union[ClusterGeneratorSpecGeneratorGrafanaSpecAuth, typing.Dict[builtins.str, typing.Any]],
    service_account: typing.Union[ClusterGeneratorSpecGeneratorGrafanaSpecServiceAccount, typing.Dict[builtins.str, typing.Any]],
    url: builtins.str,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__c7d48488f332ab62b6ff8f5758ff141bd4ec8d41be6369cc454654d1635bc550(
    *,
    basic: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorGrafanaSpecAuthBasic, typing.Dict[builtins.str, typing.Any]]] = None,
    token: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorGrafanaSpecAuthToken, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__0ca9e0312250798706b0bbbc493bb9f05d7676fc92dd825ae023d37d7286ef86(
    *,
    password: typing.Union[ClusterGeneratorSpecGeneratorGrafanaSpecAuthBasicPassword, typing.Dict[builtins.str, typing.Any]],
    username: builtins.str,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__52cbf108e35477a5a146125711b6edb5cb2e91146f6276f2d40795dc8149d0ec(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__5d5967d1dd883faa977030d1a3045ba2620b8f9c2c50ca22bba80be43429c9fe(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__c952f78a75a5bbd20df3105965c9af2c7aabb17469a906f4db76fe7c9d677307(
    *,
    name: builtins.str,
    role: builtins.str,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__6b3ec65a0916fa97e69ec9837c4c6798e17e81eb424563cc5bd5349de2ec13d6(
    *,
    allow_repeat: builtins.bool,
    length: jsii.Number,
    no_upper: builtins.bool,
    digits: typing.Optional[jsii.Number] = None,
    symbol_characters: typing.Optional[builtins.str] = None,
    symbols: typing.Optional[jsii.Number] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__b760f8c5fad1753090f4c7fdeb158c58f3a5285b02656fd11f8fd4e619c8135f(
    *,
    robot_account: builtins.str,
    service_account_ref: typing.Union[ClusterGeneratorSpecGeneratorQuayAccessTokenSpecServiceAccountRef, typing.Dict[builtins.str, typing.Any]],
    url: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__b680ae1b78ef0032f149e40bb4a19c7a0b03d8afb67edc0edde80e855f7132ee(
    *,
    name: builtins.str,
    audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__7b156d2563dfcafd7828f40e867dc8dbb62b46dfa7870adff7e1ac851c3b64a1(
    *,
    region: builtins.str,
    auth: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuth, typing.Dict[builtins.str, typing.Any]]] = None,
    request_parameters: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorStsSessionTokenSpecRequestParameters, typing.Dict[builtins.str, typing.Any]]] = None,
    role: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__500c178b87b78973cb00ae5c3d241645a7a490f3fe1a6e4706a7f938aac2027f(
    *,
    jwt: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthJwt, typing.Dict[builtins.str, typing.Any]]] = None,
    secret_ref: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__98ee3f0efdabb7496c0d2194a3493544bf0466015126da23cfb9febac799df65(
    *,
    service_account_ref: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthJwtServiceAccountRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__c2b7233aba1192fb4d482fa99d660bc1f1ba06a2aee2f70888ee3b93ba93edfe(
    *,
    name: builtins.str,
    audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__06818579d44e8d646ecdca0be2f54e320b0be3df9f6b0e5edaacc29106f66f6c(
    *,
    access_key_id_secret_ref: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefAccessKeyIdSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
    secret_access_key_secret_ref: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefSecretAccessKeySecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
    session_token_secret_ref: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorStsSessionTokenSpecAuthSecretRefSessionTokenSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__e5f427fb43d20a03744b87747aa16efdc936bdbf5b1ba330f266c27af19e6eb2(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__5cf2daf36a0f3998c035450336e8d6275fb5e89e069a644559eddc2c1972f887(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__bba4b7c291a21145c9cbb073dd1e7f376419e55e1589bd1f3197fe98d06adfb2(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__ca0a298660bade99205cdcd1774aa724a0b72dd6d95821e051f8510cba60ffa5(
    *,
    serial_number: typing.Optional[builtins.str] = None,
    session_duration: typing.Optional[jsii.Number] = None,
    token_code: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__10e2321e1cd5730bc9b0e182284aef50907db67d44c1acfada3f65f196f1582c(
    *,
    path: builtins.str,
    provider: typing.Union[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProvider, typing.Dict[builtins.str, typing.Any]],
    allow_empty_response: typing.Optional[builtins.bool] = None,
    controller: typing.Optional[builtins.str] = None,
    method: typing.Optional[builtins.str] = None,
    parameters: typing.Any = None,
    result_type: typing.Optional[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecResultType] = None,
    retry_settings: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecRetrySettings, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__02abd566c822847d8f25656374f5c631e294093b6020fa8ec60a874e692efe08(
    *,
    server: builtins.str,
    auth: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuth, typing.Dict[builtins.str, typing.Any]]] = None,
    ca_bundle: typing.Optional[builtins.str] = None,
    ca_provider: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderCaProvider, typing.Dict[builtins.str, typing.Any]]] = None,
    forward_inconsistent: typing.Optional[builtins.bool] = None,
    headers: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    namespace: typing.Optional[builtins.str] = None,
    path: typing.Optional[builtins.str] = None,
    read_your_writes: typing.Optional[builtins.bool] = None,
    tls: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTls, typing.Dict[builtins.str, typing.Any]]] = None,
    version: typing.Optional[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderVersion] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__6b46ee2f06aed6663e7fe9a51398de8f44b17d4c003a7d923ba902471c122d6c(
    *,
    app_role: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRole, typing.Dict[builtins.str, typing.Any]]] = None,
    cert: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCert, typing.Dict[builtins.str, typing.Any]]] = None,
    iam: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIam, typing.Dict[builtins.str, typing.Any]]] = None,
    jwt: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwt, typing.Dict[builtins.str, typing.Any]]] = None,
    kubernetes: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetes, typing.Dict[builtins.str, typing.Any]]] = None,
    ldap: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthLdap, typing.Dict[builtins.str, typing.Any]]] = None,
    namespace: typing.Optional[builtins.str] = None,
    token_secret_ref: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthTokenSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
    user_pass: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthUserPass, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__b1b2ca1676dd1d58a898f4207b7372f83856a2dea3dca6925938016912fe01bc(
    *,
    path: builtins.str,
    secret_ref: typing.Union[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRoleSecretRef, typing.Dict[builtins.str, typing.Any]],
    role_id: typing.Optional[builtins.str] = None,
    role_ref: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthAppRoleRoleRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__eac36a6ae09b90df622a8885e385f95e01a2bb1c1025cb1eb6748db3b6260c7b(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__cf9b835649610475ffd96ef188f0154ea6898cb01beb95dfa906f18367047270(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__6a48a6f2044f51d1f9bce54540f955f0f3c0e34ca0c5a81e258fb25258a1812d(
    *,
    client_cert: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCertClientCert, typing.Dict[builtins.str, typing.Any]]] = None,
    secret_ref: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthCertSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__b61c2f8625d6b6eefba3b38478f3db3ca23f00985a1fbade641377af48f21430(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__4096b6822d9c79e1ab7826475c9b916df90eb40d1748c567b038c74e769d3520(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__1ae76c20b2d3d164d46c1682c2dcbfe8293b4b1a1c429ba0d9ccd8de1623aefa(
    *,
    vault_role: builtins.str,
    external_id: typing.Optional[builtins.str] = None,
    jwt: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamJwt, typing.Dict[builtins.str, typing.Any]]] = None,
    path: typing.Optional[builtins.str] = None,
    region: typing.Optional[builtins.str] = None,
    role: typing.Optional[builtins.str] = None,
    secret_ref: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
    vault_aws_iam_server_id: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__3fcc58f46b972c368790d6aa7a694146a711fc7d454e2384196381bd3d4e3dcb(
    *,
    service_account_ref: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamJwtServiceAccountRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__f63c96e8522ed1b707467a41e21ae71d33e43a489100b2d1c588267e91dda515(
    *,
    name: builtins.str,
    audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__7575de5f8d585e9e8d36ce3120891d2047b67e87999e2f56ac0153b68fd7536c(
    *,
    access_key_id_secret_ref: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefAccessKeyIdSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
    secret_access_key_secret_ref: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefSecretAccessKeySecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
    session_token_secret_ref: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthIamSecretRefSessionTokenSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__d22620df921362fb2070bb61692fe2d2d4bf351da0f0dc43557fe4cf436cd013(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__c40fc197e2530062ac9b7ca3810c8fb65299f01a12ef9d4625d149ec27bc04f9(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__dadefaafed9cee8323181fe7b8a76aaeba9aaca5d903a75d4b86a38bbffd3c2a(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__229aac6ec0f9c5f66d1afbf2decfa1c8000fc02dc6e634373bc263260b357be5(
    *,
    path: builtins.str,
    kubernetes_service_account_token: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountToken, typing.Dict[builtins.str, typing.Any]]] = None,
    role: typing.Optional[builtins.str] = None,
    secret_ref: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__b199dcf4dc37caedda88bf3e2af1f395f9eac497f86fd3c9ae9e442da85fcb3c(
    *,
    service_account_ref: typing.Union[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountTokenServiceAccountRef, typing.Dict[builtins.str, typing.Any]],
    audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
    expiration_seconds: typing.Optional[jsii.Number] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__c0016c0d95b5a9e529ece0f4d6f80e3743686de5accf1efd2a269de96df7c640(
    *,
    name: builtins.str,
    audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__7017adabfb955003a67f5f12cf98885af650cc813cb74468384a84a23de6e3e7(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__55a715f0a7b9bcda5866ee8db8c2a171f2eccf9248b40b5dbb9405e47a65c174(
    *,
    mount_path: builtins.str,
    role: builtins.str,
    secret_ref: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetesSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
    service_account_ref: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthKubernetesServiceAccountRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__730f50d2640b9b2319c67640982a729e38afa13f614f8a7a2162ac6a4e2311b9(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__885d994531e7fc8461134148bac78f677ccb70cd6801065ed09c572438a39362(
    *,
    name: builtins.str,
    audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__14be59466583be10ad4bceb3c7eec0590d6926f769661ac2d858b9a6f02c06a5(
    *,
    path: builtins.str,
    username: builtins.str,
    secret_ref: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthLdapSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__9d1b45b98fc97110f897716ff6bb350ca01b97a452a0e7ed1631a19e2fa1677e(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__ba0256d12910007e8b85f34c9d7ea393f52fa367cca7b507767570486806cb3e(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__814bccc7eee2bb0b01c55e861c30268f3aa9e3d17c1930afb52360cdbf7a0fa2(
    *,
    path: builtins.str,
    username: builtins.str,
    secret_ref: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderAuthUserPassSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__1c41bb2e70be3a1141aa7931963f1605cf7b10f76a2d70a55fe2005969b40056(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__340569b935c53537966a2561c57a24a76cbf9c69dbf7689874dd5ce46ffeaf82(
    *,
    name: builtins.str,
    type: ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderCaProviderType,
    key: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__057069f97defad41a9a7d25d600958df8a1fb8a29b4c5656f593c16c84c882c1(
    *,
    cert_secret_ref: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTlsCertSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
    key_secret_ref: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorVaultDynamicSecretSpecProviderTlsKeySecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__a7a43432578b558898e36df977d0c9e9e0a455970e6f0eeade3dc49f5f8200e1(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__5b47872d55b2aa3ce83911b888bb441922abcd0a955c401e37dbef745d2e203d(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__b74fcec0cfc5ad62fc03a55496882bcc7c5fc822f3d8f6820314e48d530e85f8(
    *,
    max_retries: typing.Optional[jsii.Number] = None,
    retry_interval: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__d6461244ada6ac27bc8b5825bc53378b49b97c43164c4e5d508c69ab37ef4761(
    *,
    result: typing.Union[ClusterGeneratorSpecGeneratorWebhookSpecResult, typing.Dict[builtins.str, typing.Any]],
    url: builtins.str,
    auth: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorWebhookSpecAuth, typing.Dict[builtins.str, typing.Any]]] = None,
    body: typing.Optional[builtins.str] = None,
    ca_bundle: typing.Optional[builtins.str] = None,
    ca_provider: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorWebhookSpecCaProvider, typing.Dict[builtins.str, typing.Any]]] = None,
    headers: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    method: typing.Optional[builtins.str] = None,
    secrets: typing.Optional[typing.Sequence[typing.Union[ClusterGeneratorSpecGeneratorWebhookSpecSecrets, typing.Dict[builtins.str, typing.Any]]]] = None,
    timeout: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__5dcfc882e004f94cf73db65a2a920c62c718b548501cfa608829f09e91423b6d(
    *,
    ntlm: typing.Optional[typing.Union[ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlm, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__1c7b235434f71cb2dedf89df634e92c9be7c19319bdbabf850fb2ef0f7f26a81(
    *,
    password_secret: typing.Union[ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlmPasswordSecret, typing.Dict[builtins.str, typing.Any]],
    username_secret: typing.Union[ClusterGeneratorSpecGeneratorWebhookSpecAuthNtlmUsernameSecret, typing.Dict[builtins.str, typing.Any]],
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__89e3c64096d7ab15ba070babc315844393aa774d5e6d59f8d8af1081809d3a33(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__debabacb7a72e2aa4ed6e808a4b80893eb1122c2c840d54555a48ec65fe99f40(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__4b92096e419e1807bd3716a182558dd52eb79fd93b0891aae2196fe701b6ef16(
    *,
    name: builtins.str,
    type: ClusterGeneratorSpecGeneratorWebhookSpecCaProviderType,
    key: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__8041ab4574aca2838e415c6546545a99564650a2e591ef65839792832acd0ddb(
    *,
    json_path: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__82ab7197f1b285356b812b884d29838271d2890f88cc26e4ec5c6691a6c19ee4(
    *,
    name: builtins.str,
    secret_ref: typing.Union[ClusterGeneratorSpecGeneratorWebhookSpecSecretsSecretRef, typing.Dict[builtins.str, typing.Any]],
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__c09ce5b92036fdb91cd0502923a430b4067e058dbfbceffe4e310b5de877491c(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__e71cfb104a01494a1528bff38caa7ed42d6867f4d83a50d779a8e249dea7183a(
    scope: _constructs_77d1e7e8.Construct,
    id: builtins.str,
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Optional[typing.Union[EcrAuthorizationTokenSpec, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__7e431d24fa6016e556b9f4cdc9b5634a7ec0488fcdd0149846b1011367978e2a(
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Optional[typing.Union[EcrAuthorizationTokenSpec, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__324512f7d0f8d8b457280dd1e15f21985b97b88f08bab8a4ee40bca0e64ea7f6(
    *,
    region: builtins.str,
    auth: typing.Optional[typing.Union[EcrAuthorizationTokenSpecAuth, typing.Dict[builtins.str, typing.Any]]] = None,
    role: typing.Optional[builtins.str] = None,
    scope: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__99a4157b913631f69b599f277cde66f7621cd2ccbc79b7044db9d53b11fbed6e(
    *,
    jwt: typing.Optional[typing.Union[EcrAuthorizationTokenSpecAuthJwt, typing.Dict[builtins.str, typing.Any]]] = None,
    secret_ref: typing.Optional[typing.Union[EcrAuthorizationTokenSpecAuthSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__e21f0831584304a498cb602853af5f59bc58668301a4c6f20c4e2842a2297ff1(
    *,
    service_account_ref: typing.Optional[typing.Union[EcrAuthorizationTokenSpecAuthJwtServiceAccountRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__8c10b7f6ffeed346ecf29b79cc6266f31bf1bd8effb7681cb7cb2578520cfdb7(
    *,
    name: builtins.str,
    audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__bf78f11dcfa2cd9f8940d60487a5c7d2f01d9a4dd8d77e4bf8dcdd56085c7d95(
    *,
    access_key_id_secret_ref: typing.Optional[typing.Union[EcrAuthorizationTokenSpecAuthSecretRefAccessKeyIdSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
    secret_access_key_secret_ref: typing.Optional[typing.Union[EcrAuthorizationTokenSpecAuthSecretRefSecretAccessKeySecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
    session_token_secret_ref: typing.Optional[typing.Union[EcrAuthorizationTokenSpecAuthSecretRefSessionTokenSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__3d68e594efb66902569f54fe98715ea46d6ba8ca83b27e99b98f38a8ade43a65(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__054461f11158e4dc81b90d77e99ce0fe74d37b917fedbcb4284ed8881d1bae57(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__1b8c5ee22e2427c12cabf67d5cf6b1a7cdc91842cd7af9a753bc42ce2dd80e5d(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__b57d91e19285b6a8a017d2a83639b2a99389613e7a3f5ca4ebf7e0e4a717f1f1(
    scope: _constructs_77d1e7e8.Construct,
    id: builtins.str,
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Optional[typing.Union[FakeSpec, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__f6bcab3c7c36ee2c872120a58cef6b1878a6276f893325a6ff369928c8e1c75c(
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Optional[typing.Union[FakeSpec, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__44ead58e4ef3208607864017deeaf29547ca20b830ae43c943a9ea1bb647a2be(
    *,
    controller: typing.Optional[builtins.str] = None,
    data: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__b80007d0392365dc569ce8bd4015fe900acd943c3d36aa66178ec2ac84597b7f(
    scope: _constructs_77d1e7e8.Construct,
    id: builtins.str,
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Optional[typing.Union[GcrAccessTokenSpec, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__1ebf58f1879563b8440f47f35b33c5f08df60cc497c53708ec8773b08a2c3b3c(
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Optional[typing.Union[GcrAccessTokenSpec, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__a01287b24f44728bc8b80776e9475534ab7affaf0f4524cbf7addab8e431089e(
    *,
    auth: typing.Union[GcrAccessTokenSpecAuth, typing.Dict[builtins.str, typing.Any]],
    project_id: builtins.str,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__93eb12ae2068134fa04136f7c937cab838ac29d82534e5b5803842066fae6e48(
    *,
    secret_ref: typing.Optional[typing.Union[GcrAccessTokenSpecAuthSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
    workload_identity: typing.Optional[typing.Union[GcrAccessTokenSpecAuthWorkloadIdentity, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__f65d1a322d6d23716a2925defeb951fc75b6741a65f92879df1e71df097441a8(
    *,
    secret_access_key_secret_ref: typing.Optional[typing.Union[GcrAccessTokenSpecAuthSecretRefSecretAccessKeySecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__cbabefd39b46e713e4e457a716bfc18a7f475fccb20674d7eb3a5cdf17b09f7e(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__199ea61bce5117046e2f5da4c5a50856e146ebaa2773f338ff7d01e23079571f(
    *,
    cluster_location: builtins.str,
    cluster_name: builtins.str,
    service_account_ref: typing.Union[GcrAccessTokenSpecAuthWorkloadIdentityServiceAccountRef, typing.Dict[builtins.str, typing.Any]],
    cluster_project_id: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__4f74d21068366cc4deb9b1d016fb257384b4390cdceab57845386c22ae854561(
    *,
    name: builtins.str,
    audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__958486a855120fc7a31aee0ba4cca65a04bf9a182445fbe480e553b98ccd9036(
    scope: _constructs_77d1e7e8.Construct,
    id: builtins.str,
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Optional[typing.Union[GeneratorStateSpec, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__64f82fa95da182d383bede8cfe8bee7ac5e64f879b5ea01270eecda15719f058(
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Optional[typing.Union[GeneratorStateSpec, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__5d80cd3e33b0c4a2ec892301c844aee6f41a860238c42c36e51455f76caf187a(
    *,
    resource: typing.Any,
    state: typing.Any,
    garbage_collection_deadline: typing.Optional[datetime.datetime] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__4a77570c44994c62f1495ca397b0a38a34f7359399b5a5c444421df203d8116b(
    scope: _constructs_77d1e7e8.Construct,
    id: builtins.str,
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Optional[typing.Union[GithubAccessTokenSpec, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__03fef391cab2e0e91a690c6535a6c54804108aecbfe23f30906d896706375319(
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Optional[typing.Union[GithubAccessTokenSpec, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__7de89f6322b407b1d8de8e9206a8daa3d6a9aeefc3facc2b15cd3f2343d619bb(
    *,
    app_id: builtins.str,
    auth: typing.Union[GithubAccessTokenSpecAuth, typing.Dict[builtins.str, typing.Any]],
    install_id: builtins.str,
    permissions: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    repositories: typing.Optional[typing.Sequence[builtins.str]] = None,
    url: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__eb19f408f5f81b80adaeb0752891235a4de94e26ecf80e23ae76b0df8fce09e1(
    *,
    private_key: typing.Union[GithubAccessTokenSpecAuthPrivateKey, typing.Dict[builtins.str, typing.Any]],
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__cb39af0e0f51b28201dc29bc178b9febff7228412f055e9c07142114da340837(
    *,
    secret_ref: typing.Union[GithubAccessTokenSpecAuthPrivateKeySecretRef, typing.Dict[builtins.str, typing.Any]],
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__f44ce4532c26c546f28a977216d68c41dc675e15baa70c2618c40a1fd97f8e6b(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__d80f5795b34eebd4414d453e74364019631d46df1d6f77332167900032b31ac2(
    scope: _constructs_77d1e7e8.Construct,
    id: builtins.str,
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Optional[typing.Union[GrafanaSpec, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__653972c42261a54dd717de914b7983783972daddb15fd7d6225a1b5875a8244e(
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Optional[typing.Union[GrafanaSpec, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__6625fbfd4423ace39404bc8b275e8825a4e344ae14018a39aa1fad007fdc9a36(
    *,
    auth: typing.Union[GrafanaSpecAuth, typing.Dict[builtins.str, typing.Any]],
    service_account: typing.Union[GrafanaSpecServiceAccount, typing.Dict[builtins.str, typing.Any]],
    url: builtins.str,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__5bfaa65d8f432f88a0afafe11fd84a114db79a53e66f959629a253eaadfc36e4(
    *,
    basic: typing.Optional[typing.Union[GrafanaSpecAuthBasic, typing.Dict[builtins.str, typing.Any]]] = None,
    token: typing.Optional[typing.Union[GrafanaSpecAuthToken, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__0542f077ce34199f3ffc66976e46e28ec5e0917422dc9b25348d809fce646abb(
    *,
    password: typing.Union[GrafanaSpecAuthBasicPassword, typing.Dict[builtins.str, typing.Any]],
    username: builtins.str,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__378165568ab72ed346357c2af9813218ae826bea628ea6dcefbbbf7e29a79846(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__cff8454759fb223792b7471399e0c8d402d5677cb65b01c20b534a42a98a6aad(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__0b90062b32e8b1dfb708e1e449e63bfe0aa427c431738c846dd6d11249ad0851(
    *,
    name: builtins.str,
    role: builtins.str,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__4c09e9ade3db32eebcba799d9623871d6d90ce0ae11f370436996ea869284e6d(
    scope: _constructs_77d1e7e8.Construct,
    id: builtins.str,
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Optional[typing.Union[PasswordSpec, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__1cb0c41f9ff3670a053eb5f508cb64ec2242beb083de7e7c652d4a5b7699e91c(
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Optional[typing.Union[PasswordSpec, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__b4393f1aed12b90dce27cf67a339b9404fe1de87a2e6dc07a755ffa39d6d1349(
    *,
    allow_repeat: builtins.bool,
    length: jsii.Number,
    no_upper: builtins.bool,
    digits: typing.Optional[jsii.Number] = None,
    symbol_characters: typing.Optional[builtins.str] = None,
    symbols: typing.Optional[jsii.Number] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__58971dea6308deeb2631c838ee3c6601a0b25893b80479dc4e945254f22274b6(
    scope: _constructs_77d1e7e8.Construct,
    id: builtins.str,
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Optional[typing.Union[QuayAccessTokenSpec, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__c1de6b6de8dac96a29a81c78e7a31cd2fe43fbcb8590f2510368200297fde71d(
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Optional[typing.Union[QuayAccessTokenSpec, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__f2f7947dd3ee6ff17129eb636fd5d530fa48f6d2fec09d2559cef20aa537a9d7(
    *,
    robot_account: builtins.str,
    service_account_ref: typing.Union[QuayAccessTokenSpecServiceAccountRef, typing.Dict[builtins.str, typing.Any]],
    url: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__3e1a2c5b1a9946bee470f5e44e7010f914a64be38e1bd6c83605261840dff854(
    *,
    name: builtins.str,
    audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__6d24e2306191a5fd4c09bb6b3eba8a928429a33c1a208b4fa447525d2e6efb8e(
    scope: _constructs_77d1e7e8.Construct,
    id: builtins.str,
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Optional[typing.Union[StsSessionTokenSpec, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__99ba1ef4df49f58515dd98da924e78ed1ebbe8d10714eea217cc4e293774bf3f(
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Optional[typing.Union[StsSessionTokenSpec, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__57971c517b07bc88d332106d38b683b3192461b1e272956332f6a1e7a07ffd48(
    *,
    region: builtins.str,
    auth: typing.Optional[typing.Union[StsSessionTokenSpecAuth, typing.Dict[builtins.str, typing.Any]]] = None,
    request_parameters: typing.Optional[typing.Union[StsSessionTokenSpecRequestParameters, typing.Dict[builtins.str, typing.Any]]] = None,
    role: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__128238ae2232ebcc6bf164aa81bc2f0bce66e0e8323dc413175bb2d1cabededb(
    *,
    jwt: typing.Optional[typing.Union[StsSessionTokenSpecAuthJwt, typing.Dict[builtins.str, typing.Any]]] = None,
    secret_ref: typing.Optional[typing.Union[StsSessionTokenSpecAuthSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__0ef21507671ccea3e0d2148a2c99b012254c104057efec60f91b4f36ecbcbcd7(
    *,
    service_account_ref: typing.Optional[typing.Union[StsSessionTokenSpecAuthJwtServiceAccountRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__ef74d0e99a5dcb1aa1f95f0ef5e27a930a3ee6f122993effa5372a9f435d1af6(
    *,
    name: builtins.str,
    audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__1aa5ae84249fdfd41ca7b653dd80ec4600c5aac7fcdecbbdfd9861138e87de1c(
    *,
    access_key_id_secret_ref: typing.Optional[typing.Union[StsSessionTokenSpecAuthSecretRefAccessKeyIdSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
    secret_access_key_secret_ref: typing.Optional[typing.Union[StsSessionTokenSpecAuthSecretRefSecretAccessKeySecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
    session_token_secret_ref: typing.Optional[typing.Union[StsSessionTokenSpecAuthSecretRefSessionTokenSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__26880547e4d6d107f93525a8b3ddb6deab003815cab7d5a836b60408c97ce22e(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__25d67dc291615d535958749787fed9be52d1ba3e3c32ee47f076021cc75f627f(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__a802177567d2d782534f3eef4692d36d73e0a214f1a16b8229f4715ad33d029b(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__e77302456aefbef13fda79e9d9c8914e610c8325ae579419712258b0bd06c96f(
    *,
    serial_number: typing.Optional[builtins.str] = None,
    session_duration: typing.Optional[jsii.Number] = None,
    token_code: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__dabeb65c195f530626cc8b53a636523447b50d239eac35855f228858208d7100(
    scope: _constructs_77d1e7e8.Construct,
    id: builtins.str,
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Any = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__fc6f47b832cfa3206b7deedb2a4d4629cc00198a598cb3fa553cf5757efd0465(
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Any = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__9de7ad29b743a3478314c6a17debdf2b449820754873f9353e2c8fe6fefb8e48(
    scope: _constructs_77d1e7e8.Construct,
    id: builtins.str,
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Optional[typing.Union[VaultDynamicSecretSpec, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__31b50742f6e2bf3e29bb865c2a67519a6015bd8c040719626d607b2f4f05787f(
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Optional[typing.Union[VaultDynamicSecretSpec, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__c88f3beb5eebe3642bd7625e948d35a224c53cc7572853ef902f398263266288(
    *,
    path: builtins.str,
    provider: typing.Union[VaultDynamicSecretSpecProvider, typing.Dict[builtins.str, typing.Any]],
    allow_empty_response: typing.Optional[builtins.bool] = None,
    controller: typing.Optional[builtins.str] = None,
    method: typing.Optional[builtins.str] = None,
    parameters: typing.Any = None,
    result_type: typing.Optional[VaultDynamicSecretSpecResultType] = None,
    retry_settings: typing.Optional[typing.Union[VaultDynamicSecretSpecRetrySettings, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__99bb9f6b265462d6cb37ae7c7ac1a897af8d4eca0e046b25280a6a5eb0ddf60a(
    *,
    server: builtins.str,
    auth: typing.Optional[typing.Union[VaultDynamicSecretSpecProviderAuth, typing.Dict[builtins.str, typing.Any]]] = None,
    ca_bundle: typing.Optional[builtins.str] = None,
    ca_provider: typing.Optional[typing.Union[VaultDynamicSecretSpecProviderCaProvider, typing.Dict[builtins.str, typing.Any]]] = None,
    forward_inconsistent: typing.Optional[builtins.bool] = None,
    headers: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    namespace: typing.Optional[builtins.str] = None,
    path: typing.Optional[builtins.str] = None,
    read_your_writes: typing.Optional[builtins.bool] = None,
    tls: typing.Optional[typing.Union[VaultDynamicSecretSpecProviderTls, typing.Dict[builtins.str, typing.Any]]] = None,
    version: typing.Optional[VaultDynamicSecretSpecProviderVersion] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__f1db161975aac815c821c159e465d76a46225986d5820ef576591b42b9f95fc1(
    *,
    app_role: typing.Optional[typing.Union[VaultDynamicSecretSpecProviderAuthAppRole, typing.Dict[builtins.str, typing.Any]]] = None,
    cert: typing.Optional[typing.Union[VaultDynamicSecretSpecProviderAuthCert, typing.Dict[builtins.str, typing.Any]]] = None,
    iam: typing.Optional[typing.Union[VaultDynamicSecretSpecProviderAuthIam, typing.Dict[builtins.str, typing.Any]]] = None,
    jwt: typing.Optional[typing.Union[VaultDynamicSecretSpecProviderAuthJwt, typing.Dict[builtins.str, typing.Any]]] = None,
    kubernetes: typing.Optional[typing.Union[VaultDynamicSecretSpecProviderAuthKubernetes, typing.Dict[builtins.str, typing.Any]]] = None,
    ldap: typing.Optional[typing.Union[VaultDynamicSecretSpecProviderAuthLdap, typing.Dict[builtins.str, typing.Any]]] = None,
    namespace: typing.Optional[builtins.str] = None,
    token_secret_ref: typing.Optional[typing.Union[VaultDynamicSecretSpecProviderAuthTokenSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
    user_pass: typing.Optional[typing.Union[VaultDynamicSecretSpecProviderAuthUserPass, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__694b810088d74c88cb73306a438e0a284a0bdb9de47b1cb32eaa3818cdce846b(
    *,
    path: builtins.str,
    secret_ref: typing.Union[VaultDynamicSecretSpecProviderAuthAppRoleSecretRef, typing.Dict[builtins.str, typing.Any]],
    role_id: typing.Optional[builtins.str] = None,
    role_ref: typing.Optional[typing.Union[VaultDynamicSecretSpecProviderAuthAppRoleRoleRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__9a99fb0e822f1799fd218437bfc9f0467860abc0b235c8c0ec53c1588fa7694c(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__06f75a4d6e7bdddfad29285d9805b199b2095b6b69e37f08c865b2d156007b9e(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__397dacbf5d6cbf9d8bfbc50e753f1950aee0b37fec712f2c76630a0668f3e146(
    *,
    client_cert: typing.Optional[typing.Union[VaultDynamicSecretSpecProviderAuthCertClientCert, typing.Dict[builtins.str, typing.Any]]] = None,
    secret_ref: typing.Optional[typing.Union[VaultDynamicSecretSpecProviderAuthCertSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__b58294432d7c518baeb64f016bfac88a09ffd8adf9b8ca535499fa3213151182(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__68ed331536c95241f0ddad3378cad046ddd93e6a48174ce994cb1df3a464d36a(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__5af38260f87760cdeb000f50b6301f4794251e13a7b1b9767e70922eb3c2176c(
    *,
    vault_role: builtins.str,
    external_id: typing.Optional[builtins.str] = None,
    jwt: typing.Optional[typing.Union[VaultDynamicSecretSpecProviderAuthIamJwt, typing.Dict[builtins.str, typing.Any]]] = None,
    path: typing.Optional[builtins.str] = None,
    region: typing.Optional[builtins.str] = None,
    role: typing.Optional[builtins.str] = None,
    secret_ref: typing.Optional[typing.Union[VaultDynamicSecretSpecProviderAuthIamSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
    vault_aws_iam_server_id: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__755f376ef48f4b35fd53ce85e0facd33028f6681920cd7f29db5b5f121234af7(
    *,
    service_account_ref: typing.Optional[typing.Union[VaultDynamicSecretSpecProviderAuthIamJwtServiceAccountRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__70d3aeb75a438d9acdf35b597530aafe9dafff05ff3c888b3299b63fd7af2508(
    *,
    name: builtins.str,
    audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__942078f327579ee2ec8352e78815d24d32aedc6349eeaad52e0b478df1304bf8(
    *,
    access_key_id_secret_ref: typing.Optional[typing.Union[VaultDynamicSecretSpecProviderAuthIamSecretRefAccessKeyIdSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
    secret_access_key_secret_ref: typing.Optional[typing.Union[VaultDynamicSecretSpecProviderAuthIamSecretRefSecretAccessKeySecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
    session_token_secret_ref: typing.Optional[typing.Union[VaultDynamicSecretSpecProviderAuthIamSecretRefSessionTokenSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__5128dcc7b1f2fef664f57aac1b83767c24bc218f9a13360f6d462313905b3e3c(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__62ce9ed6591f09b9ad3bf3cb73b21f380e308f0578147c37cf827dca58235336(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__5237a9d2f5bbe28b8e8561982178657c137001b1fd187bcdf16b179626d3a617(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__545c29132ebf0518d8533ffee2e4c0a83e6074c0d9b2e21fcae009be46669414(
    *,
    path: builtins.str,
    kubernetes_service_account_token: typing.Optional[typing.Union[VaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountToken, typing.Dict[builtins.str, typing.Any]]] = None,
    role: typing.Optional[builtins.str] = None,
    secret_ref: typing.Optional[typing.Union[VaultDynamicSecretSpecProviderAuthJwtSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__4b475f364551889cfe113a71ba131461697147bf11041280bcba648eb628dd33(
    *,
    service_account_ref: typing.Union[VaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountTokenServiceAccountRef, typing.Dict[builtins.str, typing.Any]],
    audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
    expiration_seconds: typing.Optional[jsii.Number] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__3333e3e748041d6297548bda5b350634919c0f92240514def8d1409b096751e4(
    *,
    name: builtins.str,
    audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__96abba540513ab928fe5e7f6062f3c8143e07eda734654ef2b33e1c29b7385e0(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__3db9409bf746179327f1a68ae92cdef6ac3c5d1763ce35ba2f77b0afaa281ada(
    *,
    mount_path: builtins.str,
    role: builtins.str,
    secret_ref: typing.Optional[typing.Union[VaultDynamicSecretSpecProviderAuthKubernetesSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
    service_account_ref: typing.Optional[typing.Union[VaultDynamicSecretSpecProviderAuthKubernetesServiceAccountRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__4659bfab53d9dc36348d33a718d9e8ecfbe2bb88a426d276713dd23a457e62ff(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__86ab795d10d532e2cd677194c623dfd1c44794f096c0fdf250be3c75cbbfcea3(
    *,
    name: builtins.str,
    audiences: typing.Optional[typing.Sequence[builtins.str]] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__5b0220345616dc96fe17373542b0e0479cd49c760f894b3c8b2b9a7d1bee1b52(
    *,
    path: builtins.str,
    username: builtins.str,
    secret_ref: typing.Optional[typing.Union[VaultDynamicSecretSpecProviderAuthLdapSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__60bc931306020a61804834bcc79bbcf49973e8f53d58f4ea39b0ae1754711b08(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__ed41facd1379b3f85556543534fb044320dbd0b59942324205b3985c4248bd36(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__958d4e7ec13747646d6801333810ae326b34bfd2eb12c19bf05f0c3bf7d89697(
    *,
    path: builtins.str,
    username: builtins.str,
    secret_ref: typing.Optional[typing.Union[VaultDynamicSecretSpecProviderAuthUserPassSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__216849c3808d37d2df1e879ee71aff23ac155adf219272b406f534e7b6943b73(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__47aa9e507cb3a56b1071f68782774cbb97be7b7e78095f1255b6540a57b48a2e(
    *,
    name: builtins.str,
    type: VaultDynamicSecretSpecProviderCaProviderType,
    key: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__4c359e9ca0ed96202a7b48da939ccca9ad838ac2a1792e970ccc859acc513b5e(
    *,
    cert_secret_ref: typing.Optional[typing.Union[VaultDynamicSecretSpecProviderTlsCertSecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
    key_secret_ref: typing.Optional[typing.Union[VaultDynamicSecretSpecProviderTlsKeySecretRef, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__599cbaf122859dd7f009e3ed451c225503a46650ac59351333ec8c7e1ebdbeae(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__bc5c0e299295a5a887aeb0ffd3b0c7b44ddedc0ba8c0a2218c5f3b3b4b61d977(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__6ea2dadc111afddae5d1419fecc4fe0206d457921fd2b0454f3c8d16596207f4(
    *,
    max_retries: typing.Optional[jsii.Number] = None,
    retry_interval: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__2b3398300afa4aac17177a7f5a19102c6ef4c1f09f44bd175a63555207914180(
    scope: _constructs_77d1e7e8.Construct,
    id: builtins.str,
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Optional[typing.Union[WebhookSpec, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__0b254d63d89ea234a5552305205259b657fc7bdae3ce04b66e322f35dde31921(
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Optional[typing.Union[WebhookSpec, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__6ef020d87c0708a88abf8b30977911e976ff092427549278c6ce74edd91575ec(
    *,
    result: typing.Union[WebhookSpecResult, typing.Dict[builtins.str, typing.Any]],
    url: builtins.str,
    auth: typing.Optional[typing.Union[WebhookSpecAuth, typing.Dict[builtins.str, typing.Any]]] = None,
    body: typing.Optional[builtins.str] = None,
    ca_bundle: typing.Optional[builtins.str] = None,
    ca_provider: typing.Optional[typing.Union[WebhookSpecCaProvider, typing.Dict[builtins.str, typing.Any]]] = None,
    headers: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    method: typing.Optional[builtins.str] = None,
    secrets: typing.Optional[typing.Sequence[typing.Union[WebhookSpecSecrets, typing.Dict[builtins.str, typing.Any]]]] = None,
    timeout: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__78defe8d10b15821216ddfd3f988c664963f350cdd10aa5c48a1c5a5734905a6(
    *,
    ntlm: typing.Optional[typing.Union[WebhookSpecAuthNtlm, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__54f272261eb357770cbc8bfec20f2a259f0d7047b325a6c635ab4acecc21d863(
    *,
    password_secret: typing.Union[WebhookSpecAuthNtlmPasswordSecret, typing.Dict[builtins.str, typing.Any]],
    username_secret: typing.Union[WebhookSpecAuthNtlmUsernameSecret, typing.Dict[builtins.str, typing.Any]],
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__2deaaac4bc9b8850bb1260ca7fc7e46f31d6a7fd0b83be30603d96939c1a744c(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__c7a59ddd5e3704e4ca2730280bf8bd48570c20f65dafe99041e6a266f16c3e1a(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__90b741732fca9bf2aae7312269add8c4a03df33524d5574edd943d60f2b4f152(
    *,
    name: builtins.str,
    type: WebhookSpecCaProviderType,
    key: typing.Optional[builtins.str] = None,
    namespace: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__ca17a0cafac72c20c4b5371c2a40624b79067e28976caaef7d455a3af73b33b7(
    *,
    json_path: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__f6c624ae8cdb02a080db2665a395b8aab26b2f157404c3891b4e3195fc8dfc4a(
    *,
    name: builtins.str,
    secret_ref: typing.Union[WebhookSpecSecretsSecretRef, typing.Dict[builtins.str, typing.Any]],
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__da7206ccc0e7cc05ae6cece8b22e90df4f71703b449edd6dfd8a06e7de96daf9(
    *,
    key: typing.Optional[builtins.str] = None,
    name: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass
