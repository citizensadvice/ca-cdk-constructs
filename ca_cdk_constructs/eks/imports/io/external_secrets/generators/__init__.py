import abc
import builtins
import datetime
import enum
import typing

import jsii
import publication
import typing_extensions

from typeguard import check_type

from ._jsii import *

import cdk8s as _cdk8s_d3d9af27
import constructs as _constructs_77d1e7e8


class AcrAccessToken(
    _cdk8s_d3d9af27.ApiObject,
    metaclass=jsii.JSIIMeta,
    jsii_type="ioexternal-secretsgenerators.AcrAccessToken",
):
    '''ACRAccessToken returns a Azure Container Registry token that can be used for pushing/pulling images.

    Note: by default it will return an ACR Refresh Token with full access (depending on the identity). This can be scoped down to the repository level using .spec.scope. In case scope is defined it will return an ACR Access Token.
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
        '''ACRAccessToken returns a Azure Container Registry token that can be used for pushing/pulling images.

        Note: by default it will return an ACR Refresh Token with full access (depending on the identity). This can be scoped down to the repository level using .spec.scope. In case scope is defined it will return an ACR Access Token.
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
        :param scope: Define the scope for the access token, e.g. pull/push access for a repository. if not provided it will return a refresh token that has full scope. Note: you need to pin it down to the repository level, there is no wildcard available. examples: repository:my-repository:pull,push repository:my-repository:pull see docs for details: https://docs.docker.com/registry/spec/auth/scope/.
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

        By default it points to the public cloud AAD endpoint. The following endpoints are available, also see here: https://github.com/Azure/go-autorest/blob/main/autorest/azure/environments.go#L152 PublicCloud, USGovernmentCloud, ChinaCloud, GermanCloud

        :schema: AcrAccessTokenSpec#environmentType
        '''
        result = self._values.get("environment_type")
        return typing.cast(typing.Optional["AcrAccessTokenSpecEnvironmentType"], result)

    @builtins.property
    def scope(self) -> typing.Optional[builtins.str]:
        '''Define the scope for the access token, e.g. pull/push access for a repository. if not provided it will return a refresh token that has full scope. Note: you need to pin it down to the repository level, there is no wildcard available. examples: repository:my-repository:pull,push repository:my-repository:pull see docs for details: https://docs.docker.com/registry/spec/auth/scope/.

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

        :param key: The key of the entry in the Secret resource's ``data`` field to be used. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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
        '''The key of the entry in the Secret resource's ``data`` field to be used.

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
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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

        :param key: The key of the entry in the Secret resource's ``data`` field to be used. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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
        '''The key of the entry in the Secret resource's ``data`` field to be used.

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
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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

        Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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

    By default it points to the public cloud AAD endpoint. The following endpoints are available, also see here: https://github.com/Azure/go-autorest/blob/main/autorest/azure/environments.go#L152 PublicCloud, USGovernmentCloud, ChinaCloud, GermanCloud

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


class EcrAuthorizationToken(
    _cdk8s_d3d9af27.ApiObject,
    metaclass=jsii.JSIIMeta,
    jsii_type="ioexternal-secretsgenerators.EcrAuthorizationToken",
):
    '''ECRAuthorizationTokenSpec uses the GetAuthorizationToken API to retrieve an authorization token.

    The authorization token is valid for 12 hours. The authorizationToken returned is a base64 encoded string that can be decoded and used in a docker login command to authenticate to a registry. For more information, see Registry authentication (https://docs.aws.amazon.com/AmazonECR/latest/userguide/Registries.html#registry_auth) in the Amazon Elastic Container Registry User Guide.

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

        The authorization token is valid for 12 hours. The authorizationToken returned is a base64 encoded string that can be decoded and used in a docker login command to authenticate to a registry. For more information, see Registry authentication (https://docs.aws.amazon.com/AmazonECR/latest/userguide/Registries.html#registry_auth) in the Amazon Elastic Container Registry User Guide.

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
    name_mapping={"region": "region", "auth": "auth", "role": "role"},
)
class EcrAuthorizationTokenSpec:
    def __init__(
        self,
        *,
        region: builtins.str,
        auth: typing.Optional[typing.Union["EcrAuthorizationTokenSpecAuth", typing.Dict[builtins.str, typing.Any]]] = None,
        role: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param region: Region specifies the region to operate in.
        :param auth: Auth defines how to authenticate with AWS.
        :param role: You can assume a role before making calls to the desired AWS service.

        :schema: EcrAuthorizationTokenSpec
        '''
        if isinstance(auth, dict):
            auth = EcrAuthorizationTokenSpecAuth(**auth)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__324512f7d0f8d8b457280dd1e15f21985b97b88f08bab8a4ee40bca0e64ea7f6)
            check_type(argname="argument region", value=region, expected_type=type_hints["region"])
            check_type(argname="argument auth", value=auth, expected_type=type_hints["auth"])
            check_type(argname="argument role", value=role, expected_type=type_hints["role"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "region": region,
        }
        if auth is not None:
            self._values["auth"] = auth
        if role is not None:
            self._values["role"] = role

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
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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

        Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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

        :param key: The key of the entry in the Secret resource's ``data`` field to be used. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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
        '''The key of the entry in the Secret resource's ``data`` field to be used.

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
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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

        :param key: The key of the entry in the Secret resource's ``data`` field to be used. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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
        '''The key of the entry in the Secret resource's ``data`` field to be used.

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
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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

        :param key: The key of the entry in the Secret resource's ``data`` field to be used. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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
        '''The key of the entry in the Secret resource's ``data`` field to be used.

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
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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

    It lets you define a static set of credentials that is always returned.

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

        It lets you define a static set of credentials that is always returned.

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

        :param key: The key of the entry in the Secret resource's ``data`` field to be used. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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
        '''The key of the entry in the Secret resource's ``data`` field to be used.

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
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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

        Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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
        "controller": "controller",
        "method": "method",
        "parameters": "parameters",
        "result_type": "resultType",
    },
)
class VaultDynamicSecretSpec:
    def __init__(
        self,
        *,
        path: builtins.str,
        provider: typing.Union["VaultDynamicSecretSpecProvider", typing.Dict[builtins.str, typing.Any]],
        controller: typing.Optional[builtins.str] = None,
        method: typing.Optional[builtins.str] = None,
        parameters: typing.Any = None,
        result_type: typing.Optional["VaultDynamicSecretSpecResultType"] = None,
    ) -> None:
        '''
        :param path: Vault path to obtain the dynamic secret from.
        :param provider: Vault provider common spec.
        :param controller: Used to select the correct ESO controller (think: ingress.ingressClassName) The ESO controller is instantiated with a specific controller name and filters VDS based on this property.
        :param method: Vault API method to use (GET/POST/other).
        :param parameters: Parameters to pass to Vault write (for non-GET methods).
        :param result_type: Result type defines which data is returned from the generator. By default it is the "data" section of the Vault API response. When using e.g. /auth/token/create the "data" section is empty but the "auth" section contains the generated token. Please refer to the vault docs regarding the result data structure.

        :schema: VaultDynamicSecretSpec
        '''
        if isinstance(provider, dict):
            provider = VaultDynamicSecretSpecProvider(**provider)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__c88f3beb5eebe3642bd7625e948d35a224c53cc7572853ef902f398263266288)
            check_type(argname="argument path", value=path, expected_type=type_hints["path"])
            check_type(argname="argument provider", value=provider, expected_type=type_hints["provider"])
            check_type(argname="argument controller", value=controller, expected_type=type_hints["controller"])
            check_type(argname="argument method", value=method, expected_type=type_hints["method"])
            check_type(argname="argument parameters", value=parameters, expected_type=type_hints["parameters"])
            check_type(argname="argument result_type", value=result_type, expected_type=type_hints["result_type"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "path": path,
            "provider": provider,
        }
        if controller is not None:
            self._values["controller"] = controller
        if method is not None:
            self._values["method"] = method
        if parameters is not None:
            self._values["parameters"] = parameters
        if result_type is not None:
            self._values["result_type"] = result_type

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

        By default it is the "data" section of the Vault API response. When using e.g. /auth/token/create the "data" section is empty but the "auth" section contains the generated token. Please refer to the vault docs regarding the result data structure.

        :schema: VaultDynamicSecretSpec#resultType
        '''
        result = self._values.get("result_type")
        return typing.cast(typing.Optional["VaultDynamicSecretSpecResultType"], result)

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
        "auth": "auth",
        "server": "server",
        "ca_bundle": "caBundle",
        "ca_provider": "caProvider",
        "forward_inconsistent": "forwardInconsistent",
        "namespace": "namespace",
        "path": "path",
        "read_your_writes": "readYourWrites",
        "version": "version",
    },
)
class VaultDynamicSecretSpecProvider:
    def __init__(
        self,
        *,
        auth: typing.Union["VaultDynamicSecretSpecProviderAuth", typing.Dict[builtins.str, typing.Any]],
        server: builtins.str,
        ca_bundle: typing.Optional[builtins.str] = None,
        ca_provider: typing.Optional[typing.Union["VaultDynamicSecretSpecProviderCaProvider", typing.Dict[builtins.str, typing.Any]]] = None,
        forward_inconsistent: typing.Optional[builtins.bool] = None,
        namespace: typing.Optional[builtins.str] = None,
        path: typing.Optional[builtins.str] = None,
        read_your_writes: typing.Optional[builtins.bool] = None,
        version: typing.Optional["VaultDynamicSecretSpecProviderVersion"] = None,
    ) -> None:
        '''Vault provider common spec.

        :param auth: Auth configures how secret-manager authenticates with the Vault server.
        :param server: Server is the connection address for the Vault server, e.g: "https://vault.example.com:8200".
        :param ca_bundle: PEM encoded CA bundle used to validate Vault server certificate. Only used if the Server URL is using HTTPS protocol. This parameter is ignored for plain HTTP protocol connection. If not set the system root certificates are used to validate the TLS connection.
        :param ca_provider: The provider for the CA bundle to use to validate Vault server certificate.
        :param forward_inconsistent: ForwardInconsistent tells Vault to forward read-after-write requests to the Vault leader instead of simply retrying within a loop. This can increase performance if the option is enabled serverside. https://www.vaultproject.io/docs/configuration/replication#allow_forwarding_via_header
        :param namespace: Name of the vault namespace. Namespaces is a set of features within Vault Enterprise that allows Vault environments to support Secure Multi-tenancy. e.g: "ns1". More about namespaces can be found here https://www.vaultproject.io/docs/enterprise/namespaces
        :param path: Path is the mount path of the Vault KV backend endpoint, e.g: "secret". The v2 KV secret engine version specific "/data" path suffix for fetching secrets from Vault is optional and will be appended if not present in specified path.
        :param read_your_writes: ReadYourWrites ensures isolated read-after-write semantics by providing discovered cluster replication states in each request. More information about eventual consistency in Vault can be found here https://www.vaultproject.io/docs/enterprise/consistency
        :param version: Version is the Vault KV secret engine version. This can be either "v1" or "v2". Version defaults to "v2".

        :schema: VaultDynamicSecretSpecProvider
        '''
        if isinstance(auth, dict):
            auth = VaultDynamicSecretSpecProviderAuth(**auth)
        if isinstance(ca_provider, dict):
            ca_provider = VaultDynamicSecretSpecProviderCaProvider(**ca_provider)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__99bb9f6b265462d6cb37ae7c7ac1a897af8d4eca0e046b25280a6a5eb0ddf60a)
            check_type(argname="argument auth", value=auth, expected_type=type_hints["auth"])
            check_type(argname="argument server", value=server, expected_type=type_hints["server"])
            check_type(argname="argument ca_bundle", value=ca_bundle, expected_type=type_hints["ca_bundle"])
            check_type(argname="argument ca_provider", value=ca_provider, expected_type=type_hints["ca_provider"])
            check_type(argname="argument forward_inconsistent", value=forward_inconsistent, expected_type=type_hints["forward_inconsistent"])
            check_type(argname="argument namespace", value=namespace, expected_type=type_hints["namespace"])
            check_type(argname="argument path", value=path, expected_type=type_hints["path"])
            check_type(argname="argument read_your_writes", value=read_your_writes, expected_type=type_hints["read_your_writes"])
            check_type(argname="argument version", value=version, expected_type=type_hints["version"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "auth": auth,
            "server": server,
        }
        if ca_bundle is not None:
            self._values["ca_bundle"] = ca_bundle
        if ca_provider is not None:
            self._values["ca_provider"] = ca_provider
        if forward_inconsistent is not None:
            self._values["forward_inconsistent"] = forward_inconsistent
        if namespace is not None:
            self._values["namespace"] = namespace
        if path is not None:
            self._values["path"] = path
        if read_your_writes is not None:
            self._values["read_your_writes"] = read_your_writes
        if version is not None:
            self._values["version"] = version

    @builtins.property
    def auth(self) -> "VaultDynamicSecretSpecProviderAuth":
        '''Auth configures how secret-manager authenticates with the Vault server.

        :schema: VaultDynamicSecretSpecProvider#auth
        '''
        result = self._values.get("auth")
        assert result is not None, "Required property 'auth' is missing"
        return typing.cast("VaultDynamicSecretSpecProviderAuth", result)

    @builtins.property
    def server(self) -> builtins.str:
        '''Server is the connection address for the Vault server, e.g: "https://vault.example.com:8200".

        :schema: VaultDynamicSecretSpecProvider#server
        '''
        result = self._values.get("server")
        assert result is not None, "Required property 'server' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def ca_bundle(self) -> typing.Optional[builtins.str]:
        '''PEM encoded CA bundle used to validate Vault server certificate.

        Only used if the Server URL is using HTTPS protocol. This parameter is ignored for plain HTTP protocol connection. If not set the system root certificates are used to validate the TLS connection.

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

        This can increase performance if the option is enabled serverside. https://www.vaultproject.io/docs/configuration/replication#allow_forwarding_via_header

        :schema: VaultDynamicSecretSpecProvider#forwardInconsistent
        '''
        result = self._values.get("forward_inconsistent")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''Name of the vault namespace.

        Namespaces is a set of features within Vault Enterprise that allows Vault environments to support Secure Multi-tenancy. e.g: "ns1". More about namespaces can be found here https://www.vaultproject.io/docs/enterprise/namespaces

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

        More information about eventual consistency in Vault can be found here https://www.vaultproject.io/docs/enterprise/consistency

        :schema: VaultDynamicSecretSpecProvider#readYourWrites
        '''
        result = self._values.get("read_your_writes")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def version(self) -> typing.Optional["VaultDynamicSecretSpecProviderVersion"]:
        '''Version is the Vault KV secret engine version.

        This can be either "v1" or "v2". Version defaults to "v2".

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

        The ``key`` field must be specified and denotes which entry within the Secret resource is used as the app role secret.

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

        The ``key`` field must be specified and denotes which entry within the Secret resource is used as the app role id.

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

        The ``key`` field must be specified and denotes which entry within the Secret resource is used as the app role id.

        :param key: The key of the entry in the Secret resource's ``data`` field to be used. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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
        '''The key of the entry in the Secret resource's ``data`` field to be used.

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
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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

        The ``key`` field must be specified and denotes which entry within the Secret resource is used as the app role secret.

        :param key: The key of the entry in the Secret resource's ``data`` field to be used. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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
        '''The key of the entry in the Secret resource's ``data`` field to be used.

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
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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

        :param key: The key of the entry in the Secret resource's ``data`` field to be used. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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
        '''The key of the entry in the Secret resource's ``data`` field to be used.

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
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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

        :param key: The key of the entry in the Secret resource's ``data`` field to be used. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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
        '''The key of the entry in the Secret resource's ``data`` field to be used.

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
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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

        Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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

        :param key: The key of the entry in the Secret resource's ``data`` field to be used. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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
        '''The key of the entry in the Secret resource's ``data`` field to be used.

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
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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

        :param key: The key of the entry in the Secret resource's ``data`` field to be used. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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
        '''The key of the entry in the Secret resource's ``data`` field to be used.

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
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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

        :param key: The key of the entry in the Secret resource's ``data`` field to be used. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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
        '''The key of the entry in the Secret resource's ``data`` field to be used.

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
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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
        :param audiences: Optional audiences field that will be used to request a temporary Kubernetes service account token for the service account referenced by ``serviceAccountRef``. Defaults to a single audience ``vault`` it not specified. Deprecated: use serviceAccountRef.Audiences instead Default: a single audience ``vault`` it not specified. Deprecated: use serviceAccountRef.Audiences instead
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

        Defaults to a single audience ``vault`` it not specified. Deprecated: use serviceAccountRef.Audiences instead

        :default: a single audience ``vault`` it not specified. Deprecated: use serviceAccountRef.Audiences instead

        :schema: VaultDynamicSecretSpecProviderAuthJwtKubernetesServiceAccountToken#audiences
        '''
        result = self._values.get("audiences")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def expiration_seconds(self) -> typing.Optional[jsii.Number]:
        '''Optional expiration time in seconds that will be used to request a temporary Kubernetes service account token for the service account referenced by ``serviceAccountRef``.

        Deprecated: this will be removed in the future. Defaults to 10 minutes.

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
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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

        Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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

        :param key: The key of the entry in the Secret resource's ``data`` field to be used. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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
        '''The key of the entry in the Secret resource's ``data`` field to be used.

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
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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

        A Role binds a Kubernetes ServiceAccount with a set of Vault policies.

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

        If a name is specified without a key, ``token`` is the default. If one is not specified, the one bound to the controller will be used.

        :schema: VaultDynamicSecretSpecProviderAuthKubernetes#secretRef
        '''
        result = self._values.get("secret_ref")
        return typing.cast(typing.Optional["VaultDynamicSecretSpecProviderAuthKubernetesSecretRef"], result)

    @builtins.property
    def service_account_ref(
        self,
    ) -> typing.Optional["VaultDynamicSecretSpecProviderAuthKubernetesServiceAccountRef"]:
        '''Optional service account field containing the name of a kubernetes ServiceAccount.

        If the service account is specified, the service account secret token JWT will be used for authenticating with Vault. If the service account selector is not supplied, the secretRef will be used instead.

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

        If a name is specified without a key, ``token`` is the default. If one is not specified, the one bound to the controller will be used.

        :param key: The key of the entry in the Secret resource's ``data`` field to be used. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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
        '''The key of the entry in the Secret resource's ``data`` field to be used.

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
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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

        If the service account is specified, the service account secret token JWT will be used for authenticating with Vault. If the service account selector is not supplied, the secretRef will be used instead.

        :param name: The name of the ServiceAccount resource being referred to.
        :param audiences: Audience specifies the ``aud`` claim for the service account token If the service account uses a well-known annotation for e.g. IRSA or GCP Workload Identity then this audiences will be appended to the list.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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

        Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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
        :param username: Username is a LDAP user name used to authenticate using the LDAP Vault authentication method.
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
        '''Username is a LDAP user name used to authenticate using the LDAP Vault authentication method.

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

        :param key: The key of the entry in the Secret resource's ``data`` field to be used. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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
        '''The key of the entry in the Secret resource's ``data`` field to be used.

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
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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

        :param key: The key of the entry in the Secret resource's ``data`` field to be used. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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
        '''The key of the entry in the Secret resource's ``data`` field to be used.

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
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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

        :param path: Path where the UserPassword authentication backend is mounted in Vault, e.g: "user".
        :param username: Username is a user name used to authenticate using the UserPass Vault authentication method.
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
        '''Path where the UserPassword authentication backend is mounted in Vault, e.g: "user".

        :schema: VaultDynamicSecretSpecProviderAuthUserPass#path
        '''
        result = self._values.get("path")
        assert result is not None, "Required property 'path' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def username(self) -> builtins.str:
        '''Username is a user name used to authenticate using the UserPass Vault authentication method.

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

        :param key: The key of the entry in the Secret resource's ``data`` field to be used. Some instances of this field may be defaulted, in others it may be required.
        :param name: The name of the Secret resource being referred to.
        :param namespace: Namespace of the resource being referred to. Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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
        '''The key of the entry in the Secret resource's ``data`` field to be used.

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
        '''Namespace of the resource being referred to.

        Ignored if referent is not cluster-scoped. cluster-scoped defaults to the namespace of the referent.

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


@jsii.enum(
    jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecProviderVersion"
)
class VaultDynamicSecretSpecProviderVersion(enum.Enum):
    '''Version is the Vault KV secret engine version.

    This can be either "v1" or "v2". Version defaults to "v2".

    :schema: VaultDynamicSecretSpecProviderVersion
    '''

    V1 = "V1"
    '''v1.'''
    V2 = "V2"
    '''v2.'''


@jsii.enum(jsii_type="ioexternal-secretsgenerators.VaultDynamicSecretSpecResultType")
class VaultDynamicSecretSpecResultType(enum.Enum):
    '''Result type defines which data is returned from the generator.

    By default it is the "data" section of the Vault API response. When using e.g. /auth/token/create the "data" section is empty but the "auth" section contains the generated token. Please refer to the vault docs regarding the result data structure.

    :schema: VaultDynamicSecretSpecResultType
    '''

    DATA = "DATA"
    '''Data.'''
    AUTH = "AUTH"
    '''Auth.'''


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
    "Password",
    "PasswordProps",
    "PasswordSpec",
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
    "VaultDynamicSecretSpecProviderVersion",
    "VaultDynamicSecretSpecResultType",
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
    controller: typing.Optional[builtins.str] = None,
    method: typing.Optional[builtins.str] = None,
    parameters: typing.Any = None,
    result_type: typing.Optional[VaultDynamicSecretSpecResultType] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__99bb9f6b265462d6cb37ae7c7ac1a897af8d4eca0e046b25280a6a5eb0ddf60a(
    *,
    auth: typing.Union[VaultDynamicSecretSpecProviderAuth, typing.Dict[builtins.str, typing.Any]],
    server: builtins.str,
    ca_bundle: typing.Optional[builtins.str] = None,
    ca_provider: typing.Optional[typing.Union[VaultDynamicSecretSpecProviderCaProvider, typing.Dict[builtins.str, typing.Any]]] = None,
    forward_inconsistent: typing.Optional[builtins.bool] = None,
    namespace: typing.Optional[builtins.str] = None,
    path: typing.Optional[builtins.str] = None,
    read_your_writes: typing.Optional[builtins.bool] = None,
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
