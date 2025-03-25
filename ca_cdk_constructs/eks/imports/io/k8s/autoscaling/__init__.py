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


class VerticalPodAutoscaler(
    _cdk8s_d3d9af27.ApiObject,
    metaclass=jsii.JSIIMeta,
    jsii_type="iok8sautoscaling.VerticalPodAutoscaler",
):
    '''
    :schema: VerticalPodAutoscaler
    '''

    def __init__(
        self,
        scope: _constructs_77d1e7e8.Construct,
        id: builtins.str,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["VerticalPodAutoscalerSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Defines a "VerticalPodAutoscaler" API object.

        :param scope: the scope in which to define this object.
        :param id: a scope-local name for the object.
        :param metadata: 
        :param spec: 
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__caf59d86d285ee6685b1508c4068ea959df4364adaf893cf0bdee63cda7bf602)
            check_type(argname="argument scope", value=scope, expected_type=type_hints["scope"])
            check_type(argname="argument id", value=id, expected_type=type_hints["id"])
        props = VerticalPodAutoscalerProps(metadata=metadata, spec=spec)

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="manifest")
    @builtins.classmethod
    def manifest(
        cls,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["VerticalPodAutoscalerSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> typing.Any:
        '''Renders a Kubernetes manifest for "VerticalPodAutoscaler".

        This can be used to inline resource manifests inside other objects (e.g. as templates).

        :param metadata: 
        :param spec: 
        '''
        props = VerticalPodAutoscalerProps(metadata=metadata, spec=spec)

        return typing.cast(typing.Any, jsii.sinvoke(cls, "manifest", [props]))

    @jsii.member(jsii_name="toJson")
    def to_json(self) -> typing.Any:
        '''Renders the object to Kubernetes JSON.'''
        return typing.cast(typing.Any, jsii.invoke(self, "toJson", []))

    @jsii.python.classproperty
    @jsii.member(jsii_name="GVK")
    def GVK(cls) -> _cdk8s_d3d9af27.GroupVersionKind:
        '''Returns the apiVersion and kind for "VerticalPodAutoscaler".'''
        return typing.cast(_cdk8s_d3d9af27.GroupVersionKind, jsii.sget(cls, "GVK"))


class VerticalPodAutoscalerCheckpoint(
    _cdk8s_d3d9af27.ApiObject,
    metaclass=jsii.JSIIMeta,
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerCheckpoint",
):
    '''
    :schema: VerticalPodAutoscalerCheckpoint
    '''

    def __init__(
        self,
        scope: _constructs_77d1e7e8.Construct,
        id: builtins.str,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Defines a "VerticalPodAutoscalerCheckpoint" API object.

        :param scope: the scope in which to define this object.
        :param id: a scope-local name for the object.
        :param metadata: 
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__417daf29a0414735a3caff5a1262960997e0629f4d3672d94cc5030c1035a633)
            check_type(argname="argument scope", value=scope, expected_type=type_hints["scope"])
            check_type(argname="argument id", value=id, expected_type=type_hints["id"])
        props = VerticalPodAutoscalerCheckpointProps(metadata=metadata)

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="manifest")
    @builtins.classmethod
    def manifest(
        cls,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> typing.Any:
        '''Renders a Kubernetes manifest for "VerticalPodAutoscalerCheckpoint".

        This can be used to inline resource manifests inside other objects (e.g. as templates).

        :param metadata: 
        '''
        props = VerticalPodAutoscalerCheckpointProps(metadata=metadata)

        return typing.cast(typing.Any, jsii.sinvoke(cls, "manifest", [props]))

    @jsii.member(jsii_name="toJson")
    def to_json(self) -> typing.Any:
        '''Renders the object to Kubernetes JSON.'''
        return typing.cast(typing.Any, jsii.invoke(self, "toJson", []))

    @jsii.python.classproperty
    @jsii.member(jsii_name="GVK")
    def GVK(cls) -> _cdk8s_d3d9af27.GroupVersionKind:
        '''Returns the apiVersion and kind for "VerticalPodAutoscalerCheckpoint".'''
        return typing.cast(_cdk8s_d3d9af27.GroupVersionKind, jsii.sget(cls, "GVK"))


@jsii.data_type(
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerCheckpointProps",
    jsii_struct_bases=[],
    name_mapping={"metadata": "metadata"},
)
class VerticalPodAutoscalerCheckpointProps:
    def __init__(
        self,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''
        :param metadata: 

        :schema: VerticalPodAutoscalerCheckpoint
        '''
        if isinstance(metadata, dict):
            metadata = _cdk8s_d3d9af27.ApiObjectMetadata(**metadata)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__6c09821f0bd7acf378fc14e7d8baaad633b256459ef04fbf16edbaba8dbc367c)
            check_type(argname="argument metadata", value=metadata, expected_type=type_hints["metadata"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if metadata is not None:
            self._values["metadata"] = metadata

    @builtins.property
    def metadata(self) -> typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata]:
        '''
        :schema: VerticalPodAutoscalerCheckpoint#metadata
        '''
        result = self._values.get("metadata")
        return typing.cast(typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VerticalPodAutoscalerCheckpointProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerProps",
    jsii_struct_bases=[],
    name_mapping={"metadata": "metadata", "spec": "spec"},
)
class VerticalPodAutoscalerProps:
    def __init__(
        self,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["VerticalPodAutoscalerSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''
        :param metadata: 
        :param spec: 

        :schema: VerticalPodAutoscaler
        '''
        if isinstance(metadata, dict):
            metadata = _cdk8s_d3d9af27.ApiObjectMetadata(**metadata)
        if isinstance(spec, dict):
            spec = VerticalPodAutoscalerSpec(**spec)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__9fdd7c3f96f7a745f9e5cfc2908bb1ce7c61c78028c1c29dbd8a9b6d659de3cd)
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
        :schema: VerticalPodAutoscaler#metadata
        '''
        result = self._values.get("metadata")
        return typing.cast(typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata], result)

    @builtins.property
    def spec(self) -> typing.Optional["VerticalPodAutoscalerSpec"]:
        '''
        :schema: VerticalPodAutoscaler#spec
        '''
        result = self._values.get("spec")
        return typing.cast(typing.Optional["VerticalPodAutoscalerSpec"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VerticalPodAutoscalerProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerSpec",
    jsii_struct_bases=[],
    name_mapping={
        "resource_policy": "resourcePolicy",
        "target_ref": "targetRef",
        "update_policy": "updatePolicy",
    },
)
class VerticalPodAutoscalerSpec:
    def __init__(
        self,
        *,
        resource_policy: typing.Optional[typing.Union["VerticalPodAutoscalerSpecResourcePolicy", typing.Dict[builtins.str, typing.Any]]] = None,
        target_ref: typing.Any = None,
        update_policy: typing.Optional[typing.Union["VerticalPodAutoscalerSpecUpdatePolicy", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''
        :param resource_policy: 
        :param target_ref: 
        :param update_policy: 

        :schema: VerticalPodAutoscalerSpec
        '''
        if isinstance(resource_policy, dict):
            resource_policy = VerticalPodAutoscalerSpecResourcePolicy(**resource_policy)
        if isinstance(update_policy, dict):
            update_policy = VerticalPodAutoscalerSpecUpdatePolicy(**update_policy)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__aad6783c71127d8ab5dcca718acfc5e5ac0c4b9eac186e46f316e34aad7bf2c1)
            check_type(argname="argument resource_policy", value=resource_policy, expected_type=type_hints["resource_policy"])
            check_type(argname="argument target_ref", value=target_ref, expected_type=type_hints["target_ref"])
            check_type(argname="argument update_policy", value=update_policy, expected_type=type_hints["update_policy"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if resource_policy is not None:
            self._values["resource_policy"] = resource_policy
        if target_ref is not None:
            self._values["target_ref"] = target_ref
        if update_policy is not None:
            self._values["update_policy"] = update_policy

    @builtins.property
    def resource_policy(
        self,
    ) -> typing.Optional["VerticalPodAutoscalerSpecResourcePolicy"]:
        '''
        :schema: VerticalPodAutoscalerSpec#resourcePolicy
        '''
        result = self._values.get("resource_policy")
        return typing.cast(typing.Optional["VerticalPodAutoscalerSpecResourcePolicy"], result)

    @builtins.property
    def target_ref(self) -> typing.Any:
        '''
        :schema: VerticalPodAutoscalerSpec#targetRef
        '''
        result = self._values.get("target_ref")
        return typing.cast(typing.Any, result)

    @builtins.property
    def update_policy(self) -> typing.Optional["VerticalPodAutoscalerSpecUpdatePolicy"]:
        '''
        :schema: VerticalPodAutoscalerSpec#updatePolicy
        '''
        result = self._values.get("update_policy")
        return typing.cast(typing.Optional["VerticalPodAutoscalerSpecUpdatePolicy"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VerticalPodAutoscalerSpec(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerSpecResourcePolicy",
    jsii_struct_bases=[],
    name_mapping={"container_policies": "containerPolicies"},
)
class VerticalPodAutoscalerSpecResourcePolicy:
    def __init__(
        self,
        *,
        container_policies: typing.Optional[typing.Sequence[typing.Union["VerticalPodAutoscalerSpecResourcePolicyContainerPolicies", typing.Dict[builtins.str, typing.Any]]]] = None,
    ) -> None:
        '''
        :param container_policies: 

        :schema: VerticalPodAutoscalerSpecResourcePolicy
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__d666228e8864efcd5ac2ea04f382409466aa693b59fd9f519c6436b7051bd6f5)
            check_type(argname="argument container_policies", value=container_policies, expected_type=type_hints["container_policies"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if container_policies is not None:
            self._values["container_policies"] = container_policies

    @builtins.property
    def container_policies(
        self,
    ) -> typing.Optional[typing.List["VerticalPodAutoscalerSpecResourcePolicyContainerPolicies"]]:
        '''
        :schema: VerticalPodAutoscalerSpecResourcePolicy#containerPolicies
        '''
        result = self._values.get("container_policies")
        return typing.cast(typing.Optional[typing.List["VerticalPodAutoscalerSpecResourcePolicyContainerPolicies"]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VerticalPodAutoscalerSpecResourcePolicy(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerSpecResourcePolicyContainerPolicies",
    jsii_struct_bases=[],
    name_mapping={
        "container_name": "containerName",
        "controlled_resources": "controlledResources",
        "controlled_values": "controlledValues",
        "max_allowed": "maxAllowed",
        "min_allowed": "minAllowed",
        "mode": "mode",
    },
)
class VerticalPodAutoscalerSpecResourcePolicyContainerPolicies:
    def __init__(
        self,
        *,
        container_name: typing.Optional[builtins.str] = None,
        controlled_resources: typing.Optional[typing.Sequence["VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesControlledResources"]] = None,
        controlled_values: typing.Optional["VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesControlledValues"] = None,
        max_allowed: typing.Any = None,
        min_allowed: typing.Any = None,
        mode: typing.Optional["VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMode"] = None,
    ) -> None:
        '''
        :param container_name: 
        :param controlled_resources: 
        :param controlled_values: 
        :param max_allowed: 
        :param min_allowed: 
        :param mode: 

        :schema: VerticalPodAutoscalerSpecResourcePolicyContainerPolicies
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__20e39dd603c99d3d3deb05326547159fd6fe9e3b7008f5a98634351e64953eb1)
            check_type(argname="argument container_name", value=container_name, expected_type=type_hints["container_name"])
            check_type(argname="argument controlled_resources", value=controlled_resources, expected_type=type_hints["controlled_resources"])
            check_type(argname="argument controlled_values", value=controlled_values, expected_type=type_hints["controlled_values"])
            check_type(argname="argument max_allowed", value=max_allowed, expected_type=type_hints["max_allowed"])
            check_type(argname="argument min_allowed", value=min_allowed, expected_type=type_hints["min_allowed"])
            check_type(argname="argument mode", value=mode, expected_type=type_hints["mode"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if container_name is not None:
            self._values["container_name"] = container_name
        if controlled_resources is not None:
            self._values["controlled_resources"] = controlled_resources
        if controlled_values is not None:
            self._values["controlled_values"] = controlled_values
        if max_allowed is not None:
            self._values["max_allowed"] = max_allowed
        if min_allowed is not None:
            self._values["min_allowed"] = min_allowed
        if mode is not None:
            self._values["mode"] = mode

    @builtins.property
    def container_name(self) -> typing.Optional[builtins.str]:
        '''
        :schema: VerticalPodAutoscalerSpecResourcePolicyContainerPolicies#containerName
        '''
        result = self._values.get("container_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def controlled_resources(
        self,
    ) -> typing.Optional[typing.List["VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesControlledResources"]]:
        '''
        :schema: VerticalPodAutoscalerSpecResourcePolicyContainerPolicies#controlledResources
        '''
        result = self._values.get("controlled_resources")
        return typing.cast(typing.Optional[typing.List["VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesControlledResources"]], result)

    @builtins.property
    def controlled_values(
        self,
    ) -> typing.Optional["VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesControlledValues"]:
        '''
        :schema: VerticalPodAutoscalerSpecResourcePolicyContainerPolicies#controlledValues
        '''
        result = self._values.get("controlled_values")
        return typing.cast(typing.Optional["VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesControlledValues"], result)

    @builtins.property
    def max_allowed(self) -> typing.Any:
        '''
        :schema: VerticalPodAutoscalerSpecResourcePolicyContainerPolicies#maxAllowed
        '''
        result = self._values.get("max_allowed")
        return typing.cast(typing.Any, result)

    @builtins.property
    def min_allowed(self) -> typing.Any:
        '''
        :schema: VerticalPodAutoscalerSpecResourcePolicyContainerPolicies#minAllowed
        '''
        result = self._values.get("min_allowed")
        return typing.cast(typing.Any, result)

    @builtins.property
    def mode(
        self,
    ) -> typing.Optional["VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMode"]:
        '''
        :schema: VerticalPodAutoscalerSpecResourcePolicyContainerPolicies#mode
        '''
        result = self._values.get("mode")
        return typing.cast(typing.Optional["VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMode"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VerticalPodAutoscalerSpecResourcePolicyContainerPolicies(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesControlledResources"
)
class VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesControlledResources(
    enum.Enum,
):
    '''
    :schema: VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesControlledResources
    '''

    CPU = "CPU"
    '''cpu.'''
    MEMORY = "MEMORY"
    '''memory.'''


@jsii.enum(
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesControlledValues"
)
class VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesControlledValues(
    enum.Enum,
):
    '''
    :schema: VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesControlledValues
    '''

    REQUESTS_AND_LIMITS = "REQUESTS_AND_LIMITS"
    '''RequestsAndLimits.'''
    REQUESTS_ONLY = "REQUESTS_ONLY"
    '''RequestsOnly.'''


@jsii.enum(
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMode"
)
class VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMode(enum.Enum):
    '''
    :schema: VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMode
    '''

    AUTO = "AUTO"
    '''Auto.'''
    OFF = "OFF"
    '''Off.'''


@jsii.data_type(
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerSpecUpdatePolicy",
    jsii_struct_bases=[],
    name_mapping={"min_replicas": "minReplicas", "update_mode": "updateMode"},
)
class VerticalPodAutoscalerSpecUpdatePolicy:
    def __init__(
        self,
        *,
        min_replicas: typing.Optional[jsii.Number] = None,
        update_mode: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param min_replicas: 
        :param update_mode: 

        :schema: VerticalPodAutoscalerSpecUpdatePolicy
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__2090e51372d1722715886f39b00478aa4a1a6c5c8b06379c6ccf82ad97b6e06b)
            check_type(argname="argument min_replicas", value=min_replicas, expected_type=type_hints["min_replicas"])
            check_type(argname="argument update_mode", value=update_mode, expected_type=type_hints["update_mode"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if min_replicas is not None:
            self._values["min_replicas"] = min_replicas
        if update_mode is not None:
            self._values["update_mode"] = update_mode

    @builtins.property
    def min_replicas(self) -> typing.Optional[jsii.Number]:
        '''
        :schema: VerticalPodAutoscalerSpecUpdatePolicy#minReplicas
        '''
        result = self._values.get("min_replicas")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def update_mode(self) -> typing.Optional[builtins.str]:
        '''
        :schema: VerticalPodAutoscalerSpecUpdatePolicy#updateMode
        '''
        result = self._values.get("update_mode")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VerticalPodAutoscalerSpecUpdatePolicy(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "VerticalPodAutoscaler",
    "VerticalPodAutoscalerCheckpoint",
    "VerticalPodAutoscalerCheckpointProps",
    "VerticalPodAutoscalerProps",
    "VerticalPodAutoscalerSpec",
    "VerticalPodAutoscalerSpecResourcePolicy",
    "VerticalPodAutoscalerSpecResourcePolicyContainerPolicies",
    "VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesControlledResources",
    "VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesControlledValues",
    "VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMode",
    "VerticalPodAutoscalerSpecUpdatePolicy",
]

publication.publish()

def _typecheckingstub__caf59d86d285ee6685b1508c4068ea959df4364adaf893cf0bdee63cda7bf602(
    scope: _constructs_77d1e7e8.Construct,
    id: builtins.str,
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Optional[typing.Union[VerticalPodAutoscalerSpec, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__417daf29a0414735a3caff5a1262960997e0629f4d3672d94cc5030c1035a633(
    scope: _constructs_77d1e7e8.Construct,
    id: builtins.str,
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__6c09821f0bd7acf378fc14e7d8baaad633b256459ef04fbf16edbaba8dbc367c(
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__9fdd7c3f96f7a745f9e5cfc2908bb1ce7c61c78028c1c29dbd8a9b6d659de3cd(
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Optional[typing.Union[VerticalPodAutoscalerSpec, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__aad6783c71127d8ab5dcca718acfc5e5ac0c4b9eac186e46f316e34aad7bf2c1(
    *,
    resource_policy: typing.Optional[typing.Union[VerticalPodAutoscalerSpecResourcePolicy, typing.Dict[builtins.str, typing.Any]]] = None,
    target_ref: typing.Any = None,
    update_policy: typing.Optional[typing.Union[VerticalPodAutoscalerSpecUpdatePolicy, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__d666228e8864efcd5ac2ea04f382409466aa693b59fd9f519c6436b7051bd6f5(
    *,
    container_policies: typing.Optional[typing.Sequence[typing.Union[VerticalPodAutoscalerSpecResourcePolicyContainerPolicies, typing.Dict[builtins.str, typing.Any]]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__20e39dd603c99d3d3deb05326547159fd6fe9e3b7008f5a98634351e64953eb1(
    *,
    container_name: typing.Optional[builtins.str] = None,
    controlled_resources: typing.Optional[typing.Sequence[VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesControlledResources]] = None,
    controlled_values: typing.Optional[VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesControlledValues] = None,
    max_allowed: typing.Any = None,
    min_allowed: typing.Any = None,
    mode: typing.Optional[VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMode] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__2090e51372d1722715886f39b00478aa4a1a6c5c8b06379c6ccf82ad97b6e06b(
    *,
    min_replicas: typing.Optional[jsii.Number] = None,
    update_mode: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass
