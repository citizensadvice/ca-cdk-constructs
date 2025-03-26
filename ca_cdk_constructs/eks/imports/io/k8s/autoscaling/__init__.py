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
    '''VerticalPodAutoscaler is the configuration for a vertical pod autoscaler, which automatically manages pod resources based on historical and real time resource utilization.

    :schema: VerticalPodAutoscaler
    '''

    def __init__(
        self,
        scope: _constructs_77d1e7e8.Construct,
        id: builtins.str,
        *,
        spec: typing.Union["VerticalPodAutoscalerSpec", typing.Dict[builtins.str, typing.Any]],
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Defines a "VerticalPodAutoscaler" API object.

        :param scope: the scope in which to define this object.
        :param id: a scope-local name for the object.
        :param spec: Specification of the behavior of the autoscaler. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.
        :param metadata: 
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__caf59d86d285ee6685b1508c4068ea959df4364adaf893cf0bdee63cda7bf602)
            check_type(argname="argument scope", value=scope, expected_type=type_hints["scope"])
            check_type(argname="argument id", value=id, expected_type=type_hints["id"])
        props = VerticalPodAutoscalerProps(spec=spec, metadata=metadata)

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="manifest")
    @builtins.classmethod
    def manifest(
        cls,
        *,
        spec: typing.Union["VerticalPodAutoscalerSpec", typing.Dict[builtins.str, typing.Any]],
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> typing.Any:
        '''Renders a Kubernetes manifest for "VerticalPodAutoscaler".

        This can be used to inline resource manifests inside other objects (e.g. as templates).

        :param spec: Specification of the behavior of the autoscaler. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.
        :param metadata: 
        '''
        props = VerticalPodAutoscalerProps(spec=spec, metadata=metadata)

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
    '''VerticalPodAutoscalerCheckpoint is the checkpoint of the internal state of VPA that is used for recovery after recommender's restart.

    :schema: VerticalPodAutoscalerCheckpoint
    '''

    def __init__(
        self,
        scope: _constructs_77d1e7e8.Construct,
        id: builtins.str,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["VerticalPodAutoscalerCheckpointSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Defines a "VerticalPodAutoscalerCheckpoint" API object.

        :param scope: the scope in which to define this object.
        :param id: a scope-local name for the object.
        :param metadata: 
        :param spec: Specification of the checkpoint. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__417daf29a0414735a3caff5a1262960997e0629f4d3672d94cc5030c1035a633)
            check_type(argname="argument scope", value=scope, expected_type=type_hints["scope"])
            check_type(argname="argument id", value=id, expected_type=type_hints["id"])
        props = VerticalPodAutoscalerCheckpointProps(metadata=metadata, spec=spec)

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="manifest")
    @builtins.classmethod
    def manifest(
        cls,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["VerticalPodAutoscalerCheckpointSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> typing.Any:
        '''Renders a Kubernetes manifest for "VerticalPodAutoscalerCheckpoint".

        This can be used to inline resource manifests inside other objects (e.g. as templates).

        :param metadata: 
        :param spec: Specification of the checkpoint. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.
        '''
        props = VerticalPodAutoscalerCheckpointProps(metadata=metadata, spec=spec)

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
    name_mapping={"metadata": "metadata", "spec": "spec"},
)
class VerticalPodAutoscalerCheckpointProps:
    def __init__(
        self,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["VerticalPodAutoscalerCheckpointSpec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''VerticalPodAutoscalerCheckpoint is the checkpoint of the internal state of VPA that is used for recovery after recommender's restart.

        :param metadata: 
        :param spec: Specification of the checkpoint. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.

        :schema: VerticalPodAutoscalerCheckpoint
        '''
        if isinstance(metadata, dict):
            metadata = _cdk8s_d3d9af27.ApiObjectMetadata(**metadata)
        if isinstance(spec, dict):
            spec = VerticalPodAutoscalerCheckpointSpec(**spec)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__6c09821f0bd7acf378fc14e7d8baaad633b256459ef04fbf16edbaba8dbc367c)
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
        :schema: VerticalPodAutoscalerCheckpoint#metadata
        '''
        result = self._values.get("metadata")
        return typing.cast(typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata], result)

    @builtins.property
    def spec(self) -> typing.Optional["VerticalPodAutoscalerCheckpointSpec"]:
        '''Specification of the checkpoint.

        More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.

        :schema: VerticalPodAutoscalerCheckpoint#spec
        '''
        result = self._values.get("spec")
        return typing.cast(typing.Optional["VerticalPodAutoscalerCheckpointSpec"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VerticalPodAutoscalerCheckpointProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerCheckpointSpec",
    jsii_struct_bases=[],
    name_mapping={
        "container_name": "containerName",
        "vpa_object_name": "vpaObjectName",
    },
)
class VerticalPodAutoscalerCheckpointSpec:
    def __init__(
        self,
        *,
        container_name: typing.Optional[builtins.str] = None,
        vpa_object_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Specification of the checkpoint.

        More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.

        :param container_name: Name of the checkpointed container.
        :param vpa_object_name: Name of the VPA object that stored VerticalPodAutoscalerCheckpoint object.

        :schema: VerticalPodAutoscalerCheckpointSpec
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__4926d22a30287a53595e4c60d286da97757a94e8c82011a5a7eac45f0d5471eb)
            check_type(argname="argument container_name", value=container_name, expected_type=type_hints["container_name"])
            check_type(argname="argument vpa_object_name", value=vpa_object_name, expected_type=type_hints["vpa_object_name"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if container_name is not None:
            self._values["container_name"] = container_name
        if vpa_object_name is not None:
            self._values["vpa_object_name"] = vpa_object_name

    @builtins.property
    def container_name(self) -> typing.Optional[builtins.str]:
        '''Name of the checkpointed container.

        :schema: VerticalPodAutoscalerCheckpointSpec#containerName
        '''
        result = self._values.get("container_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def vpa_object_name(self) -> typing.Optional[builtins.str]:
        '''Name of the VPA object that stored VerticalPodAutoscalerCheckpoint object.

        :schema: VerticalPodAutoscalerCheckpointSpec#vpaObjectName
        '''
        result = self._values.get("vpa_object_name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VerticalPodAutoscalerCheckpointSpec(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class VerticalPodAutoscalerCheckpointV1Beta2(
    _cdk8s_d3d9af27.ApiObject,
    metaclass=jsii.JSIIMeta,
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerCheckpointV1Beta2",
):
    '''VerticalPodAutoscalerCheckpoint is the checkpoint of the internal state of VPA that is used for recovery after recommender's restart.

    :schema: VerticalPodAutoscalerCheckpointV1Beta2
    '''

    def __init__(
        self,
        scope: _constructs_77d1e7e8.Construct,
        id: builtins.str,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["VerticalPodAutoscalerCheckpointV1Beta2Spec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Defines a "VerticalPodAutoscalerCheckpointV1Beta2" API object.

        :param scope: the scope in which to define this object.
        :param id: a scope-local name for the object.
        :param metadata: 
        :param spec: Specification of the checkpoint. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__e965f8c6b458dc1cd77321285fce0a2d2bc53ac846b7debafdd4e084ab9d0966)
            check_type(argname="argument scope", value=scope, expected_type=type_hints["scope"])
            check_type(argname="argument id", value=id, expected_type=type_hints["id"])
        props = VerticalPodAutoscalerCheckpointV1Beta2Props(
            metadata=metadata, spec=spec
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="manifest")
    @builtins.classmethod
    def manifest(
        cls,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["VerticalPodAutoscalerCheckpointV1Beta2Spec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> typing.Any:
        '''Renders a Kubernetes manifest for "VerticalPodAutoscalerCheckpointV1Beta2".

        This can be used to inline resource manifests inside other objects (e.g. as templates).

        :param metadata: 
        :param spec: Specification of the checkpoint. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.
        '''
        props = VerticalPodAutoscalerCheckpointV1Beta2Props(
            metadata=metadata, spec=spec
        )

        return typing.cast(typing.Any, jsii.sinvoke(cls, "manifest", [props]))

    @jsii.member(jsii_name="toJson")
    def to_json(self) -> typing.Any:
        '''Renders the object to Kubernetes JSON.'''
        return typing.cast(typing.Any, jsii.invoke(self, "toJson", []))

    @jsii.python.classproperty
    @jsii.member(jsii_name="GVK")
    def GVK(cls) -> _cdk8s_d3d9af27.GroupVersionKind:
        '''Returns the apiVersion and kind for "VerticalPodAutoscalerCheckpointV1Beta2".'''
        return typing.cast(_cdk8s_d3d9af27.GroupVersionKind, jsii.sget(cls, "GVK"))


@jsii.data_type(
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerCheckpointV1Beta2Props",
    jsii_struct_bases=[],
    name_mapping={"metadata": "metadata", "spec": "spec"},
)
class VerticalPodAutoscalerCheckpointV1Beta2Props:
    def __init__(
        self,
        *,
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
        spec: typing.Optional[typing.Union["VerticalPodAutoscalerCheckpointV1Beta2Spec", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''VerticalPodAutoscalerCheckpoint is the checkpoint of the internal state of VPA that is used for recovery after recommender's restart.

        :param metadata: 
        :param spec: Specification of the checkpoint. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.

        :schema: VerticalPodAutoscalerCheckpointV1Beta2
        '''
        if isinstance(metadata, dict):
            metadata = _cdk8s_d3d9af27.ApiObjectMetadata(**metadata)
        if isinstance(spec, dict):
            spec = VerticalPodAutoscalerCheckpointV1Beta2Spec(**spec)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__a3056128a13898c38734cd5a9c41636e80201bd29082acb7843438509646ab48)
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
        :schema: VerticalPodAutoscalerCheckpointV1Beta2#metadata
        '''
        result = self._values.get("metadata")
        return typing.cast(typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata], result)

    @builtins.property
    def spec(self) -> typing.Optional["VerticalPodAutoscalerCheckpointV1Beta2Spec"]:
        '''Specification of the checkpoint.

        More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.

        :schema: VerticalPodAutoscalerCheckpointV1Beta2#spec
        '''
        result = self._values.get("spec")
        return typing.cast(typing.Optional["VerticalPodAutoscalerCheckpointV1Beta2Spec"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VerticalPodAutoscalerCheckpointV1Beta2Props(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerCheckpointV1Beta2Spec",
    jsii_struct_bases=[],
    name_mapping={
        "container_name": "containerName",
        "vpa_object_name": "vpaObjectName",
    },
)
class VerticalPodAutoscalerCheckpointV1Beta2Spec:
    def __init__(
        self,
        *,
        container_name: typing.Optional[builtins.str] = None,
        vpa_object_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Specification of the checkpoint.

        More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.

        :param container_name: Name of the checkpointed container.
        :param vpa_object_name: Name of the VPA object that stored VerticalPodAutoscalerCheckpoint object.

        :schema: VerticalPodAutoscalerCheckpointV1Beta2Spec
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__8b3f23f9542562f2c369c0a5d837e33dbbb7622ce2bcd688da1c58b93ed20a62)
            check_type(argname="argument container_name", value=container_name, expected_type=type_hints["container_name"])
            check_type(argname="argument vpa_object_name", value=vpa_object_name, expected_type=type_hints["vpa_object_name"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if container_name is not None:
            self._values["container_name"] = container_name
        if vpa_object_name is not None:
            self._values["vpa_object_name"] = vpa_object_name

    @builtins.property
    def container_name(self) -> typing.Optional[builtins.str]:
        '''Name of the checkpointed container.

        :schema: VerticalPodAutoscalerCheckpointV1Beta2Spec#containerName
        '''
        result = self._values.get("container_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def vpa_object_name(self) -> typing.Optional[builtins.str]:
        '''Name of the VPA object that stored VerticalPodAutoscalerCheckpoint object.

        :schema: VerticalPodAutoscalerCheckpointV1Beta2Spec#vpaObjectName
        '''
        result = self._values.get("vpa_object_name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VerticalPodAutoscalerCheckpointV1Beta2Spec(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerProps",
    jsii_struct_bases=[],
    name_mapping={"spec": "spec", "metadata": "metadata"},
)
class VerticalPodAutoscalerProps:
    def __init__(
        self,
        *,
        spec: typing.Union["VerticalPodAutoscalerSpec", typing.Dict[builtins.str, typing.Any]],
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''VerticalPodAutoscaler is the configuration for a vertical pod autoscaler, which automatically manages pod resources based on historical and real time resource utilization.

        :param spec: Specification of the behavior of the autoscaler. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.
        :param metadata: 

        :schema: VerticalPodAutoscaler
        '''
        if isinstance(spec, dict):
            spec = VerticalPodAutoscalerSpec(**spec)
        if isinstance(metadata, dict):
            metadata = _cdk8s_d3d9af27.ApiObjectMetadata(**metadata)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__9fdd7c3f96f7a745f9e5cfc2908bb1ce7c61c78028c1c29dbd8a9b6d659de3cd)
            check_type(argname="argument spec", value=spec, expected_type=type_hints["spec"])
            check_type(argname="argument metadata", value=metadata, expected_type=type_hints["metadata"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "spec": spec,
        }
        if metadata is not None:
            self._values["metadata"] = metadata

    @builtins.property
    def spec(self) -> "VerticalPodAutoscalerSpec":
        '''Specification of the behavior of the autoscaler.

        More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.

        :schema: VerticalPodAutoscaler#spec
        '''
        result = self._values.get("spec")
        assert result is not None, "Required property 'spec' is missing"
        return typing.cast("VerticalPodAutoscalerSpec", result)

    @builtins.property
    def metadata(self) -> typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata]:
        '''
        :schema: VerticalPodAutoscaler#metadata
        '''
        result = self._values.get("metadata")
        return typing.cast(typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata], result)

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
        "target_ref": "targetRef",
        "recommenders": "recommenders",
        "resource_policy": "resourcePolicy",
        "update_policy": "updatePolicy",
    },
)
class VerticalPodAutoscalerSpec:
    def __init__(
        self,
        *,
        target_ref: typing.Union["VerticalPodAutoscalerSpecTargetRef", typing.Dict[builtins.str, typing.Any]],
        recommenders: typing.Optional[typing.Sequence[typing.Union["VerticalPodAutoscalerSpecRecommenders", typing.Dict[builtins.str, typing.Any]]]] = None,
        resource_policy: typing.Optional[typing.Union["VerticalPodAutoscalerSpecResourcePolicy", typing.Dict[builtins.str, typing.Any]]] = None,
        update_policy: typing.Optional[typing.Union["VerticalPodAutoscalerSpecUpdatePolicy", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Specification of the behavior of the autoscaler.

        More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.

        :param target_ref: TargetRef points to the controller managing the set of pods for the autoscaler to control - e.g. Deployment, StatefulSet. VerticalPodAutoscaler can be targeted at controller implementing scale subresource (the pod set is retrieved from the controller's ScaleStatus) or some well known controllers (e.g. for DaemonSet the pod set is read from the controller's spec). If VerticalPodAutoscaler cannot use specified target it will report ConfigUnsupported condition. Note that VerticalPodAutoscaler does not require full implementation of scale subresource - it will not use it to modify the replica count. The only thing retrieved is a label selector matching pods grouped by the target resource.
        :param recommenders: Recommender responsible for generating recommendation for this object. List should be empty (then the default recommender will generate the recommendation) or contain exactly one recommender.
        :param resource_policy: Controls how the autoscaler computes recommended resources. The resource policy may be used to set constraints on the recommendations for individual containers. If any individual containers need to be excluded from getting the VPA recommendations, then it must be disabled explicitly by setting mode to "Off" under containerPolicies. If not specified, the autoscaler computes recommended resources for all containers in the pod, without additional constraints.
        :param update_policy: Describes the rules on how changes are applied to the pods. If not specified, all fields in the ``PodUpdatePolicy`` are set to their default values.

        :schema: VerticalPodAutoscalerSpec
        '''
        if isinstance(target_ref, dict):
            target_ref = VerticalPodAutoscalerSpecTargetRef(**target_ref)
        if isinstance(resource_policy, dict):
            resource_policy = VerticalPodAutoscalerSpecResourcePolicy(**resource_policy)
        if isinstance(update_policy, dict):
            update_policy = VerticalPodAutoscalerSpecUpdatePolicy(**update_policy)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__aad6783c71127d8ab5dcca718acfc5e5ac0c4b9eac186e46f316e34aad7bf2c1)
            check_type(argname="argument target_ref", value=target_ref, expected_type=type_hints["target_ref"])
            check_type(argname="argument recommenders", value=recommenders, expected_type=type_hints["recommenders"])
            check_type(argname="argument resource_policy", value=resource_policy, expected_type=type_hints["resource_policy"])
            check_type(argname="argument update_policy", value=update_policy, expected_type=type_hints["update_policy"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "target_ref": target_ref,
        }
        if recommenders is not None:
            self._values["recommenders"] = recommenders
        if resource_policy is not None:
            self._values["resource_policy"] = resource_policy
        if update_policy is not None:
            self._values["update_policy"] = update_policy

    @builtins.property
    def target_ref(self) -> "VerticalPodAutoscalerSpecTargetRef":
        '''TargetRef points to the controller managing the set of pods for the autoscaler to control - e.g. Deployment, StatefulSet. VerticalPodAutoscaler can be targeted at controller implementing scale subresource (the pod set is retrieved from the controller's ScaleStatus) or some well known controllers (e.g. for DaemonSet the pod set is read from the controller's spec). If VerticalPodAutoscaler cannot use specified target it will report ConfigUnsupported condition. Note that VerticalPodAutoscaler does not require full implementation of scale subresource - it will not use it to modify the replica count. The only thing retrieved is a label selector matching pods grouped by the target resource.

        :schema: VerticalPodAutoscalerSpec#targetRef
        '''
        result = self._values.get("target_ref")
        assert result is not None, "Required property 'target_ref' is missing"
        return typing.cast("VerticalPodAutoscalerSpecTargetRef", result)

    @builtins.property
    def recommenders(
        self,
    ) -> typing.Optional[typing.List["VerticalPodAutoscalerSpecRecommenders"]]:
        '''Recommender responsible for generating recommendation for this object.

        List should be empty (then the default recommender will generate the
        recommendation) or contain exactly one recommender.

        :schema: VerticalPodAutoscalerSpec#recommenders
        '''
        result = self._values.get("recommenders")
        return typing.cast(typing.Optional[typing.List["VerticalPodAutoscalerSpecRecommenders"]], result)

    @builtins.property
    def resource_policy(
        self,
    ) -> typing.Optional["VerticalPodAutoscalerSpecResourcePolicy"]:
        '''Controls how the autoscaler computes recommended resources.

        The resource policy may be used to set constraints on the recommendations
        for individual containers.
        If any individual containers need to be excluded from getting the VPA recommendations, then
        it must be disabled explicitly by setting mode to "Off" under containerPolicies.
        If not specified, the autoscaler computes recommended resources for all containers in the pod,
        without additional constraints.

        :schema: VerticalPodAutoscalerSpec#resourcePolicy
        '''
        result = self._values.get("resource_policy")
        return typing.cast(typing.Optional["VerticalPodAutoscalerSpecResourcePolicy"], result)

    @builtins.property
    def update_policy(self) -> typing.Optional["VerticalPodAutoscalerSpecUpdatePolicy"]:
        '''Describes the rules on how changes are applied to the pods.

        If not specified, all fields in the ``PodUpdatePolicy`` are set to their
        default values.

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
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerSpecRecommenders",
    jsii_struct_bases=[],
    name_mapping={"name": "name"},
)
class VerticalPodAutoscalerSpecRecommenders:
    def __init__(self, *, name: builtins.str) -> None:
        '''VerticalPodAutoscalerRecommenderSelector points to a specific Vertical Pod Autoscaler recommender.

        In the future it might pass parameters to the recommender.

        :param name: Name of the recommender responsible for generating recommendation for this object.

        :schema: VerticalPodAutoscalerSpecRecommenders
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__3e5198b23f37399ac14dd9bde4cc16da589345871e41914d8ae0fa2e1196edd7)
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "name": name,
        }

    @builtins.property
    def name(self) -> builtins.str:
        '''Name of the recommender responsible for generating recommendation for this object.

        :schema: VerticalPodAutoscalerSpecRecommenders#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VerticalPodAutoscalerSpecRecommenders(%s)" % ", ".join(
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
        '''Controls how the autoscaler computes recommended resources.

        The resource policy may be used to set constraints on the recommendations
        for individual containers.
        If any individual containers need to be excluded from getting the VPA recommendations, then
        it must be disabled explicitly by setting mode to "Off" under containerPolicies.
        If not specified, the autoscaler computes recommended resources for all containers in the pod,
        without additional constraints.

        :param container_policies: Per-container resource policies.

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
        '''Per-container resource policies.

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
        controlled_resources: typing.Optional[typing.Sequence[builtins.str]] = None,
        controlled_values: typing.Optional["VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesControlledValues"] = None,
        max_allowed: typing.Optional[typing.Mapping[builtins.str, "VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMaxAllowed"]] = None,
        min_allowed: typing.Optional[typing.Mapping[builtins.str, "VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMinAllowed"]] = None,
        mode: typing.Optional["VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMode"] = None,
    ) -> None:
        '''ContainerResourcePolicy controls how autoscaler computes the recommended resources for a specific container.

        :param container_name: Name of the container or DefaultContainerResourcePolicy, in which case the policy is used by the containers that don't have their own policy specified.
        :param controlled_resources: Specifies the type of recommendations that will be computed (and possibly applied) by VPA. If not specified, the default of [ResourceCPU, ResourceMemory] will be used.
        :param controlled_values: Specifies which resource values should be controlled. The default is "RequestsAndLimits".
        :param max_allowed: Specifies the maximum amount of resources that will be recommended for the container. The default is no maximum.
        :param min_allowed: Specifies the minimal amount of resources that will be recommended for the container. The default is no minimum.
        :param mode: Whether autoscaler is enabled for the container. The default is "Auto".

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
        '''Name of the container or DefaultContainerResourcePolicy, in which case the policy is used by the containers that don't have their own policy specified.

        :schema: VerticalPodAutoscalerSpecResourcePolicyContainerPolicies#containerName
        '''
        result = self._values.get("container_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def controlled_resources(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Specifies the type of recommendations that will be computed (and possibly applied) by VPA.

        If not specified, the default of [ResourceCPU, ResourceMemory] will be used.

        :schema: VerticalPodAutoscalerSpecResourcePolicyContainerPolicies#controlledResources
        '''
        result = self._values.get("controlled_resources")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def controlled_values(
        self,
    ) -> typing.Optional["VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesControlledValues"]:
        '''Specifies which resource values should be controlled.

        The default is "RequestsAndLimits".

        :schema: VerticalPodAutoscalerSpecResourcePolicyContainerPolicies#controlledValues
        '''
        result = self._values.get("controlled_values")
        return typing.cast(typing.Optional["VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesControlledValues"], result)

    @builtins.property
    def max_allowed(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, "VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMaxAllowed"]]:
        '''Specifies the maximum amount of resources that will be recommended for the container.

        The default is no maximum.

        :schema: VerticalPodAutoscalerSpecResourcePolicyContainerPolicies#maxAllowed
        '''
        result = self._values.get("max_allowed")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, "VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMaxAllowed"]], result)

    @builtins.property
    def min_allowed(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, "VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMinAllowed"]]:
        '''Specifies the minimal amount of resources that will be recommended for the container.

        The default is no minimum.

        :schema: VerticalPodAutoscalerSpecResourcePolicyContainerPolicies#minAllowed
        '''
        result = self._values.get("min_allowed")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, "VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMinAllowed"]], result)

    @builtins.property
    def mode(
        self,
    ) -> typing.Optional["VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMode"]:
        '''Whether autoscaler is enabled for the container.

        The default is "Auto".

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
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesControlledValues"
)
class VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesControlledValues(
    enum.Enum,
):
    '''Specifies which resource values should be controlled.

    The default is "RequestsAndLimits".

    :schema: VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesControlledValues
    '''

    REQUESTS_AND_LIMITS = "REQUESTS_AND_LIMITS"
    '''RequestsAndLimits.'''
    REQUESTS_ONLY = "REQUESTS_ONLY"
    '''RequestsOnly.'''


class VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMaxAllowed(
    metaclass=jsii.JSIIMeta,
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMaxAllowed",
):
    '''
    :schema: VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMaxAllowed
    '''

    @jsii.member(jsii_name="fromNumber")
    @builtins.classmethod
    def from_number(
        cls,
        value: jsii.Number,
    ) -> "VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMaxAllowed":
        '''
        :param value: -
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__5a3489df3481bf643eba8891e566a27cb7a905ce3bc7a75836f55e77cea812ce)
            check_type(argname="argument value", value=value, expected_type=type_hints["value"])
        return typing.cast("VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMaxAllowed", jsii.sinvoke(cls, "fromNumber", [value]))

    @jsii.member(jsii_name="fromString")
    @builtins.classmethod
    def from_string(
        cls,
        value: builtins.str,
    ) -> "VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMaxAllowed":
        '''
        :param value: -
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__1149315f4d028ce0f7fb1a6f25223eae226e5cacb95c987bb93237bde6b3f708)
            check_type(argname="argument value", value=value, expected_type=type_hints["value"])
        return typing.cast("VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMaxAllowed", jsii.sinvoke(cls, "fromString", [value]))

    @builtins.property
    @jsii.member(jsii_name="value")
    def value(self) -> typing.Union[builtins.str, jsii.Number]:
        return typing.cast(typing.Union[builtins.str, jsii.Number], jsii.get(self, "value"))


class VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMinAllowed(
    metaclass=jsii.JSIIMeta,
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMinAllowed",
):
    '''
    :schema: VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMinAllowed
    '''

    @jsii.member(jsii_name="fromNumber")
    @builtins.classmethod
    def from_number(
        cls,
        value: jsii.Number,
    ) -> "VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMinAllowed":
        '''
        :param value: -
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__0d73f677b6a482dbb3b55973d80ae592e9d8c000e9b9e097a4bba666ae8624ef)
            check_type(argname="argument value", value=value, expected_type=type_hints["value"])
        return typing.cast("VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMinAllowed", jsii.sinvoke(cls, "fromNumber", [value]))

    @jsii.member(jsii_name="fromString")
    @builtins.classmethod
    def from_string(
        cls,
        value: builtins.str,
    ) -> "VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMinAllowed":
        '''
        :param value: -
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__48e1ef241fc712d94bafc6720c9dbdf04454d7347d241bf8e7b39f821f87b9c6)
            check_type(argname="argument value", value=value, expected_type=type_hints["value"])
        return typing.cast("VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMinAllowed", jsii.sinvoke(cls, "fromString", [value]))

    @builtins.property
    @jsii.member(jsii_name="value")
    def value(self) -> typing.Union[builtins.str, jsii.Number]:
        return typing.cast(typing.Union[builtins.str, jsii.Number], jsii.get(self, "value"))


@jsii.enum(
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMode"
)
class VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMode(enum.Enum):
    '''Whether autoscaler is enabled for the container.

    The default is "Auto".

    :schema: VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMode
    '''

    AUTO = "AUTO"
    '''Auto.'''
    OFF = "OFF"
    '''Off.'''


@jsii.data_type(
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerSpecTargetRef",
    jsii_struct_bases=[],
    name_mapping={"kind": "kind", "name": "name", "api_version": "apiVersion"},
)
class VerticalPodAutoscalerSpecTargetRef:
    def __init__(
        self,
        *,
        kind: builtins.str,
        name: builtins.str,
        api_version: typing.Optional[builtins.str] = None,
    ) -> None:
        '''TargetRef points to the controller managing the set of pods for the autoscaler to control - e.g. Deployment, StatefulSet. VerticalPodAutoscaler can be targeted at controller implementing scale subresource (the pod set is retrieved from the controller's ScaleStatus) or some well known controllers (e.g. for DaemonSet the pod set is read from the controller's spec). If VerticalPodAutoscaler cannot use specified target it will report ConfigUnsupported condition. Note that VerticalPodAutoscaler does not require full implementation of scale subresource - it will not use it to modify the replica count. The only thing retrieved is a label selector matching pods grouped by the target resource.

        :param kind: kind is the kind of the referent; More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds
        :param name: name is the name of the referent; More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
        :param api_version: apiVersion is the API version of the referent.

        :schema: VerticalPodAutoscalerSpecTargetRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__9f7e1cdc947c495ae1aa36536adc3a83321ba4c464768bf26354e40e3055ae51)
            check_type(argname="argument kind", value=kind, expected_type=type_hints["kind"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument api_version", value=api_version, expected_type=type_hints["api_version"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "kind": kind,
            "name": name,
        }
        if api_version is not None:
            self._values["api_version"] = api_version

    @builtins.property
    def kind(self) -> builtins.str:
        '''kind is the kind of the referent;

        More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds

        :schema: VerticalPodAutoscalerSpecTargetRef#kind
        '''
        result = self._values.get("kind")
        assert result is not None, "Required property 'kind' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def name(self) -> builtins.str:
        '''name is the name of the referent;

        More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names

        :schema: VerticalPodAutoscalerSpecTargetRef#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def api_version(self) -> typing.Optional[builtins.str]:
        '''apiVersion is the API version of the referent.

        :schema: VerticalPodAutoscalerSpecTargetRef#apiVersion
        '''
        result = self._values.get("api_version")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VerticalPodAutoscalerSpecTargetRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerSpecUpdatePolicy",
    jsii_struct_bases=[],
    name_mapping={
        "eviction_requirements": "evictionRequirements",
        "min_replicas": "minReplicas",
        "update_mode": "updateMode",
    },
)
class VerticalPodAutoscalerSpecUpdatePolicy:
    def __init__(
        self,
        *,
        eviction_requirements: typing.Optional[typing.Sequence[typing.Union["VerticalPodAutoscalerSpecUpdatePolicyEvictionRequirements", typing.Dict[builtins.str, typing.Any]]]] = None,
        min_replicas: typing.Optional[jsii.Number] = None,
        update_mode: typing.Optional["VerticalPodAutoscalerSpecUpdatePolicyUpdateMode"] = None,
    ) -> None:
        '''Describes the rules on how changes are applied to the pods.

        If not specified, all fields in the ``PodUpdatePolicy`` are set to their
        default values.

        :param eviction_requirements: EvictionRequirements is a list of EvictionRequirements that need to evaluate to true in order for a Pod to be evicted. If more than one EvictionRequirement is specified, all of them need to be fulfilled to allow eviction.
        :param min_replicas: Minimal number of replicas which need to be alive for Updater to attempt pod eviction (pending other checks like PDB). Only positive values are allowed. Overrides global '--min-replicas' flag.
        :param update_mode: Controls when autoscaler applies changes to the pod resources. The default is 'Auto'.

        :schema: VerticalPodAutoscalerSpecUpdatePolicy
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__2090e51372d1722715886f39b00478aa4a1a6c5c8b06379c6ccf82ad97b6e06b)
            check_type(argname="argument eviction_requirements", value=eviction_requirements, expected_type=type_hints["eviction_requirements"])
            check_type(argname="argument min_replicas", value=min_replicas, expected_type=type_hints["min_replicas"])
            check_type(argname="argument update_mode", value=update_mode, expected_type=type_hints["update_mode"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if eviction_requirements is not None:
            self._values["eviction_requirements"] = eviction_requirements
        if min_replicas is not None:
            self._values["min_replicas"] = min_replicas
        if update_mode is not None:
            self._values["update_mode"] = update_mode

    @builtins.property
    def eviction_requirements(
        self,
    ) -> typing.Optional[typing.List["VerticalPodAutoscalerSpecUpdatePolicyEvictionRequirements"]]:
        '''EvictionRequirements is a list of EvictionRequirements that need to evaluate to true in order for a Pod to be evicted.

        If more than one
        EvictionRequirement is specified, all of them need to be fulfilled to allow eviction.

        :schema: VerticalPodAutoscalerSpecUpdatePolicy#evictionRequirements
        '''
        result = self._values.get("eviction_requirements")
        return typing.cast(typing.Optional[typing.List["VerticalPodAutoscalerSpecUpdatePolicyEvictionRequirements"]], result)

    @builtins.property
    def min_replicas(self) -> typing.Optional[jsii.Number]:
        '''Minimal number of replicas which need to be alive for Updater to attempt pod eviction (pending other checks like PDB).

        Only positive values are
        allowed. Overrides global '--min-replicas' flag.

        :schema: VerticalPodAutoscalerSpecUpdatePolicy#minReplicas
        '''
        result = self._values.get("min_replicas")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def update_mode(
        self,
    ) -> typing.Optional["VerticalPodAutoscalerSpecUpdatePolicyUpdateMode"]:
        '''Controls when autoscaler applies changes to the pod resources.

        The default is 'Auto'.

        :schema: VerticalPodAutoscalerSpecUpdatePolicy#updateMode
        '''
        result = self._values.get("update_mode")
        return typing.cast(typing.Optional["VerticalPodAutoscalerSpecUpdatePolicyUpdateMode"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VerticalPodAutoscalerSpecUpdatePolicy(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerSpecUpdatePolicyEvictionRequirements",
    jsii_struct_bases=[],
    name_mapping={"change_requirement": "changeRequirement", "resources": "resources"},
)
class VerticalPodAutoscalerSpecUpdatePolicyEvictionRequirements:
    def __init__(
        self,
        *,
        change_requirement: "VerticalPodAutoscalerSpecUpdatePolicyEvictionRequirementsChangeRequirement",
        resources: typing.Sequence[builtins.str],
    ) -> None:
        '''EvictionRequirement defines a single condition which needs to be true in order to evict a Pod.

        :param change_requirement: EvictionChangeRequirement refers to the relationship between the new target recommendation for a Pod and its current requests, what kind of change is necessary for the Pod to be evicted.
        :param resources: Resources is a list of one or more resources that the condition applies to. If more than one resource is given, the EvictionRequirement is fulfilled if at least one resource meets ``changeRequirement``.

        :schema: VerticalPodAutoscalerSpecUpdatePolicyEvictionRequirements
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__310af4049a060a72c926875cbb7db2a8eef4e477f2b93cf2fe28b1cbac746f57)
            check_type(argname="argument change_requirement", value=change_requirement, expected_type=type_hints["change_requirement"])
            check_type(argname="argument resources", value=resources, expected_type=type_hints["resources"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "change_requirement": change_requirement,
            "resources": resources,
        }

    @builtins.property
    def change_requirement(
        self,
    ) -> "VerticalPodAutoscalerSpecUpdatePolicyEvictionRequirementsChangeRequirement":
        '''EvictionChangeRequirement refers to the relationship between the new target recommendation for a Pod and its current requests, what kind of change is necessary for the Pod to be evicted.

        :schema: VerticalPodAutoscalerSpecUpdatePolicyEvictionRequirements#changeRequirement
        '''
        result = self._values.get("change_requirement")
        assert result is not None, "Required property 'change_requirement' is missing"
        return typing.cast("VerticalPodAutoscalerSpecUpdatePolicyEvictionRequirementsChangeRequirement", result)

    @builtins.property
    def resources(self) -> typing.List[builtins.str]:
        '''Resources is a list of one or more resources that the condition applies to.

        If more than one resource is given, the EvictionRequirement is fulfilled
        if at least one resource meets ``changeRequirement``.

        :schema: VerticalPodAutoscalerSpecUpdatePolicyEvictionRequirements#resources
        '''
        result = self._values.get("resources")
        assert result is not None, "Required property 'resources' is missing"
        return typing.cast(typing.List[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VerticalPodAutoscalerSpecUpdatePolicyEvictionRequirements(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerSpecUpdatePolicyEvictionRequirementsChangeRequirement"
)
class VerticalPodAutoscalerSpecUpdatePolicyEvictionRequirementsChangeRequirement(
    enum.Enum,
):
    '''EvictionChangeRequirement refers to the relationship between the new target recommendation for a Pod and its current requests, what kind of change is necessary for the Pod to be evicted.

    :schema: VerticalPodAutoscalerSpecUpdatePolicyEvictionRequirementsChangeRequirement
    '''

    TARGET_HIGHER_THAN_REQUESTS = "TARGET_HIGHER_THAN_REQUESTS"
    '''TargetHigherThanRequests.'''
    TARGET_LOWER_THAN_REQUESTS = "TARGET_LOWER_THAN_REQUESTS"
    '''TargetLowerThanRequests.'''


@jsii.enum(
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerSpecUpdatePolicyUpdateMode"
)
class VerticalPodAutoscalerSpecUpdatePolicyUpdateMode(enum.Enum):
    '''Controls when autoscaler applies changes to the pod resources.

    The default is 'Auto'.

    :schema: VerticalPodAutoscalerSpecUpdatePolicyUpdateMode
    '''

    OFF = "OFF"
    '''Off.'''
    INITIAL = "INITIAL"
    '''Initial.'''
    RECREATE = "RECREATE"
    '''Recreate.'''
    AUTO = "AUTO"
    '''Auto.'''


class VerticalPodAutoscalerV1Beta2(
    _cdk8s_d3d9af27.ApiObject,
    metaclass=jsii.JSIIMeta,
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerV1Beta2",
):
    '''VerticalPodAutoscaler is the configuration for a vertical pod autoscaler, which automatically manages pod resources based on historical and real time resource utilization.

    :schema: VerticalPodAutoscalerV1Beta2
    '''

    def __init__(
        self,
        scope: _constructs_77d1e7e8.Construct,
        id: builtins.str,
        *,
        spec: typing.Union["VerticalPodAutoscalerV1Beta2Spec", typing.Dict[builtins.str, typing.Any]],
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Defines a "VerticalPodAutoscalerV1Beta2" API object.

        :param scope: the scope in which to define this object.
        :param id: a scope-local name for the object.
        :param spec: Specification of the behavior of the autoscaler. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.
        :param metadata: 
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__e62d9c88d47e2b7c49e596ee1a15c109172519d6ecebad967bc021a61f70947e)
            check_type(argname="argument scope", value=scope, expected_type=type_hints["scope"])
            check_type(argname="argument id", value=id, expected_type=type_hints["id"])
        props = VerticalPodAutoscalerV1Beta2Props(spec=spec, metadata=metadata)

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="manifest")
    @builtins.classmethod
    def manifest(
        cls,
        *,
        spec: typing.Union["VerticalPodAutoscalerV1Beta2Spec", typing.Dict[builtins.str, typing.Any]],
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> typing.Any:
        '''Renders a Kubernetes manifest for "VerticalPodAutoscalerV1Beta2".

        This can be used to inline resource manifests inside other objects (e.g. as templates).

        :param spec: Specification of the behavior of the autoscaler. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.
        :param metadata: 
        '''
        props = VerticalPodAutoscalerV1Beta2Props(spec=spec, metadata=metadata)

        return typing.cast(typing.Any, jsii.sinvoke(cls, "manifest", [props]))

    @jsii.member(jsii_name="toJson")
    def to_json(self) -> typing.Any:
        '''Renders the object to Kubernetes JSON.'''
        return typing.cast(typing.Any, jsii.invoke(self, "toJson", []))

    @jsii.python.classproperty
    @jsii.member(jsii_name="GVK")
    def GVK(cls) -> _cdk8s_d3d9af27.GroupVersionKind:
        '''Returns the apiVersion and kind for "VerticalPodAutoscalerV1Beta2".'''
        return typing.cast(_cdk8s_d3d9af27.GroupVersionKind, jsii.sget(cls, "GVK"))


@jsii.data_type(
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerV1Beta2Props",
    jsii_struct_bases=[],
    name_mapping={"spec": "spec", "metadata": "metadata"},
)
class VerticalPodAutoscalerV1Beta2Props:
    def __init__(
        self,
        *,
        spec: typing.Union["VerticalPodAutoscalerV1Beta2Spec", typing.Dict[builtins.str, typing.Any]],
        metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''VerticalPodAutoscaler is the configuration for a vertical pod autoscaler, which automatically manages pod resources based on historical and real time resource utilization.

        :param spec: Specification of the behavior of the autoscaler. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.
        :param metadata: 

        :schema: VerticalPodAutoscalerV1Beta2
        '''
        if isinstance(spec, dict):
            spec = VerticalPodAutoscalerV1Beta2Spec(**spec)
        if isinstance(metadata, dict):
            metadata = _cdk8s_d3d9af27.ApiObjectMetadata(**metadata)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__8e1a91a8e7590b5de4cca8619ac3b00df33c6af7316dd70203be615d6a1c2890)
            check_type(argname="argument spec", value=spec, expected_type=type_hints["spec"])
            check_type(argname="argument metadata", value=metadata, expected_type=type_hints["metadata"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "spec": spec,
        }
        if metadata is not None:
            self._values["metadata"] = metadata

    @builtins.property
    def spec(self) -> "VerticalPodAutoscalerV1Beta2Spec":
        '''Specification of the behavior of the autoscaler.

        More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.

        :schema: VerticalPodAutoscalerV1Beta2#spec
        '''
        result = self._values.get("spec")
        assert result is not None, "Required property 'spec' is missing"
        return typing.cast("VerticalPodAutoscalerV1Beta2Spec", result)

    @builtins.property
    def metadata(self) -> typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata]:
        '''
        :schema: VerticalPodAutoscalerV1Beta2#metadata
        '''
        result = self._values.get("metadata")
        return typing.cast(typing.Optional[_cdk8s_d3d9af27.ApiObjectMetadata], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VerticalPodAutoscalerV1Beta2Props(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerV1Beta2Spec",
    jsii_struct_bases=[],
    name_mapping={
        "target_ref": "targetRef",
        "resource_policy": "resourcePolicy",
        "update_policy": "updatePolicy",
    },
)
class VerticalPodAutoscalerV1Beta2Spec:
    def __init__(
        self,
        *,
        target_ref: typing.Union["VerticalPodAutoscalerV1Beta2SpecTargetRef", typing.Dict[builtins.str, typing.Any]],
        resource_policy: typing.Optional[typing.Union["VerticalPodAutoscalerV1Beta2SpecResourcePolicy", typing.Dict[builtins.str, typing.Any]]] = None,
        update_policy: typing.Optional[typing.Union["VerticalPodAutoscalerV1Beta2SpecUpdatePolicy", typing.Dict[builtins.str, typing.Any]]] = None,
    ) -> None:
        '''Specification of the behavior of the autoscaler.

        More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status.

        :param target_ref: TargetRef points to the controller managing the set of pods for the autoscaler to control - e.g. Deployment, StatefulSet. VerticalPodAutoscaler can be targeted at controller implementing scale subresource (the pod set is retrieved from the controller's ScaleStatus) or some well known controllers (e.g. for DaemonSet the pod set is read from the controller's spec). If VerticalPodAutoscaler cannot use specified target it will report ConfigUnsupported condition. Note that VerticalPodAutoscaler does not require full implementation of scale subresource - it will not use it to modify the replica count. The only thing retrieved is a label selector matching pods grouped by the target resource.
        :param resource_policy: Controls how the autoscaler computes recommended resources. The resource policy may be used to set constraints on the recommendations for individual containers. If not specified, the autoscaler computes recommended resources for all containers in the pod, without additional constraints.
        :param update_policy: Describes the rules on how changes are applied to the pods. If not specified, all fields in the ``PodUpdatePolicy`` are set to their default values.

        :schema: VerticalPodAutoscalerV1Beta2Spec
        '''
        if isinstance(target_ref, dict):
            target_ref = VerticalPodAutoscalerV1Beta2SpecTargetRef(**target_ref)
        if isinstance(resource_policy, dict):
            resource_policy = VerticalPodAutoscalerV1Beta2SpecResourcePolicy(**resource_policy)
        if isinstance(update_policy, dict):
            update_policy = VerticalPodAutoscalerV1Beta2SpecUpdatePolicy(**update_policy)
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__99534649bf878687433d2d89ab24d48a97de2958ca7513f0e54f0b47ea5ccebb)
            check_type(argname="argument target_ref", value=target_ref, expected_type=type_hints["target_ref"])
            check_type(argname="argument resource_policy", value=resource_policy, expected_type=type_hints["resource_policy"])
            check_type(argname="argument update_policy", value=update_policy, expected_type=type_hints["update_policy"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "target_ref": target_ref,
        }
        if resource_policy is not None:
            self._values["resource_policy"] = resource_policy
        if update_policy is not None:
            self._values["update_policy"] = update_policy

    @builtins.property
    def target_ref(self) -> "VerticalPodAutoscalerV1Beta2SpecTargetRef":
        '''TargetRef points to the controller managing the set of pods for the autoscaler to control - e.g. Deployment, StatefulSet. VerticalPodAutoscaler can be targeted at controller implementing scale subresource (the pod set is retrieved from the controller's ScaleStatus) or some well known controllers (e.g. for DaemonSet the pod set is read from the controller's spec). If VerticalPodAutoscaler cannot use specified target it will report ConfigUnsupported condition. Note that VerticalPodAutoscaler does not require full implementation of scale subresource - it will not use it to modify the replica count. The only thing retrieved is a label selector matching pods grouped by the target resource.

        :schema: VerticalPodAutoscalerV1Beta2Spec#targetRef
        '''
        result = self._values.get("target_ref")
        assert result is not None, "Required property 'target_ref' is missing"
        return typing.cast("VerticalPodAutoscalerV1Beta2SpecTargetRef", result)

    @builtins.property
    def resource_policy(
        self,
    ) -> typing.Optional["VerticalPodAutoscalerV1Beta2SpecResourcePolicy"]:
        '''Controls how the autoscaler computes recommended resources.

        The resource policy may be used to set constraints on the recommendations
        for individual containers. If not specified, the autoscaler computes recommended
        resources for all containers in the pod, without additional constraints.

        :schema: VerticalPodAutoscalerV1Beta2Spec#resourcePolicy
        '''
        result = self._values.get("resource_policy")
        return typing.cast(typing.Optional["VerticalPodAutoscalerV1Beta2SpecResourcePolicy"], result)

    @builtins.property
    def update_policy(
        self,
    ) -> typing.Optional["VerticalPodAutoscalerV1Beta2SpecUpdatePolicy"]:
        '''Describes the rules on how changes are applied to the pods.

        If not specified, all fields in the ``PodUpdatePolicy`` are set to their
        default values.

        :schema: VerticalPodAutoscalerV1Beta2Spec#updatePolicy
        '''
        result = self._values.get("update_policy")
        return typing.cast(typing.Optional["VerticalPodAutoscalerV1Beta2SpecUpdatePolicy"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VerticalPodAutoscalerV1Beta2Spec(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerV1Beta2SpecResourcePolicy",
    jsii_struct_bases=[],
    name_mapping={"container_policies": "containerPolicies"},
)
class VerticalPodAutoscalerV1Beta2SpecResourcePolicy:
    def __init__(
        self,
        *,
        container_policies: typing.Optional[typing.Sequence[typing.Union["VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPolicies", typing.Dict[builtins.str, typing.Any]]]] = None,
    ) -> None:
        '''Controls how the autoscaler computes recommended resources.

        The resource policy may be used to set constraints on the recommendations
        for individual containers. If not specified, the autoscaler computes recommended
        resources for all containers in the pod, without additional constraints.

        :param container_policies: Per-container resource policies.

        :schema: VerticalPodAutoscalerV1Beta2SpecResourcePolicy
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__340f8a3834dddb8945e030d1e547c99b6ec0f68f67ce5961a5a878d5be0be59c)
            check_type(argname="argument container_policies", value=container_policies, expected_type=type_hints["container_policies"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if container_policies is not None:
            self._values["container_policies"] = container_policies

    @builtins.property
    def container_policies(
        self,
    ) -> typing.Optional[typing.List["VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPolicies"]]:
        '''Per-container resource policies.

        :schema: VerticalPodAutoscalerV1Beta2SpecResourcePolicy#containerPolicies
        '''
        result = self._values.get("container_policies")
        return typing.cast(typing.Optional[typing.List["VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPolicies"]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VerticalPodAutoscalerV1Beta2SpecResourcePolicy(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPolicies",
    jsii_struct_bases=[],
    name_mapping={
        "container_name": "containerName",
        "max_allowed": "maxAllowed",
        "min_allowed": "minAllowed",
        "mode": "mode",
    },
)
class VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPolicies:
    def __init__(
        self,
        *,
        container_name: typing.Optional[builtins.str] = None,
        max_allowed: typing.Optional[typing.Mapping[builtins.str, "VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPoliciesMaxAllowed"]] = None,
        min_allowed: typing.Optional[typing.Mapping[builtins.str, "VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPoliciesMinAllowed"]] = None,
        mode: typing.Optional["VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPoliciesMode"] = None,
    ) -> None:
        '''ContainerResourcePolicy controls how autoscaler computes the recommended resources for a specific container.

        :param container_name: Name of the container or DefaultContainerResourcePolicy, in which case the policy is used by the containers that don't have their own policy specified.
        :param max_allowed: Specifies the maximum amount of resources that will be recommended for the container. The default is no maximum.
        :param min_allowed: Specifies the minimal amount of resources that will be recommended for the container. The default is no minimum.
        :param mode: Whether autoscaler is enabled for the container. The default is "Auto".

        :schema: VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPolicies
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__37a19ec4542ee9b3c482c463626b5c1bd42c8e2e33344c398be7f0169a170722)
            check_type(argname="argument container_name", value=container_name, expected_type=type_hints["container_name"])
            check_type(argname="argument max_allowed", value=max_allowed, expected_type=type_hints["max_allowed"])
            check_type(argname="argument min_allowed", value=min_allowed, expected_type=type_hints["min_allowed"])
            check_type(argname="argument mode", value=mode, expected_type=type_hints["mode"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if container_name is not None:
            self._values["container_name"] = container_name
        if max_allowed is not None:
            self._values["max_allowed"] = max_allowed
        if min_allowed is not None:
            self._values["min_allowed"] = min_allowed
        if mode is not None:
            self._values["mode"] = mode

    @builtins.property
    def container_name(self) -> typing.Optional[builtins.str]:
        '''Name of the container or DefaultContainerResourcePolicy, in which case the policy is used by the containers that don't have their own policy specified.

        :schema: VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPolicies#containerName
        '''
        result = self._values.get("container_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def max_allowed(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, "VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPoliciesMaxAllowed"]]:
        '''Specifies the maximum amount of resources that will be recommended for the container.

        The default is no maximum.

        :schema: VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPolicies#maxAllowed
        '''
        result = self._values.get("max_allowed")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, "VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPoliciesMaxAllowed"]], result)

    @builtins.property
    def min_allowed(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, "VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPoliciesMinAllowed"]]:
        '''Specifies the minimal amount of resources that will be recommended for the container.

        The default is no minimum.

        :schema: VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPolicies#minAllowed
        '''
        result = self._values.get("min_allowed")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, "VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPoliciesMinAllowed"]], result)

    @builtins.property
    def mode(
        self,
    ) -> typing.Optional["VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPoliciesMode"]:
        '''Whether autoscaler is enabled for the container.

        The default is "Auto".

        :schema: VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPolicies#mode
        '''
        result = self._values.get("mode")
        return typing.cast(typing.Optional["VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPoliciesMode"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPolicies(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPoliciesMaxAllowed(
    metaclass=jsii.JSIIMeta,
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPoliciesMaxAllowed",
):
    '''
    :schema: VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPoliciesMaxAllowed
    '''

    @jsii.member(jsii_name="fromNumber")
    @builtins.classmethod
    def from_number(
        cls,
        value: jsii.Number,
    ) -> "VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPoliciesMaxAllowed":
        '''
        :param value: -
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__34d6b77a70ee0211e503a20956b0ba579708b52b04480f66cab005ee63fac135)
            check_type(argname="argument value", value=value, expected_type=type_hints["value"])
        return typing.cast("VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPoliciesMaxAllowed", jsii.sinvoke(cls, "fromNumber", [value]))

    @jsii.member(jsii_name="fromString")
    @builtins.classmethod
    def from_string(
        cls,
        value: builtins.str,
    ) -> "VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPoliciesMaxAllowed":
        '''
        :param value: -
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__ae3cf7bbfce7e31dd0f70760de9c879ff4cdea48512f1a94084eb81afaaa70ac)
            check_type(argname="argument value", value=value, expected_type=type_hints["value"])
        return typing.cast("VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPoliciesMaxAllowed", jsii.sinvoke(cls, "fromString", [value]))

    @builtins.property
    @jsii.member(jsii_name="value")
    def value(self) -> typing.Union[builtins.str, jsii.Number]:
        return typing.cast(typing.Union[builtins.str, jsii.Number], jsii.get(self, "value"))


class VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPoliciesMinAllowed(
    metaclass=jsii.JSIIMeta,
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPoliciesMinAllowed",
):
    '''
    :schema: VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPoliciesMinAllowed
    '''

    @jsii.member(jsii_name="fromNumber")
    @builtins.classmethod
    def from_number(
        cls,
        value: jsii.Number,
    ) -> "VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPoliciesMinAllowed":
        '''
        :param value: -
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__8e54aa4f5ee4a3a1d8bf5fc549d79bda640fd52623091c88e457a8541d962f48)
            check_type(argname="argument value", value=value, expected_type=type_hints["value"])
        return typing.cast("VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPoliciesMinAllowed", jsii.sinvoke(cls, "fromNumber", [value]))

    @jsii.member(jsii_name="fromString")
    @builtins.classmethod
    def from_string(
        cls,
        value: builtins.str,
    ) -> "VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPoliciesMinAllowed":
        '''
        :param value: -
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__4edbe499599341ff3077182dad7ca8e4442befbe9c670d59195effa558372419)
            check_type(argname="argument value", value=value, expected_type=type_hints["value"])
        return typing.cast("VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPoliciesMinAllowed", jsii.sinvoke(cls, "fromString", [value]))

    @builtins.property
    @jsii.member(jsii_name="value")
    def value(self) -> typing.Union[builtins.str, jsii.Number]:
        return typing.cast(typing.Union[builtins.str, jsii.Number], jsii.get(self, "value"))


@jsii.enum(
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPoliciesMode"
)
class VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPoliciesMode(enum.Enum):
    '''Whether autoscaler is enabled for the container.

    The default is "Auto".

    :schema: VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPoliciesMode
    '''

    AUTO = "AUTO"
    '''Auto.'''
    OFF = "OFF"
    '''Off.'''


@jsii.data_type(
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerV1Beta2SpecTargetRef",
    jsii_struct_bases=[],
    name_mapping={"kind": "kind", "name": "name", "api_version": "apiVersion"},
)
class VerticalPodAutoscalerV1Beta2SpecTargetRef:
    def __init__(
        self,
        *,
        kind: builtins.str,
        name: builtins.str,
        api_version: typing.Optional[builtins.str] = None,
    ) -> None:
        '''TargetRef points to the controller managing the set of pods for the autoscaler to control - e.g. Deployment, StatefulSet. VerticalPodAutoscaler can be targeted at controller implementing scale subresource (the pod set is retrieved from the controller's ScaleStatus) or some well known controllers (e.g. for DaemonSet the pod set is read from the controller's spec). If VerticalPodAutoscaler cannot use specified target it will report ConfigUnsupported condition. Note that VerticalPodAutoscaler does not require full implementation of scale subresource - it will not use it to modify the replica count. The only thing retrieved is a label selector matching pods grouped by the target resource.

        :param kind: kind is the kind of the referent; More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds
        :param name: name is the name of the referent; More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
        :param api_version: apiVersion is the API version of the referent.

        :schema: VerticalPodAutoscalerV1Beta2SpecTargetRef
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__f17c3920203c108e147cc631476784035b9441bcc15ab7cf47800cad0cbfac10)
            check_type(argname="argument kind", value=kind, expected_type=type_hints["kind"])
            check_type(argname="argument name", value=name, expected_type=type_hints["name"])
            check_type(argname="argument api_version", value=api_version, expected_type=type_hints["api_version"])
        self._values: typing.Dict[builtins.str, typing.Any] = {
            "kind": kind,
            "name": name,
        }
        if api_version is not None:
            self._values["api_version"] = api_version

    @builtins.property
    def kind(self) -> builtins.str:
        '''kind is the kind of the referent;

        More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds

        :schema: VerticalPodAutoscalerV1Beta2SpecTargetRef#kind
        '''
        result = self._values.get("kind")
        assert result is not None, "Required property 'kind' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def name(self) -> builtins.str:
        '''name is the name of the referent;

        More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names

        :schema: VerticalPodAutoscalerV1Beta2SpecTargetRef#name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def api_version(self) -> typing.Optional[builtins.str]:
        '''apiVersion is the API version of the referent.

        :schema: VerticalPodAutoscalerV1Beta2SpecTargetRef#apiVersion
        '''
        result = self._values.get("api_version")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VerticalPodAutoscalerV1Beta2SpecTargetRef(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerV1Beta2SpecUpdatePolicy",
    jsii_struct_bases=[],
    name_mapping={"update_mode": "updateMode"},
)
class VerticalPodAutoscalerV1Beta2SpecUpdatePolicy:
    def __init__(
        self,
        *,
        update_mode: typing.Optional["VerticalPodAutoscalerV1Beta2SpecUpdatePolicyUpdateMode"] = None,
    ) -> None:
        '''Describes the rules on how changes are applied to the pods.

        If not specified, all fields in the ``PodUpdatePolicy`` are set to their
        default values.

        :param update_mode: Controls when autoscaler applies changes to the pod resources. The default is 'Auto'.

        :schema: VerticalPodAutoscalerV1Beta2SpecUpdatePolicy
        '''
        if __debug__:
            type_hints = typing.get_type_hints(_typecheckingstub__6745106fd41202b69ac4f89545bd10e7a4e347bcf067bd1dc7b2b535eb8dd61d)
            check_type(argname="argument update_mode", value=update_mode, expected_type=type_hints["update_mode"])
        self._values: typing.Dict[builtins.str, typing.Any] = {}
        if update_mode is not None:
            self._values["update_mode"] = update_mode

    @builtins.property
    def update_mode(
        self,
    ) -> typing.Optional["VerticalPodAutoscalerV1Beta2SpecUpdatePolicyUpdateMode"]:
        '''Controls when autoscaler applies changes to the pod resources.

        The default is 'Auto'.

        :schema: VerticalPodAutoscalerV1Beta2SpecUpdatePolicy#updateMode
        '''
        result = self._values.get("update_mode")
        return typing.cast(typing.Optional["VerticalPodAutoscalerV1Beta2SpecUpdatePolicyUpdateMode"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VerticalPodAutoscalerV1Beta2SpecUpdatePolicy(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(
    jsii_type="iok8sautoscaling.VerticalPodAutoscalerV1Beta2SpecUpdatePolicyUpdateMode"
)
class VerticalPodAutoscalerV1Beta2SpecUpdatePolicyUpdateMode(enum.Enum):
    '''Controls when autoscaler applies changes to the pod resources.

    The default is 'Auto'.

    :schema: VerticalPodAutoscalerV1Beta2SpecUpdatePolicyUpdateMode
    '''

    OFF = "OFF"
    '''Off.'''
    INITIAL = "INITIAL"
    '''Initial.'''
    RECREATE = "RECREATE"
    '''Recreate.'''
    AUTO = "AUTO"
    '''Auto.'''


__all__ = [
    "VerticalPodAutoscaler",
    "VerticalPodAutoscalerCheckpoint",
    "VerticalPodAutoscalerCheckpointProps",
    "VerticalPodAutoscalerCheckpointSpec",
    "VerticalPodAutoscalerCheckpointV1Beta2",
    "VerticalPodAutoscalerCheckpointV1Beta2Props",
    "VerticalPodAutoscalerCheckpointV1Beta2Spec",
    "VerticalPodAutoscalerProps",
    "VerticalPodAutoscalerSpec",
    "VerticalPodAutoscalerSpecRecommenders",
    "VerticalPodAutoscalerSpecResourcePolicy",
    "VerticalPodAutoscalerSpecResourcePolicyContainerPolicies",
    "VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesControlledValues",
    "VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMaxAllowed",
    "VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMinAllowed",
    "VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMode",
    "VerticalPodAutoscalerSpecTargetRef",
    "VerticalPodAutoscalerSpecUpdatePolicy",
    "VerticalPodAutoscalerSpecUpdatePolicyEvictionRequirements",
    "VerticalPodAutoscalerSpecUpdatePolicyEvictionRequirementsChangeRequirement",
    "VerticalPodAutoscalerSpecUpdatePolicyUpdateMode",
    "VerticalPodAutoscalerV1Beta2",
    "VerticalPodAutoscalerV1Beta2Props",
    "VerticalPodAutoscalerV1Beta2Spec",
    "VerticalPodAutoscalerV1Beta2SpecResourcePolicy",
    "VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPolicies",
    "VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPoliciesMaxAllowed",
    "VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPoliciesMinAllowed",
    "VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPoliciesMode",
    "VerticalPodAutoscalerV1Beta2SpecTargetRef",
    "VerticalPodAutoscalerV1Beta2SpecUpdatePolicy",
    "VerticalPodAutoscalerV1Beta2SpecUpdatePolicyUpdateMode",
]

publication.publish()

def _typecheckingstub__caf59d86d285ee6685b1508c4068ea959df4364adaf893cf0bdee63cda7bf602(
    scope: _constructs_77d1e7e8.Construct,
    id: builtins.str,
    *,
    spec: typing.Union[VerticalPodAutoscalerSpec, typing.Dict[builtins.str, typing.Any]],
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__417daf29a0414735a3caff5a1262960997e0629f4d3672d94cc5030c1035a633(
    scope: _constructs_77d1e7e8.Construct,
    id: builtins.str,
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Optional[typing.Union[VerticalPodAutoscalerCheckpointSpec, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__6c09821f0bd7acf378fc14e7d8baaad633b256459ef04fbf16edbaba8dbc367c(
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Optional[typing.Union[VerticalPodAutoscalerCheckpointSpec, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__4926d22a30287a53595e4c60d286da97757a94e8c82011a5a7eac45f0d5471eb(
    *,
    container_name: typing.Optional[builtins.str] = None,
    vpa_object_name: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__e965f8c6b458dc1cd77321285fce0a2d2bc53ac846b7debafdd4e084ab9d0966(
    scope: _constructs_77d1e7e8.Construct,
    id: builtins.str,
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Optional[typing.Union[VerticalPodAutoscalerCheckpointV1Beta2Spec, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__a3056128a13898c38734cd5a9c41636e80201bd29082acb7843438509646ab48(
    *,
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
    spec: typing.Optional[typing.Union[VerticalPodAutoscalerCheckpointV1Beta2Spec, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__8b3f23f9542562f2c369c0a5d837e33dbbb7622ce2bcd688da1c58b93ed20a62(
    *,
    container_name: typing.Optional[builtins.str] = None,
    vpa_object_name: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__9fdd7c3f96f7a745f9e5cfc2908bb1ce7c61c78028c1c29dbd8a9b6d659de3cd(
    *,
    spec: typing.Union[VerticalPodAutoscalerSpec, typing.Dict[builtins.str, typing.Any]],
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__aad6783c71127d8ab5dcca718acfc5e5ac0c4b9eac186e46f316e34aad7bf2c1(
    *,
    target_ref: typing.Union[VerticalPodAutoscalerSpecTargetRef, typing.Dict[builtins.str, typing.Any]],
    recommenders: typing.Optional[typing.Sequence[typing.Union[VerticalPodAutoscalerSpecRecommenders, typing.Dict[builtins.str, typing.Any]]]] = None,
    resource_policy: typing.Optional[typing.Union[VerticalPodAutoscalerSpecResourcePolicy, typing.Dict[builtins.str, typing.Any]]] = None,
    update_policy: typing.Optional[typing.Union[VerticalPodAutoscalerSpecUpdatePolicy, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__3e5198b23f37399ac14dd9bde4cc16da589345871e41914d8ae0fa2e1196edd7(
    *,
    name: builtins.str,
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
    controlled_resources: typing.Optional[typing.Sequence[builtins.str]] = None,
    controlled_values: typing.Optional[VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesControlledValues] = None,
    max_allowed: typing.Optional[typing.Mapping[builtins.str, VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMaxAllowed]] = None,
    min_allowed: typing.Optional[typing.Mapping[builtins.str, VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMinAllowed]] = None,
    mode: typing.Optional[VerticalPodAutoscalerSpecResourcePolicyContainerPoliciesMode] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__5a3489df3481bf643eba8891e566a27cb7a905ce3bc7a75836f55e77cea812ce(
    value: jsii.Number,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__1149315f4d028ce0f7fb1a6f25223eae226e5cacb95c987bb93237bde6b3f708(
    value: builtins.str,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__0d73f677b6a482dbb3b55973d80ae592e9d8c000e9b9e097a4bba666ae8624ef(
    value: jsii.Number,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__48e1ef241fc712d94bafc6720c9dbdf04454d7347d241bf8e7b39f821f87b9c6(
    value: builtins.str,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__9f7e1cdc947c495ae1aa36536adc3a83321ba4c464768bf26354e40e3055ae51(
    *,
    kind: builtins.str,
    name: builtins.str,
    api_version: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__2090e51372d1722715886f39b00478aa4a1a6c5c8b06379c6ccf82ad97b6e06b(
    *,
    eviction_requirements: typing.Optional[typing.Sequence[typing.Union[VerticalPodAutoscalerSpecUpdatePolicyEvictionRequirements, typing.Dict[builtins.str, typing.Any]]]] = None,
    min_replicas: typing.Optional[jsii.Number] = None,
    update_mode: typing.Optional[VerticalPodAutoscalerSpecUpdatePolicyUpdateMode] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__310af4049a060a72c926875cbb7db2a8eef4e477f2b93cf2fe28b1cbac746f57(
    *,
    change_requirement: VerticalPodAutoscalerSpecUpdatePolicyEvictionRequirementsChangeRequirement,
    resources: typing.Sequence[builtins.str],
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__e62d9c88d47e2b7c49e596ee1a15c109172519d6ecebad967bc021a61f70947e(
    scope: _constructs_77d1e7e8.Construct,
    id: builtins.str,
    *,
    spec: typing.Union[VerticalPodAutoscalerV1Beta2Spec, typing.Dict[builtins.str, typing.Any]],
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__8e1a91a8e7590b5de4cca8619ac3b00df33c6af7316dd70203be615d6a1c2890(
    *,
    spec: typing.Union[VerticalPodAutoscalerV1Beta2Spec, typing.Dict[builtins.str, typing.Any]],
    metadata: typing.Optional[typing.Union[_cdk8s_d3d9af27.ApiObjectMetadata, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__99534649bf878687433d2d89ab24d48a97de2958ca7513f0e54f0b47ea5ccebb(
    *,
    target_ref: typing.Union[VerticalPodAutoscalerV1Beta2SpecTargetRef, typing.Dict[builtins.str, typing.Any]],
    resource_policy: typing.Optional[typing.Union[VerticalPodAutoscalerV1Beta2SpecResourcePolicy, typing.Dict[builtins.str, typing.Any]]] = None,
    update_policy: typing.Optional[typing.Union[VerticalPodAutoscalerV1Beta2SpecUpdatePolicy, typing.Dict[builtins.str, typing.Any]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__340f8a3834dddb8945e030d1e547c99b6ec0f68f67ce5961a5a878d5be0be59c(
    *,
    container_policies: typing.Optional[typing.Sequence[typing.Union[VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPolicies, typing.Dict[builtins.str, typing.Any]]]] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__37a19ec4542ee9b3c482c463626b5c1bd42c8e2e33344c398be7f0169a170722(
    *,
    container_name: typing.Optional[builtins.str] = None,
    max_allowed: typing.Optional[typing.Mapping[builtins.str, VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPoliciesMaxAllowed]] = None,
    min_allowed: typing.Optional[typing.Mapping[builtins.str, VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPoliciesMinAllowed]] = None,
    mode: typing.Optional[VerticalPodAutoscalerV1Beta2SpecResourcePolicyContainerPoliciesMode] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__34d6b77a70ee0211e503a20956b0ba579708b52b04480f66cab005ee63fac135(
    value: jsii.Number,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__ae3cf7bbfce7e31dd0f70760de9c879ff4cdea48512f1a94084eb81afaaa70ac(
    value: builtins.str,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__8e54aa4f5ee4a3a1d8bf5fc549d79bda640fd52623091c88e457a8541d962f48(
    value: jsii.Number,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__4edbe499599341ff3077182dad7ca8e4442befbe9c670d59195effa558372419(
    value: builtins.str,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__f17c3920203c108e147cc631476784035b9441bcc15ab7cf47800cad0cbfac10(
    *,
    kind: builtins.str,
    name: builtins.str,
    api_version: typing.Optional[builtins.str] = None,
) -> None:
    """Type checking stubs"""
    pass

def _typecheckingstub__6745106fd41202b69ac4f89545bd10e7a4e347bcf067bd1dc7b2b535eb8dd61d(
    *,
    update_mode: typing.Optional[VerticalPodAutoscalerV1Beta2SpecUpdatePolicyUpdateMode] = None,
) -> None:
    """Type checking stubs"""
    pass
