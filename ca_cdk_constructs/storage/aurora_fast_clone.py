from typing import Any
from aws_cdk import CfnOutput, Token, Stack
from constructs import Construct
from aws_cdk.aws_ec2 import SubnetSelection, IVpc, SecurityGroup, IConnectable, Port
from aws_cdk.aws_rds import (
    CfnDBCluster,
    DatabaseCluster,
    SubnetGroup,
    CfnDBParameterGroup,
    CfnDBClusterParameterGroup,
    CfnDBInstance,
)


class AuroraFastClone(Construct):
    """Creates Aurora fast clone"""

    def __init__(
        self,
        scope: Construct,
        id: str,
        source_cluster: DatabaseCluster,
        vpc: IVpc,
        db_instance_class: str,
        cluster_parameters: dict[str, Any],
        instance_params: dict[str, Any],
    ) -> None:
        super().__init__(scope, id)

        clone_cluster_id = f"{Stack.of(source_cluster).stack_name}-{Stack.of(self).stack_name}"

        db_subnet_group = SubnetGroup(
            self,
            "SubnetGroup",
            description=f"Subnet group for {clone_cluster_id}",
            vpc=vpc,
            vpc_subnets=SubnetSelection(subnets=vpc.private_subnets),
        )

        cluster_pg = CfnDBClusterParameterGroup(
            self,
            "DBClusterParameterGroup",
            description=f"Cluster parameter group for {clone_cluster_id}",
            family=source_cluster.engine.parameter_group_family,
            parameters=cluster_parameters,
        )
        cluster_instance_pg = CfnDBParameterGroup(
            self,
            "DBParameterGroup",
            description=f"DB parameter group for {clone_cluster_id}",
            family=source_cluster.engine.parameter_group_family,
            parameters=instance_params,
        )

        self.cluster_sg = SecurityGroup(self, "CloneClusterSG", vpc=vpc)
        self.cluster = CfnDBCluster(
            self,
            "CloneCluster",
            db_cluster_parameter_group_name=cluster_pg.ref,
            engine=source_cluster.engine.engine_type,
            use_latest_restorable_time=True,
            restore_type="copy-on-write",
            source_db_cluster_identifier=source_cluster.cluster_identifier,
            engine_version=source_cluster.engine.engine_version.full_version,
            # ignored, see below
            db_subnet_group_name=db_subnet_group.subnet_group_name,
            vpc_security_group_ids=[self.cluster_sg.security_group_id],
        )
        # https://github.com/aws-cloudformation/cloudformation-coverage-roadmap/issues/336
        self.cluster.add_override(
            "Properties.DBSubnetGroupName", db_subnet_group.subnet_group_name
        )

        self.cluster.add_override(
            "Properties.VpcSecurityGroupIds", [self.cluster_sg.security_group_id]
        )

        self.cluster_instance = CfnDBInstance(
            self,
            "CloneClusterPrimaryInstance",
            db_instance_class=db_instance_class,
            # ignored when using self.cluster.db_cluster_identifier
            db_cluster_identifier=self.cluster.ref,
            db_parameter_group_name=cluster_instance_pg.ref,
            engine=self.cluster.engine,
            delete_automated_backups=True
        )

        CfnOutput(self, "ClusterEndpointAddress", value=self.cluster.attr_endpoint_address)
        CfnOutput(self, "ClusterEndpointPort", value=self.cluster.attr_endpoint_port)

    def allow_from(self, *args: IConnectable):
        for peer in args:
            self.cluster_sg.connections.allow_from(
                peer, port_range=Port.tcp(Token.as_number(self.cluster.attr_endpoint_port))
            )
