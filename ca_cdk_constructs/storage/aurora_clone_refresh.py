import os

from aws_cdk import CfnOutput, Stack
from aws_cdk import Duration
from aws_cdk.aws_ec2 import SubnetSelection, IVpc, SecurityGroup, IConnectable, Port
from aws_cdk.aws_events import Rule, Schedule, RuleTargetInput
from aws_cdk.aws_events_targets import SfnStateMachine
from aws_cdk.aws_iam import PolicyStatement
from aws_cdk.aws_lambda import Runtime
from aws_cdk.aws_lambda_python_alpha import PythonFunction
from aws_cdk.aws_rds import (
    DatabaseSecret,
    SubnetGroup,
    CfnDBClusterParameterGroup,
    CfnDBParameterGroup,
    IDatabaseCluster,
)
from aws_cdk.aws_sns import Topic, ITopic
from aws_cdk.aws_stepfunctions import (
    JsonPath,
    Choice,
    Wait,
    WaitTime,
    Condition,
    StateMachine,
    Fail,
    TaskInput,
    Chain,
    Pass,
)
from aws_cdk.aws_stepfunctions_tasks import LambdaInvoke, SnsPublish
from constructs import Construct

from ca_cdk_constructs.aws_lambda.layers.boto3 import Boto3LambdaLayer
from ca_cdk_constructs.storage.modify_db_cluster_password import ModifyDBClusterPassword


class AuroraCloneRefresh(Construct):
    """
    Uses copy-on-write to create an Aurora cluster clone and periodically recreates the clone according to the specified schedule.
    The clone master password will be reset and the new credentials and connection information will be stored in a DatabaseSecret created by this constrict.
    """

    LAMBDA_SOURCE_DIR = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "aurora_fast_clone"
    )

    def __init__(
        self,
        scope: Construct,
        id: str,
        source_cluster: IDatabaseCluster,
        source_cluster_vpc: IVpc,
        clone_db_instance_class: str,
        source_cluster_master_username: str,
        clone_cluster_parameter_group: CfnDBClusterParameterGroup,
        clone_instance_parameter_group: CfnDBParameterGroup,
        clone_tags={},
        clone_schedule: Schedule = Schedule.cron(minute="0", hour="8"),
        notifications_topic: ITopic = None,
    ) -> None:
        """

        Args:
            scope: Contruct
            id: ID
            source_cluster (IDatabaseCluster): the cluster to be cloned
            source_cluster_vpc (IVpc): the vpc of the source cluster
            source_cluster_master_username (str): The master user of the source cluster
            clone_db_instance_class (str): the instance class of the primary DB instance in the cloned cluster
            clone_cluster_parameter_group (CfnDBClusterParameterGroup): cloned cluster parameter group
            clone_instance_parameter_group (CfnDBParameterGroup): the parameter group of the primary instance in the cloned cluster
            clone_tags (dict[str,str]): optional tags to be added to the cloned cluster and instance. The source cluster tags are added automatically
            clone_schedule (Schedule): Clone schedule
            notifications_topic (ITopic): Existing topic to publish notifications to. Default - new topic will be created
        """
        super().__init__(scope, id)

        tags = clone_tags | {
            "CreatedByStack": Stack.of(self).stack_name,
            "CloneOf": source_cluster.cluster_identifier,
        }

        tag_list = [{"Key": k, "Value": v} for k, v in tags.items()]

        # rds IDs are all lowercase
        clone_cluster_id = f"{Stack.of(source_cluster).stack_name}-{id}".lower()
        clone_instance_id = f"{clone_cluster_id}-primary".lower()

        self.notifications_topic = notifications_topic or Topic(self, "Notifications")

        self.clone_secret = DatabaseSecret(
            self, "ClonedClusterSecret", username=source_cluster_master_username
        )

        db_subnet_group = SubnetGroup(
            self,
            "SubnetGroup",
            description=f"Subnet group for {clone_cluster_id}",
            vpc=source_cluster_vpc,
            vpc_subnets=SubnetSelection(subnets=source_cluster_vpc.private_subnets),
        )

        self.cluster_sg = SecurityGroup(self, "CloneClusterSG", vpc=source_cluster_vpc)

        rule_input = {
            "SourceDBClusterIdentifier": source_cluster.cluster_identifier,
            "TargetDBClusterIdentifier": clone_cluster_id,
            "TargetDBInstanceIdentifier": clone_instance_id,
            "TargetDBSubnetGroupName": db_subnet_group.subnet_group_name,
            "TargetDBInstanceClass": clone_db_instance_class,
            "TargetVpcSecurityGroupIds": [self.cluster_sg.security_group_id],
            "TargetDBClusterParameterGroupName": clone_cluster_parameter_group.ref,
            "TargetDBClusterInstanceParameterGroupName": clone_instance_parameter_group.ref,
            "Port": source_cluster.cluster_endpoint.port,
            "TargetTags": tag_list,
        }

        boto3_lambda_layer = Boto3LambdaLayer(self, "BotoLayer").layer

        cluster_clone_lambda = PythonFunction(
            self,
            "AuroraCloneLambda",
            runtime=Runtime.PYTHON_3_9,
            handler="lambda_handler",
            timeout=Duration.minutes(15),
            layers=[boto3_lambda_layer],
            entry=self.LAMBDA_SOURCE_DIR,
            index="aurora_clone.py",
        )

        cluster_clone_lambda.add_to_role_policy(
            PolicyStatement(
                actions=[
                    "rds:RestoreDBClusterToPointInTime",
                    "rds:CreateDBInstance",
                    "rds:AddTagsToResource",
                ],
                resources=[
                    f"arn:aws:rds:{Stack.of(self).region}:{Stack.of(self).account}:cluster:{source_cluster.cluster_identifier}",
                    f"arn:aws:rds:{Stack.of(self).region}:{Stack.of(self).account}:cluster-pg:*",
                    f"arn:aws:rds:{Stack.of(self).region}:{Stack.of(self).account}:pg:*",
                    f"arn:aws:rds:{Stack.of(self).region}:{Stack.of(self).account}:subgrp:*",
                    f"arn:aws:rds:{Stack.of(self).region}:{Stack.of(self).account}:cluster:{clone_cluster_id}",
                    f"arn:aws:rds:{Stack.of(self).region}:{Stack.of(self).account}:db:{clone_instance_id}",
                ],
            ),
        )

        cluster_clone_lambda.add_to_role_policy(
            PolicyStatement(
                actions=[
                    "rds:DescribeDBClusters",
                    "rds:DescribeDBInstances",
                    "rds:DescribeDBClusterEndpoints",
                ],
                resources=["*"],
            ),
        )

        cluster_clone_lambda.add_to_role_policy(
            PolicyStatement(
                actions=[
                    "kms:DescribeKey",
                    "kms:CreateGrant",
                ],
                resources=["*"],
            ),
        )

        cluster_status_lambda = PythonFunction(
            self,
            "AuroraStatusCheckLambda",
            runtime=Runtime.PYTHON_3_9,
            handler="lambda_handler",
            layers=[boto3_lambda_layer],
            entry=self.LAMBDA_SOURCE_DIR,
            index="aurora_check_status.py",
        )

        cluster_status_lambda.add_to_role_policy(
            PolicyStatement(
                resources=["*"],
                actions=["rds:DescribeDBClusters"],
            )
        )

        aurora_delete_clone_lambda = PythonFunction(
            self,
            "AuroraDeleteClusterLambda",
            runtime=Runtime.PYTHON_3_9,
            timeout=Duration.minutes(15),
            layers=[boto3_lambda_layer],
            handler="lambda_handler",
            entry=self.LAMBDA_SOURCE_DIR,
            index="aurora_delete_clone.py",
        )

        aurora_delete_clone_lambda.add_to_role_policy(
            PolicyStatement(
                actions=[
                    "rds:DeleteDBCluster",
                    "rds:DeleteDBInstance",
                ],
                resources=[
                    f"arn:aws:rds:{Stack.of(self).region}:{Stack.of(self).account}:cluster:{clone_cluster_id}",
                    f"arn:aws:rds:{Stack.of(self).region}:{Stack.of(self).account}:db:{clone_instance_id}",
                ],
            )
        )
        aurora_delete_clone_lambda.add_to_role_policy(
            PolicyStatement(
                actions=[
                    "rds:DescribeDBClusters",
                    "rds:DescribeDBInstances",
                ],
                resources=["*"],
            )
        )

        # state machine
        check_cloned_cluster_job = LambdaInvoke(
            self,
            "GetCloneClusterStatus",
            payload=TaskInput.from_object(
                {
                    "TargetDBClusterIdentifier": clone_cluster_id,
                }
            ),
            lambda_function=cluster_status_lambda,
            output_path="$.Payload",
        )

        check_source_cluster_job = LambdaInvoke(
            self,
            "GetSourceClusterStatus",
            payload=TaskInput.from_object(
                {"TargetDBClusterIdentifier": source_cluster.cluster_identifier}
            ),
            lambda_function=cluster_status_lambda,
            output_path="$.Payload",
        )

        delete_cloned_cluster_job = LambdaInvoke(
            self,
            "DeleteClonedCluster",
            payload=TaskInput.from_object(
                {
                    "TargetDBClusterIdentifier": clone_cluster_id,
                    "TargetDBInstanceIdentifier": clone_instance_id,
                }
            ),
            lambda_function=aurora_delete_clone_lambda,
            result_path=JsonPath.DISCARD,
        )

        clone_cluster_job = LambdaInvoke(
            self,
            "AuroraClone",
            payload=TaskInput.from_object(rule_input),
            lambda_function=cluster_clone_lambda,
        )

        notification_job = SnsPublish(
            self,
            "Publish to SNS",
            result_path=JsonPath.DISCARD,
            topic=self.notifications_topic,
            message=TaskInput.from_json_path_at("$.Payload.message"),
        )
        is_success = Choice(self, "Success?")
        notification_job.next(
            is_success.when(
                Condition.string_equals("$.Payload.status", "clone-complete"),
                Pass(self, "Pass"),
            ).otherwise(Fail(self, "Fail"))
        )

        source_cluster_available = Choice(self, "Source cluster available?")

        wait_for_source_cluster_job = Wait(
            self,
            "Wait 5m for source cluster to boot",
            time=WaitTime.duration(Duration.minutes(5)),
        )

        cloned_cluster_exists = Choice(self, "Cloned Cluster exists?")

        wait_step = Wait(
            self,
            "Wait 30s",
            time=WaitTime.duration(Duration.seconds(30)),
        )

        modify_cluster_password = ModifyDBClusterPassword(
            self,
            "ModifyClonedClusterPassword",
            cluster_id=clone_cluster_id,
            secret=self.clone_secret,
        )

        modify_clone_password_task = LambdaInvoke(
            self,
            "ModifyClusterPassword",
            lambda_function=modify_cluster_password.lambda_funct,
            result_path=JsonPath.DISCARD,  # pass the input through
            payload=TaskInput.from_object(
                {
                    "secret_name": self.clone_secret.secret_name,
                    "cluster_identifier": JsonPath.string_at("$.Payload.cluster_identifier"),
                    "source_cluster": source_cluster.cluster_identifier,
                    "endpoint": JsonPath.string_at("$.Payload.endpoint"),
                }
            ),
        )
        clone_cluster_job.next(modify_clone_password_task.next(notification_job))

        chain = Chain.start(check_source_cluster_job).next(
            source_cluster_available.when(
                Condition.string_equals("$.status", "starting"),
                wait_for_source_cluster_job.next(check_source_cluster_job),
            )
            .when(
                Condition.string_equals("$.status", "stopped"),
                notification_job,
            )
            .when(
                Condition.string_equals("$.status", "available"),
                check_cloned_cluster_job.next(
                    cloned_cluster_exists.when(
                        Condition.string_equals("$.status", "available"),
                        delete_cloned_cluster_job.next(clone_cluster_job),
                    )
                    .when(
                        Condition.string_equals("$.status", "creating"),
                        wait_step.next(check_cloned_cluster_job),
                    )
                    .when(Condition.string_equals("$.status", "deleting"), wait_step)
                    .when(Condition.string_equals("$.status", "not-found"), clone_cluster_job)
                    .otherwise(notification_job)
                ),
            )
            .otherwise(notification_job)
        )

        aurora_clone_state_machine = StateMachine(
            self,
            "AuroraCloneStateMachine",
            definition=chain,
            timeout=Duration.minutes(30),
        )

        self.event_rule = Rule(
            self,
            "Rule",
            schedule=clone_schedule,
        )

        self.event_rule.add_target(
            SfnStateMachine(
                aurora_clone_state_machine,
                input=RuleTargetInput.from_object(rule_input),
            )
        )

        self.clone_cluster_id = clone_cluster_id
        self.clone_instance_id = clone_instance_id

        CfnOutput(
            self, "StateMachineName", value=aurora_clone_state_machine.state_machine_name
        )
        CfnOutput(self, "CloneClusterSecretName", value=self.clone_secret.secret_name)
        CfnOutput(self, "NotificationTopicArn", value=self.notifications_topic.topic_arn)
        CfnOutput(self, "CloneClusterId", value=clone_cluster_id)
        CfnOutput(self, "CloneClusterInstanceId", value=clone_instance_id)

    def allow_from(self, *args: IConnectable):
        for peer in args:
            self.cluster_sg.connections.allow_from(peer, port_range=Port.all_traffic())
