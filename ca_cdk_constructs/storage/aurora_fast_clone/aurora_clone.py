import boto3

client = boto3.client("rds")


def lambda_handler(event, context):
    source_db_cluster_identifier = event["SourceDBClusterIdentifier"]

    target_db_cluster_identifier = event["TargetDBClusterIdentifier"]
    target_db_instance_identifier = event["TargetDBInstanceIdentifier"]
    target_db_subnet_group_name = event["TargetDBSubnetGroupName"]
    target_db_instance_class = event["TargetDBInstanceClass"]
    target_vpc_security_group_ids = event["TargetVpcSecurityGroupIds"]
    target_db_cluster_parameter_group_name = event["TargetDBClusterParameterGroupName"]
    target_db_cluster_instance_parameter_group_name = event[
        "TargetDBClusterInstanceParameterGroupName"
    ]
    cluster_query = client.describe_db_clusters(
        DBClusterIdentifier=source_db_cluster_identifier
    )

    tags = cluster_query["DBClusters"][0]["TagList"] + event["TargetTags"]
    # deduplicate tags and ignore these starting with aws:
    target_tags = {}
    for entry in tags:
        if not entry["Key"].startswith("aws:"):
            target_tags[entry["Key"]] = entry["Value"]

    target_tags["Name"] = target_db_cluster_identifier
    tag_list = [{"Key": k, "Value": v} for k, v in target_tags.items()]

    port = int(event["Port"])

    cluster_clone_response = client.restore_db_cluster_to_point_in_time(
        DBClusterIdentifier=target_db_cluster_identifier,
        RestoreType="copy-on-write",
        SourceDBClusterIdentifier=source_db_cluster_identifier,
        UseLatestRestorableTime=True,
        Port=port,
        DBSubnetGroupName=target_db_subnet_group_name,
        VpcSecurityGroupIds=target_vpc_security_group_ids,
        Tags=tag_list,
        EnableIAMDatabaseAuthentication=False,
        DBClusterParameterGroupName=target_db_cluster_parameter_group_name,
        DeletionProtection=False,
        CopyTagsToSnapshot=True,
    )
    clone_cluster_id = cluster_clone_response["DBCluster"]["DBClusterIdentifier"]
    cluster_available_waiter = client.get_waiter("db_cluster_available")

    cluster_available_waiter.wait(
        DBClusterIdentifier=clone_cluster_id,
        WaiterConfig={"Delay": 30, "MaxAttempts": 30},  # sec
    )

    create_instance_response = client.create_db_instance(
        DBInstanceIdentifier=target_db_instance_identifier,
        Engine=cluster_clone_response["DBCluster"]["Engine"],
        DBParameterGroupName=target_db_cluster_instance_parameter_group_name,
        DBInstanceClass=target_db_instance_class,
        DBClusterIdentifier=target_db_cluster_identifier,
        Tags=tag_list,
    )

    instance_available_waiter = client.get_waiter("db_instance_available")

    instance_available_waiter.wait(
        DBInstanceIdentifier=create_instance_response["DBInstance"]["DBInstanceIdentifier"],
        WaiterConfig={"Delay": 30, "MaxAttempts": 30},  # sec
    )

    describe_endpoints_response = client.describe_db_cluster_endpoints(
        DBClusterIdentifier=clone_cluster_id,
        Filters=[{"Name": "db-cluster-endpoint-type", "Values": ["writer"]}],
    )
    endpoint = describe_endpoints_response["DBClusterEndpoints"][0]["Endpoint"]
    return {
        "status": "clone-complete",
        "message": f"The cluster {source_db_cluster_identifier} was cloned to {clone_cluster_id}, available at {endpoint}",
        "cluster_identifier": clone_cluster_id,
        "endpoint": describe_endpoints_response["DBClusterEndpoints"][0]["Endpoint"],
    }
