import boto3

client = boto3.client("rds")


def lambda_handler(event, context):
    payload = event.copy()

    target_db_cluster_identifier = event["TargetDBClusterIdentifier"]
    target_db_instance_identifier = event["TargetDBInstanceIdentifier"]

    try:
        client.delete_db_instance(
            DBInstanceIdentifier=target_db_instance_identifier,
            SkipFinalSnapshot=True,
            DeleteAutomatedBackups=True,
        )
        instance_waiter = client.get_waiter("db_instance_deleted")
        instance_waiter.wait(DBInstanceIdentifier=target_db_instance_identifier)
    except client.exceptions.DBInstanceNotFoundFault:
        print(f"WARN: Cluster {target_db_cluster_identifier} has no instances...")

    client.delete_db_cluster(
        DBClusterIdentifier=target_db_cluster_identifier,
        SkipFinalSnapshot=True,
    )
    waiter = client.get_waiter("db_cluster_deleted")
    waiter.wait(DBClusterIdentifier=target_db_cluster_identifier)

    payload["message"] = "deleted"
    return payload
