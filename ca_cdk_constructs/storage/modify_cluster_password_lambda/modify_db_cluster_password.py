import json

import boto3

session = boto3.session.Session()
rds_client = session.client(service_name="rds")
secrets_client = session.client(service_name="secretsmanager")


def get_secret(secret_arn: str) -> dict:
    secret_data_response = secrets_client.get_secret_value(SecretId=secret_arn)
    return json.loads(secret_data_response["SecretString"])


def handler(event, _context):
    payload = event.copy()
    secret_data = get_secret(payload["secret_arn"])

    resp = rds_client.modify_db_cluster(
        DBClusterIdentifier=payload["cluster_identifier"],
        ApplyImmediately=True,
        MasterUserPassword=secret_data["password"],
    )
    print(json.dumps({"modify_cluster": resp["ResponseMetadata"]}))

    cluster_available_waiter = rds_client.get_waiter("db_cluster_available")
    cluster_available_waiter.wait(
        DBClusterIdentifier=payload["cluster_identifier"],
        WaiterConfig={"Delay": 30, "MaxAttempts": 30},  # sec
    )

    try:
        db_name = resp["DBCluster"]["DatabaseName"]
    except KeyError:
        # the db name was not set when creating the source cluster
        # use the defaults: https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/Aurora.CreateInstance.html
        if "postgres" in resp["DBCluster"]["Engine"]:
            db_name = "postgres"
        else:
            db_name = ""

    secrets_client.update_secret(
        SecretId=payload["secret_arn"],
        SecretString=json.dumps(
            {
                "dbClusterIdentifier": resp["DBCluster"]["DBClusterIdentifier"],
                "password": secret_data["password"],
                "dbname": db_name,
                "engine": resp["DBCluster"]["Engine"],
                "port": resp["DBCluster"]["Port"],
                "host": resp["DBCluster"]["Endpoint"],
                "username": resp["DBCluster"]["MasterUsername"],
            }
        ),
    )
