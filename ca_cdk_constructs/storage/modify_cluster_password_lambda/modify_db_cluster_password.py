import json
import os

import boto3

secret_name = os.getenv("secret_name")
region_name = os.getenv("secret_region")
cluster_identifier = os.getenv("cluster_identifier")

session = boto3.session.Session()
rds_client = session.client(service_name="rds", region_name=region_name)
secrets_client = session.client(service_name="secretsmanager", region_name=region_name)


def get_secret() -> dict:
    secret_data_response = secrets_client.get_secret_value(SecretId=secret_name)
    return json.loads(secret_data_response["SecretString"])


def handler(_event, _context):
    secret_data = get_secret()

    resp = rds_client.modify_db_cluster(
        DBClusterIdentifier=cluster_identifier,
        ApplyImmediately=True,
        MasterUserPassword=secret_data["password"],
    )
    print(resp["ResponseMetadata"])
