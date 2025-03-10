import argparse
import time
import logging
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger("KeyspaceWrapper")


class KeyspaceWrapper:
    """Encapsulates Amazon Keyspaces (for Apache Cassandra) keyspace and table actions."""

    def __init__(self, keyspaces_client):
        """
        :param keyspaces_client: A Boto3 Amazon Keyspaces client.
        """
        self.keyspaces_client = keyspaces_client

    @classmethod
    def from_client(cls, aws_access_key, aws_secret_key, aws_region):
        session = boto3.Session(
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=aws_region
        )
        keyspaces_client = session.client('keyspaces')
        return cls(keyspaces_client)

    def get_table(self, ks_name, table_name):
        """
        Gets data about a table in the keyspace.

        :param table_name: The name of the table to look up.
        :return: Data about the table.
        """
        try:
            response = self.keyspaces_client.get_table(
                keyspaceName=ks_name, tableName=table_name)
            self.table_name = table_name
        except ClientError as err:
            if err.response['Error']['Code'] == 'ResourceNotFoundException':
                logger.info("Table %s does not exist.", table_name)
                self.table_name = None
                response = None
            else:
                logger.error(
                    "Couldn't verify %s exists. Here's why: %s: %s", table_name,
                    err.response['Error']['Code'], err.response['Error']['Message'])
                raise
        return response

    def restore_table(self, ks_name, table_name, restore_timestamp, restored_table_name=""):
        """
        Restores the table to a previous point in time. The table is restored
        to a new table in the same keyspace.
        :param restore_timestamp: The point in time to restore the table. This time
                                  must be in UTC format.
        :return: The name of the restored table.
        """
        # if restored_table_name is None or restored_table_name == "":
        #     restored_table_name = str(uuid.uuid4().hex)
        #     logger.info(
        #         f"Restored table name is not specified, generated name is: {restored_table_name}")

        try:
            if restore_timestamp is None:
                restore_timestamp = ""
                self.keyspaces_client.restore_table(
                    sourceKeyspaceName=ks_name, sourceTableName=table_name,
                    targetKeyspaceName=ks_name, targetTableName=restored_table_name)
            else:
                self.keyspaces_client.restore_table(
                    sourceKeyspaceName=ks_name, sourceTableName=table_name,
                    targetKeyspaceName=ks_name, targetTableName=restored_table_name, restoreTimestamp=restore_timestamp)
        except ClientError as err:
            logger.error(
                "Couldn't restore table %s. Here's why: %s: %s", restore_timestamp,
                err.response['Error']['Code'], err.response['Error']['Message'])
            raise
        else:
            return restored_table_name

    def wait_table_restored(self, ks_name, restored_table_name, max_retries, retry_interval) -> bool:
        """
        Wait for a table to be restored

        :param keyspace: The keyspace that holds the table.
        :param table: The table to wait.
        """
        status = ""
        for retry in range(max_retries + 1):
            logger.info(
                f"Waiting the table {restored_table_name} to be restored, retries left: {max_retries - retry}")
            response = self.get_table(ks_name, restored_table_name)
            if response is not None:
                status = response["status"]
            if (response is None or status.lower() == "restoring") and retry < max_retries:
                time.sleep(retry_interval)
            else:
                break

        if status.lower() == "active":
            return True
        elif status.lower() == "restoring":
            logger.error(
                f"Timeout reached waiting for the table {restored_table_name} to be restored.")
            return False
        else:
            logger.error(
                f"Failed to restore the table {restored_table_name}, final status: {status}")
            return False


def run_aws_restore(ks_name, table_name, restored_table_name, aws_access_key, aws_secret_key, region):
    try:
        max_retries = 360
        retry_interval = 10
        restore_timestamp = None
        wrapper = KeyspaceWrapper.from_client(
            aws_access_key, aws_secret_key, region)
        restored_table = wrapper.restore_table(
            ks_name, table_name, restore_timestamp, restored_table_name=restored_table_name)
        if not wrapper.wait_table_restored(ks_name, restored_table, max_retries, retry_interval):
            logger.error(f"Failed to restore table {table_name}")
            exit(1)
        else:
            logger.info(
                f"Restore has finished successfully. Restored table name: {restored_table}")
            exit(0)
    except Exception:
        logging.exception("Something went wrong with the restore.")
        exit(1)
