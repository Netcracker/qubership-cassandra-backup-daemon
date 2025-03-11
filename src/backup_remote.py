#!/usr/bin/env python3
from ssl import CERT_REQUIRED, PROTOCOL_TLSv1_2, SSLContext
import subprocess
import os
import argparse
import json
from pathlib import Path
import logging

from cassandra import ConsistencyLevel
from cassandra.auth import PlainTextAuthProvider
from cassandra.cluster import Cluster, ExecutionProfile, EXEC_PROFILE_DEFAULT

excluded_keyspaces = ["system", "system_distributed", "system_auth",
                      "system_schema", "system_virtual_schema", "system_views", "system_traces"]

CASSANDRA_HOME_BIN = "/opt/cassandra/bin"
CASSANDRA_DIR = "/var/lib/cassandra/data"
METADATA_FILE = f"{CASSANDRA_DIR}/backup/metadata.json"

logger = logging.getLogger(__name__)


class CassandraClient(object):
    def __init__(self, host, username="admin", password="admin", port=9042,
                 tls_enabled="False", consistency_level=ConsistencyLevel.ONE, connect_timeout=20, request_timeout=20):
        self.host = [host]
        self.port = int(port)
        self.username = username
        self.password = password
        self.connect_timeout = connect_timeout
        self.request_timeout = request_timeout
        self.session = None
        self.consistency_level = consistency_level

        auth_provider = PlainTextAuthProvider(
            username=self.username, password=self.password)
        profile = ExecutionProfile(
            consistency_level=self.consistency_level,
            request_timeout=self.request_timeout
        )
        ssl_context = None
        if tls_enabled.lower() == "true":
            ssl_context = SSLContext(PROTOCOL_TLSv1_2)
            ssl_context.load_verify_locations(
                os.getenv("TLS_ROOTCERT", f"{CASSANDRA_DIR}/../configuration/ca.crt"))
            ssl_context.verify_mode = CERT_REQUIRED

        self.cluster = Cluster(self.host, execution_profiles={
            EXEC_PROFILE_DEFAULT: profile}, auth_provider=auth_provider,
            ssl_context=ssl_context, connect_timeout=self.connect_timeout)
        self.session = self.cluster.connect()

    def execute_query(self, query):
        try:
            rows = self.session.execute(query)
            return rows
        except Exception as e:
            logger.error(f"Failed to execute the query: {query}, error is: {e}")
            raise e

    def get_keyspaces_to_backup(self):
        keyspaces = self.execute_query(
            "select keyspace_name from system_schema.keyspaces")
        final_list = [
            k.keyspace_name for k in keyspaces if k.keyspace_name not in excluded_keyspaces]
        return final_list

    def get_keyspace_roles(self, keyspace):
        roles = []
        permissions = []
        rows = self.execute_query(
            f"select role, permissions from system_auth.role_permissions where resource = 'data/{keyspace}' allow filtering")
        for row in rows:
            roles.append(row.role)
            permissions.append(row.permissions)

        return roles, permissions

    def get_keyspace_schema(self, keyspace):
        rows = self.execute_query(
            f"select durable_writes, replication from system_schema.keyspaces where keyspace_name = '{keyspace}'")
        if rows is None:
            return None
        replication = {}

        for settings in rows:
            for k in settings.replication.keys():
                replication[k] = settings.replication[k]
            replication = json.dumps(replication).replace('"', "\'")
            return f"CREATE KEYSPACE IF NOT EXISTS {keyspace} WITH replication = {replication}  AND durable_writes = {settings.durable_writes};"

        return None

    def get_salted_hash(self, role_name):
        row = self.execute_query(
            f"select salted_hash from system_auth.roles where role = '{role_name}'")
        if row is None:
            return None
        return row[0].salted_hash

    def close(self):
        self.session.shutdown()
        self.cluster.shutdown()


def execute_command(command):
    logger.info(f"Executing: {command}")
    p = subprocess.run(command, stderr=subprocess.PIPE)
    if p.returncode != 0:
        raise ChildProcessError(f"command {command} has failed with err code: {p.returncode}, err: {p.stderr.decode() if p.stderr is not None else '' }")


def execute_snapshot(snapshot_name, keyspace, table):
    commands_list = [f"{CASSANDRA_HOME_BIN}/nodetool",
                     "snapshot", "-t", snapshot_name]
    if table is not None:
        commands_list = commands_list + ["-cf", table]
    execute_command(commands_list + [keyspace])


def delete_snapshot(snapshot_name):
    execute_command([f"{CASSANDRA_HOME_BIN}/nodetool",
                    "clearsnapshot", "-t", snapshot_name])


def make_archive(filepath, dirs: list[str]):
    execute_command(["bsdtar", "-cvzf", filepath]+dirs)


def walklevel(path, depth=1):
    """It works just like os.walk, but you can pass it a level parameter
       that indicates how deep the recursion will go.
       If depth is 1, the current directory is listed.
       If depth is 0, nothing is returned.
       If depth is -1 (or less than 0), the full depth is walked.
    """
    # If depth is negative, just walk
    # Not using yield from for python2 compat
    # and copy dirs to keep consistant behavior for depth = -1 and depth = inf
    if depth < 0:
        for root, dirs, files in os.walk(path):
            yield root, dirs[:], files
        return
    elif depth == 0:
        return
    base_depth = path.rstrip(os.path.sep).count(os.path.sep)
    for root, dirs, files in os.walk(path):
        yield root, dirs[:], files
        cur_depth = root.count(os.path.sep)
        if base_depth + depth <= cur_depth:
            del dirs[:]


def find_snapshot_dirs(cassandra_data_dir, snapshot_name):
    dirs = []
    for root, _, _ in walklevel(cassandra_data_dir, 4):
        if snapshot_name in root:
            dirs.append(root)
    return dirs


def backup_roles(keyspace, cassandraClient: CassandraClient, dirname: str):
    if keyspace in excluded_keyspaces:
        return True
    roles, permissions = cassandraClient.get_keyspace_roles(keyspace)
    if len(roles) == 0 or len(permissions) == 0:
        logger.info(
            f"Can't backup roles. There are no any roles and permissions for keyspace {keyspace}")
        return False
    # only admin user
    elif len(roles) == 1:
        return True

    for indx, role in enumerate(roles):
        output = ""
        if role == "cassandra" or role == cassandraClient.username:
            continue

        salted_hash = cassandraClient.get_salted_hash(role)
        if salted_hash is None:
            logger.error(f"Failed to get saltad_hash for role {role}")
            return False

        output += f"CREATE ROLE IF NOT EXISTS '{role}' WITH PASSWORD = '{role}' AND LOGIN = true;\n"
        output += f"UPDATE system_auth.roles SET salted_hash = '{salted_hash}' WHERE role = '{role}' IF EXISTS;\n"
        for permission in permissions[indx]:
            output += f"GRANT {permission} on KEYSPACE {keyspace} to '{role}';\n"

        with open(f"{dirname}/bkp_role_{role}.cql", "a") as f:
            f.write(output)


def backup_keyspace_schema(filename, schema):
    if schema is None:
        raise ValueError("Failed to write schema, it is empty")
    with open(filename, "w") as f:
        f.write(schema)


def prepare_metadata(keyspace, tables, backup_dir):
    all_tables = False
    # if backup was run for the whole keyspace, get table names from snapshot directory
    if tables is None or len(tables) == 0:
        all_tables = True
        for i in range(3):
            backup_dir = os.path.dirname(backup_dir)
        tables = os.listdir(backup_dir)
        for i in range(len(tables)):
            tables[i] = tables[i].split('-')[0]

    return {
        "keyspace": keyspace,
        "all_tables": all_tables,
        "tables": tables
    }


def get_tables_for_backup(keyspace):
    if isinstance(keyspace, dict):
        keyspace_name = list(keyspace.keys())[0]
        tables = keyspace[keyspace_name]["tables"]
        return keyspace_name, tables

    return keyspace, None


def main():
    parser = argparse.ArgumentParser(description='Cassandra backup')
    parser.add_argument('-u', dest='username',
                        help='Cassandra username', required=True)
    parser.add_argument('-p', dest='password',
                        help='Cassandra password', required=True)
    parser.add_argument('-s', dest='tls_enabled',
                        help='Enable TLS', default=False)
    parser.add_argument('-d', dest='keyspaces', help='Keyspaces to backup')
    parser.add_argument('-t', dest='timestamp',
                        help='Timestamp for backup', required=True)
    parser.add_argument('-ct', dest='connect_timeout', help='Connect timeout')
    parser.add_argument('-rt', dest='request_timeout', help='Request timeout')

    args = parser.parse_args()
    Path(f"{CASSANDRA_DIR}/backup").mkdir(parents=True, exist_ok=True)

    cassandraClient = CassandraClient(
        "localhost", username=args.username, password=args.password,
        tls_enabled=args.tls_enabled, connect_timeout=int(args.connect_timeout), request_timeout=int(args.request_timeout))

    metadata = list()

    keyspaces = args.keyspaces
    if keyspaces is None or keyspaces == "":
        keyspaces = cassandraClient.get_keyspaces_to_backup()
        if keyspaces is None or len(keyspaces) == 0:
            logger.error("Failed to retrieve keyspaces, exiting")
            exit(1)
    else:
        keyspaces = json.loads(keyspaces)

    for keyspace in keyspaces:
        keyspace_name, tables = get_tables_for_backup(keyspace)

        backup_name = f"{keyspace_name}-{args.timestamp}"
        backup_filepath = f"{CASSANDRA_DIR}/backup/{backup_name}.tar.gz"

        if tables is None or len(tables) == 0:
            execute_snapshot(backup_name, keyspace_name, None)
        else:
            for table in tables:
                execute_snapshot(backup_name, keyspace_name, table)

        dirs = find_snapshot_dirs(CASSANDRA_DIR, backup_name)
        if len(dirs) == 0:
            logger.info(
                f"Failed to find snapshot directories. Probably keyspace {keyspace_name} is empty.")
            dirname = f"{CASSANDRA_DIR}/{keyspace_name}/{backup_name}"
            os.makedirs(dirname)
            dirs.append(dirname)

        metadata.append(prepare_metadata(keyspace_name, tables, dirs[0]))

        try:
            backup_roles(keyspace_name, cassandraClient, dirs[0])
            backup_keyspace_schema(
                f"{dirs[0]}/tsschema.cql", cassandraClient.get_keyspace_schema(keyspace_name))

            make_archive(backup_filepath, dirs)
        except Exception as e:
            delete_snapshot(backup_name)
            logger.error(f"Backup has failed: {e}")
            exit(1)
        delete_snapshot(backup_name)
        logger.info(
            f"Backup for keyspace {keyspace_name} is successful: {backup_filepath}")

    try:
        with open(METADATA_FILE, 'w+') as f:
            f.write(json.dumps(metadata))
    except Exception as e:
        logger.error(f"Backup failed while writing data to metadata.json file: {e}")
        exit(1)


if __name__ == "__main__":
    main()
