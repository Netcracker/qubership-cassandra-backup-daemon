#!/usr/bin/env python3
# Copyright 2024-2025 NetCracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from datetime import datetime
import os
import json
import shutil
import uuid
import logging
import glob
from src import cassandra_client, os_utils


CASSANDRA_HOME_BIN = "/opt/cassandra/bin"
CASSANDRA_DATA_DIR = os.getenv(
    "CASSANDRA_DATA_DIR", "var/lib/cassandra/data")
CASSANDRA_USERNAME = os.getenv('CASSANDRA_USERNAME')
CASSANDRA_PASSWORD = os.getenv('CASSANDRA_PASSWORD')
CASSANDRA_HOSTS = os.getenv('CASSANDRA_HOSTS')


class Restore(object):
    def __init__(self, vault, dbmap, dbs, restore_roles) -> None:
        self.dbs = dbs
        self.clone = dbmap is not None
        self.vault = vault
        self.dbmap = dbmap
        self.need_restore_roles = os_utils.str_to_bool(
            restore_roles) if restore_roles is not None else False
        self.username = os.getenv('CASSANDRA_USERNAME')
        self.password = os.getenv('CASSANDRA_PASSWORD')
        self.connect_timeout = os.getenv('CONNECT_TIMEOUT', 20)
        self.request_timeout = os.getenv('REQUEST_TIMEOUT', 20)
        self.tls_enabled = os_utils.str_to_bool(
            os.getenv("TLS_ENABLED", False))
        self.cassandra_bin_dir = "/opt/cassandra/bin"
        self.cassandra_data_dir = os.getenv(
            "CASSANDRA_DATA_DIR", "var/lib/cassandra/data")
        self.cassandra_hosts = os_utils.reformat_hostnames(
            os.getenv('CASSANDRA_HOSTS'))
        self.cassandra_client = cassandra_client.CassandraClient(
            self.cassandra_hosts, username=self.username, password=self.password, tls_enabled=self.tls_enabled,
            connect_timeout=int(self.connect_timeout), request_timeout=int(self.request_timeout))

        if self.tls_enabled:
            os.environ['SSL_CERTFILE'] = os.getenv("TLS_ROOTCERT")
            self.loader_ssl_args = ['-ts', '/opt/cassandra/truststore.jks',
                                    '-ks', '/opt/cassandra/truststore.jks', '-tspw', 'cassandra', '-kspw', 'cassandra']
        self.log = logging.getLogger(__name__)

    def get_tables_for_restore(self, databases, keyspace):
        number_of_dbs = len(databases)
        tables = []
        for i in range(number_of_dbs):
            if isinstance(databases[i], str) and databases[i] == keyspace:
                tables = ""
            elif isinstance(databases[i], dict) and list(databases[i].keys())[0] == keyspace:
                tables = databases[i][keyspace]["tables"]

        number_of_tbs = len(tables)
        tbs = ""

        if number_of_tbs > 0:
            for j in range(number_of_tbs):
                tbs += f" {tables[j]}"

        return tbs.strip()

    def restore_roles(self, keyspace_path, keyspace_name):
        self.log.info("Start restoring roles")
        cql_files = [
            os.path.join(dp, f)
            for dp, dn, filenames in os.walk(keyspace_path)
            for f in filenames
            if f.startswith("bkp_role_") and f.endswith(".cql")
        ]

        for role in cql_files:
            if self.clone:
                new_keyspace_name = json.loads(
                    self.dbmap).get(keyspace_name, "")
                os_utils.replace_in_file(
                    role, keyspace_name, new_keyspace_name)
            self.cassandra_client.run_cql_file(role)

    def restore_keyspace(self, keyspace_snapshot_dir, keyspace_name, tables_for_restore, new_keyspace_name=None):
        self.log.debug(f"Restoring : {keyspace_snapshot_dir}")
        tables_schema_file: str = os_utils.find_file_in_directory(
            keyspace_snapshot_dir, "schema.cql")

        if tables_schema_file is None or tables_schema_file == '':
            self.log.info("no tables to restore, skipping")
            return

        table_path = os.path.realpath(
            os.path.join(keyspace_snapshot_dir, "..", ".."))

        self.log.debug(f"table_path: {table_path}")
        if self.clone:
            generated_uuid = str(uuid.uuid4())
            os_utils.replace_uuid(tables_schema_file, keyspace_name,
                                  new_keyspace_name, generated_uuid)
            self.cassandra_client.run_cql_file(tables_schema_file)
            table_path = os_utils.get_new_table_path(
                table_path, generated_uuid)
            self.log.debug(f"get_new_table_path: {table_path}")
            shutil.move(os.path.join(
                keyspace_snapshot_dir), table_path)

        else:
            # drop and create table
            table_name = os.path.basename(table_path).split("-")[0]
            self.log.debug(f"Tables for restore: {tables_for_restore}")
            if not tables_for_restore or table_name in tables_for_restore:
                self.cassandra_client.drop_table(keyspace_name, table_name)
            self.cassandra_client.run_cql_file(tables_schema_file)

            # copy files to final location
            for item in os.listdir(keyspace_snapshot_dir):
                source_path = os.path.join(keyspace_snapshot_dir, item)
                destination_path = os.path.join(table_path, item)
                shutil.move(source_path, destination_path)

        self.sstable_loader(table_path)

    def sstable_loader(self, table_path):
        hostname = ",".join(f"{hostname}" for hostname in self.cassandra_hosts)
        self.log.debug(f"Loading table {table_path} to {hostname}")
        command = [
            f"{self.cassandra_bin_dir}/sstableloader",
            "-u", self.username,
            "-pw", self.password,
            "-d", hostname,
            table_path
        ]
        if self.tls_enabled:
            command.extend(self.loader_ssl_args)

        os_utils.execute_command(command)

    def restore(self):
        host_archives = os_utils.find_host_archives(self.vault)

        for keyspace_name in self.dbs:
            # find keyspace backups on all hosts
            backups = [
                x for x in host_archives if keyspace_name == x["keyspace"]]
            keyspace_dropped = False
            for backup in backups:
                path = backup["path"]
                backup_name = backup["archive"][:-7]  # cat .tar.gz
                tempDir = os_utils.extract_to_tmp_dir(path, backup["archive"])
                if tempDir == "":
                    continue

                keyspace_path = os.path.join(
                    tempDir, self.cassandra_data_dir, keyspace_name)

                metaobject = get_metadata_object(path, keyspace_name)

                tables_for_restore = self.get_tables_for_restore(
                    self.dbs, keyspace_name)
                if tables_for_restore:
                    check_tables_for_restore(metaobject, tables_for_restore)

                keyspace_schema_file: str = os_utils.find_file_in_directory(
                    keyspace_path, "tsschema.cql")

                new_keyspace_name = None

                if not self.clone:
                    if not keyspace_dropped:
                        if metaobject.get("all_tables", False) and not tables_for_restore:
                            if self.need_restore_roles:
                                self.log.info(
                                    f"Dropping keyspace: {keyspace_name}")
                                self.cassandra_client.drop_keyspace(
                                    keyspace_name)
                            keyspace_dropped = True

                        self.log.info(f"Creating keyspace: {keyspace_name}")
                        self.cassandra_client.run_cql_file(
                            keyspace_schema_file)

                elif self.clone:
                    new_keyspace_name = json.loads(
                        self.dbmap).get(keyspace_name, "")
                    self.log.debug(f"new_keyspace_name: {new_keyspace_name}")
                    os_utils.replace_in_file(keyspace_schema_file,
                                             keyspace_name, new_keyspace_name)
                    self.cassandra_client.run_cql_file(keyspace_schema_file)

                    new_keyspace_path = os.path.join(
                        tempDir, self.cassandra_data_dir, new_keyspace_name)
                    shutil.move(keyspace_path, new_keyspace_path)
                    keyspace_path = new_keyspace_path
                    self.log.debug(f"new_keyspace_path: {keyspace_path}")
                    if not keyspace_dropped and not self.need_restore_roles:
                        self.log.info(
                            f"Dropping all tables: {new_keyspace_name}")
                        self.cassandra_client.drop_all_tables(
                            new_keyspace_name)
                        keyspace_dropped = True

                if self.need_restore_roles:
                    self.restore_roles(
                        keyspace_path=keyspace_path, keyspace_name=keyspace_name)
                self.log.info("Start restoring tables.")
                keyspace_snapshots = glob.glob(
                    f"{keyspace_path}/**/{backup_name}", recursive=True)

                try:
                    for keyspace_snapshot in keyspace_snapshots:
                        self.restore_keyspace(
                            keyspace_snapshot, keyspace_name, tables_for_restore, new_keyspace_name)

                except Exception as e:
                    raise e
                finally:
                    self.log.info(f"Removing temp folder {tempDir}")
                    shutil.rmtree(tempDir)
        self.log.info("Restore finished")


def cluster_backup(databases, vault, tls_enabled, cassandra_username, cassandra_password):
    logging.info("Starting backup")
    logging.info("Databse List: {databases}, vault: {vault}")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    ansible_command = [
        "ansible-playbook",
        "-vvv",
        "-i",
        "/opt/backup/hosts",
        "/opt/backup/playbooks/backup.yaml",
        "--extra-vars",
        (
            f'vault={vault} '
            f'cassandra_user={cassandra_username} '
            f'cassandra_password={cassandra_password} '
            f'ssl={tls_enabled} '
            f'databases={"" if databases is None else databases} '
            f'timestamp={timestamp} '
            f'connect_timeout={os.getenv("CONNECT_TIMEOUT", 20)} '
            f'request_timeout={os.getenv("REQUEST_TIMEOUT", 20)}'
        )
    ]
    os_utils.execute_command(ansible_command)


def get_metadata_object(directory, keyspace_name):
    json_file = os.path.join(directory, 'metadata.json')

    with open(json_file) as f:
        metadata = json.load(f)

    for obj in metadata:
        if obj.get('keyspace') == keyspace_name:
            return obj

    return None


def check_tables_for_restore(metaobject, tables_for_restore, backup_name):
    tib = metaobject.get("tables", [])
    not_found = [table for table in tables_for_restore if table not in tib]

    if not_found:
        raise LookupError(
            f"Tables {not_found} don't exist in backup {backup_name}")


def list_databases(vault):
    os_utils.add_custom_vars(vault)
    database_names = []
    for root, dirs, files in os.walk(vault):
        for file in files:
            if file.endswith('.tar.gz'):
                database_name = file.split('-')[0]
                database_names.append(database_name)

    return database_names
