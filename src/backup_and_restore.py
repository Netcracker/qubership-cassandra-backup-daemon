#!/usr/bin/env python3
from datetime import datetime
import os
import json
import shutil
import logging
import glob
from src import cassandra_client, os_utils


CASSANDRA_HOME_BIN = "/opt/cassandra/bin"
CASSANDRA_DATA_DIR = os.getenv("CASSANDRA_DATA_DIR", "var/lib/cassandra/data")
CASSANDRA_USERNAME = os.getenv("CASSANDRA_USERNAME")
CASSANDRA_PASSWORD = os.getenv("CASSANDRA_PASSWORD")
CASSANDRA_HOSTS = os.getenv("CASSANDRA_HOSTS")


class Restore(object):
    def __init__(self, vault, dbmap, dbs, restore_roles) -> None:
        self.dbs = dbs
        self.clone = dbmap is not None
        self.vault = vault
        self.dbmap = dbmap
        self.need_restore_roles = os_utils.str_to_bool(
            restore_roles) if restore_roles is not None else False

        self.username = os.getenv("CASSANDRA_USERNAME")
        self.password = os.getenv("CASSANDRA_PASSWORD")
        self.connect_timeout = os.getenv("CONNECT_TIMEOUT", 20)
        self.request_timeout = os.getenv("REQUEST_TIMEOUT", 20)

        self.tls_enabled = os_utils.str_to_bool(os.getenv("TLS_ENABLED", False))
        self.cassandra_bin_dir = "/opt/cassandra/bin"
        self.cassandra_data_dir = os.getenv(
            "CASSANDRA_DATA_DIR", "var/lib/cassandra/data"
        )
        self.cassandra_hosts = os_utils.reformat_hostnames(
            os.getenv("CASSANDRA_HOSTS")
        )

        self.cassandra_client = cassandra_client.CassandraClient(
            self.cassandra_hosts,
            username=self.username,
            password=self.password,
            tls_enabled=self.tls_enabled,
            connect_timeout=int(self.connect_timeout),
            request_timeout=int(self.request_timeout),
        )

        if self.tls_enabled:
            os.environ["SSL_CERTFILE"] = os.getenv("TLS_ROOTCERT")
            self.loader_ssl_args = [
                "-ts", "/opt/cassandra/truststore.jks",
                "-ks", "/opt/cassandra/truststore.jks",
                "-tspw", "cassandra",
                "-kspw", "cassandra",
            ]

        self.log = logging.getLogger(__name__)

    def get_tables_for_restore(self, databases, keyspace):
        tables = []
        for entry in databases:
            if isinstance(entry, str) and entry == keyspace:
                return ""
            if isinstance(entry, dict) and keyspace in entry:
                tables = entry[keyspace]["tables"]

        return " ".join(tables)

    def restore_roles(self, keyspace_path, keyspace_name):
        self.log.info("Start restoring roles")
        cql_files = [
            os.path.join(dp, f)
            for dp, _, filenames in os.walk(keyspace_path)
            for f in filenames
            if f.startswith("bkp_role_") and f.endswith(".cql")
        ]

        for role in cql_files:
            if self.clone:
                new_keyspace_name = json.loads(self.dbmap).get(keyspace_name, "")
                os_utils.replace_in_file(role, keyspace_name, new_keyspace_name)
            self.cassandra_client.run_cql_file(role)

    # ✅ FIXED: proper instance method
    def strip_table_ids(self, cql_file):
        """
        Removes Cassandra 5 table IDs:
          WITH ID = <uuid>
        """
        os_utils.replace_regex_in_file(
            cql_file,
            r"\s+WITH\s+ID\s*=\s*[a-f0-9\-]+",
            ""
        )

    def restore_keyspace(self, keyspace_snapshot_dir, keyspace_name,
                          tables_for_restore, new_keyspace_name=None):

        self.log.debug(f"Restoring : {keyspace_snapshot_dir}")

        tables_schema_file = os_utils.find_file_in_directory(
            keyspace_snapshot_dir, "schema.cql"
        )

        if not tables_schema_file:
            self.log.info("No tables to restore, skipping")
            return

        table_path = os.path.realpath(
            os.path.join(keyspace_snapshot_dir, "..", "..")
        )

        if self.clone and new_keyspace_name:
            os_utils.replace_in_file(
                tables_schema_file, keyspace_name, new_keyspace_name
            )
            self.strip_table_ids(tables_schema_file)
            self.cassandra_client.run_cql_file(tables_schema_file)

            new_keyspace_path = os.path.join(
                os.path.dirname(os.path.dirname(keyspace_snapshot_dir)),
                new_keyspace_name
            )
            shutil.move(keyspace_snapshot_dir, new_keyspace_path)
            table_path = new_keyspace_path

        else:
            table_name = os.path.basename(table_path).split("-")[0]
            if not tables_for_restore or table_name in tables_for_restore:
                self.cassandra_client.drop_table(keyspace_name, table_name)

            self.cassandra_client.run_cql_file(tables_schema_file)

            for item in os.listdir(keyspace_snapshot_dir):
                shutil.move(
                    os.path.join(keyspace_snapshot_dir, item),
                    os.path.join(table_path, item),
                )

        # ✅ CRITICAL: no SSTable loading for clones
        if not self.clone:
            self.sstable_loader(table_path)
        else:
            self.log.info(
                f"Skipping sstableloader for cloned keyspace {new_keyspace_name}"
            )

    def sstable_loader(self, table_path):
        hostname = ",".join(self.cassandra_hosts)
        self.log.debug(f"Loading table {table_path} to {hostname}")

        command = [
            f"{self.cassandra_bin_dir}/sstableloader",
            "-u", self.username,
            "-pw", self.password,
            "-d", hostname,
            table_path,
        ]

        if self.tls_enabled:
            command.extend(self.loader_ssl_args)

        os_utils.execute_command(command)

    def restore(self):
        host_archives = os_utils.find_host_archives(self.vault)

        for keyspace_name in self.dbs:
            backups = [
                x for x in host_archives if keyspace_name == x["keyspace"]
            ]
            keyspace_dropped = False

            for backup in backups:
                path = backup["path"]
                backup_name = backup["archive"][:-7]
                tempDir = os_utils.extract_to_tmp_dir(path, backup["archive"])
                if not tempDir:
                    continue

                keyspace_path = os.path.join(
                    tempDir, self.cassandra_data_dir, keyspace_name
                )

                metaobject = get_metadata_object(path, keyspace_name)
                tables_for_restore = self.get_tables_for_restore(
                    self.dbs, keyspace_name
                )

                keyspace_schema_file = os_utils.find_file_in_directory(
                    keyspace_path, "tsschema.cql"
                )

                new_keyspace_name = None

                if not self.clone:
                    if not keyspace_dropped:
                        self.cassandra_client.run_cql_file(
                            keyspace_schema_file
                        )
                        keyspace_dropped = True
                else:
                    new_keyspace_name = json.loads(self.dbmap).get(
                        keyspace_name, ""
                    )
                    os_utils.replace_in_file(
                        keyspace_schema_file,
                        keyspace_name,
                        new_keyspace_name,
                    )
                    self.strip_table_ids(keyspace_schema_file)
                    self.cassandra_client.run_cql_file(keyspace_schema_file)

                    new_keyspace_path = os.path.join(
                        tempDir, self.cassandra_data_dir, new_keyspace_name
                    )
                    shutil.move(keyspace_path, new_keyspace_path)
                    keyspace_path = new_keyspace_path

                snapshots = glob.glob(
                    f"{keyspace_path}/**/{backup_name}", recursive=True
                )

                try:
                    for snapshot in snapshots:
                        self.restore_keyspace(
                            snapshot,
                            keyspace_name,
                            tables_for_restore,
                            new_keyspace_name,
                        )
                finally:
                    shutil.rmtree(tempDir)

        self.log.info("Restore finished")


def get_metadata_object(directory, keyspace_name):
    with open(os.path.join(directory, "metadata.json")) as f:
        metadata = json.load(f)

    for obj in metadata:
        if obj.get("keyspace") == keyspace_name:
            return obj
    return None


def list_databases(vault):
    os_utils.add_custom_vars(vault)
    return [
        f.split("-")[0]
        for _, _, files in os.walk(vault)
        for f in files
        if f.endswith(".tar.gz")
    ]
