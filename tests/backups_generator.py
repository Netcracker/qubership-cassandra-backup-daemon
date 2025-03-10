

import json
import os
import random
import shutil
import string
import uuid
import tarfile


class BackupGenerator(object):
    def __init__(self, keyspace_number: int, tables_number: int, temp_dir) -> None:
        self.keyspace_number = keyspace_number
        self.tables_number = tables_number
        self.temp_dir = temp_dir

    def generate_keyspace_schema(self, keyspace_name) -> str:
        return f"CREATE KEYSPACE IF NOT EXISTS {keyspace_name} WITH replication = {{'class': 'org.apache.cassandra.locator.SimpleStrategy', 'replication_factor': '1'}}  AND durable_writes = True;"

    def generate_table_schema(self, keyspace_name, table_name, _uuid) -> str:
        return """
        CREATE TABLE IF NOT EXISTS {}.{} (
            id int PRIMARY KEY,
            group text,
            login text,
            name text
        ) WITH ID = {}
            AND additional_write_policy = '99p'
            AND bloom_filter_fp_chance = 0.01
            AND caching = {{'keys': 'ALL', 'rows_per_partition': 'NONE'}}
            AND cdc = false
            AND comment = ''
            AND compaction = {{'class': 'org.apache.cassandra.db.compaction.SizeTieredCompactionStrategy', 'max_threshold': '32', 'min_threshold': '4'}}
            AND compression = {{'chunk_length_in_kb': '16', 'class': 'org.apache.cassandra.io.compress.LZ4Compressor'}}
            AND memtable = 'default'
            AND crc_check_chance = 1.0
            AND default_time_to_live = 0
            AND extensions = {{}}
            AND gc_grace_seconds = 864000
            AND max_index_interval = 2048
            AND memtable_flush_period_in_ms = 0
            AND min_index_interval = 128
            AND read_repair = 'BLOCKING'
            AND speculative_retry = '99p';
        """.format(keyspace_name, table_name, _uuid)

    def generate_snapshot(self, keyspace_name, table_name, snapshot_name, is_empty: bool):
        generated_uuid = str(uuid.uuid4())
        snapshot_path = f"{self.temp_dir}/cassandra0-0.cassandra.cassandra.svc.cluster.local/var/lib/cassandra/data/{keyspace_name}/{table_name}-{generated_uuid}/snapshots/{snapshot_name}"
        keyspace_schema = self.generate_keyspace_schema(keyspace_name)

        os.makedirs(snapshot_path, exist_ok=True)
        with open(f"{snapshot_path}/tsschema.cql", 'w') as keyspace_file:
            keyspace_file.write(keyspace_schema)

        if not is_empty:
            table_schema = self.generate_table_schema(
                keyspace_name, table_name, generated_uuid)
            with open(f"{snapshot_path}/schema.cql", 'w') as table_file:
                table_file.write(table_schema)

    def generate_archives(self):
        temp_dir = os.path.abspath("./tests/generated")
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        os.makedirs(temp_dir)
        keyspaces = []
        metadata = []
        try:
            for _ in range(self.keyspace_number):
                keyspace_name = ''.join(random.choice(
                    string.ascii_lowercase + string.digits) for _ in range(47))
                keyspaces.append(keyspace_name)
                snapshot_name = keyspace_name + "-" + ''.join(random.choice(string.digits) for _ in range(
                    8)) + "_" + ''.join(random.choice(string.digits) for _ in range(6))
                table_names = []
                for _ in range(self.tables_number):
                    table_name = ''.join(random.choice(
                        string.ascii_lowercase + string.digits) for _ in range(15))
                    table_names.append(table_name)
                    self.generate_snapshot(
                        keyspace_name, table_name, snapshot_name, False)

                metadata.append({"keyspace": keyspace_name,
                                 "all_tables": "true", "tables": table_names})
                host_dir = f"{self.temp_dir}/cassandra0-0.cassandra.cassandra.svc.cluster.local"
                with open(f"{host_dir}/metadata.json", 'w') as meta_file:
                    meta_file.write(json.dumps(metadata))

                with tarfile.open(f"{host_dir}/{snapshot_name}.tar.gz", "w:gz") as tar:
                    for fn in os.listdir(host_dir):
                        p = os.path.join(host_dir, fn)
                        tar.add(p, arcname=fn)

        finally:
            shutil.rmtree(os.path.abspath(
                "./tests/generated/cassandra0-0.cassandra.cassandra.svc.cluster.local/var"))

        return keyspaces

    def clear(self):
        shutil.rmtree(self.temp_dir)


def main():
    generator = BackupGenerator(
        1, 3, os.path.abspath("./tests/generated"))
    keyspaces = generator.generate_archives()
    print(keyspaces)


if __name__ == "__main__":
    main()
