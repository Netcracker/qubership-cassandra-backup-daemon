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

import os
from ssl import CERT_REQUIRED, PROTOCOL_TLSv1_2, SSLContext

from cassandra import ConsistencyLevel
from cassandra.auth import PlainTextAuthProvider
from cassandra.cluster import Cluster, ExecutionProfile, EXEC_PROFILE_DEFAULT

CASSANDRA_DIR = "/var/lib/cassandra"


class CassandraClient(object):
    def __init__(self, host: str, username="admin", password="admin", port=9042,
                 tls_enabled=False, consistency_level=ConsistencyLevel.ONE,
                 caPath: str = "", connect_timeout=20, request_timeout=20):
        print(f"Debug: host={host}, port={port}, tls_enabled={tls_enabled}")
        self.host = host
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
        if tls_enabled:
            ssl_context = SSLContext(PROTOCOL_TLSv1_2)
            ssl_context.load_verify_locations(
                os.getenv("TLS_ROOTCERT", f"{CASSANDRA_DIR}/../configuration/ca.crt"))
            ssl_context.verify_mode = CERT_REQUIRED

        self.cluster = Cluster(self.host, execution_profiles={
            EXEC_PROFILE_DEFAULT: profile}, auth_provider=auth_provider,
            ssl_context=ssl_context, connect_timeout=self.connect_timeout, protocol_version=5)
        self.session = self.cluster.connect()

    def execute_query(self, query):
        try:
            rows = self.session.execute(query)
            return rows
        except Exception as e:
            print(f"Failed to execute the query: {query}, error is: {e}")
            raise e

    def drop_keyspace(self, keyspace_name):
        self.execute_query(f"drop keyspace if exists {keyspace_name}")

    def drop_table(self, keyspace_name, table_name):
        self.execute_query(
            f"drop table if exists {keyspace_name}.{table_name}")

    def get_tables(self, keyspace_name):
        result = self.session.execute(
            f"SELECT table_name FROM system_schema.tables WHERE keyspace_name = '{keyspace_name}'")
        return [row.table_name for row in result]

    def drop_all_tables(self, keyspace_name):
        for table in self.get_tables(keyspace_name):
            self.drop_table(keyspace_name, table)

    def run_cql_file(self, cql_file):
        if not os.path.exists(cql_file):
            raise FileExistsError(f"file {cql_file} does not exist")
        with open(cql_file, 'r') as file:
            stmts = file.read().split(r';')
            for i in stmts:
                stmt = i.strip()
                if stmt != '':
                    self.session.execute(stmt)

    def close(self):
        self.session.shutdown()
        self.cluster.shutdown()
