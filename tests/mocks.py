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


class MockCassandraClient(object):
    def __init__(self):
        pass

    def execute_query(self, query):
        pass

    def drop_keyspace(self, keyspace_name):
        pass

    def drop_table(self, keyspace_name, table_name):
        pass

    def run_cql_file(self, cql_file):
        if not os.path.exists(cql_file):
            raise FileNotFoundError(f"{cql_file}")

    def close(self):
        pass
