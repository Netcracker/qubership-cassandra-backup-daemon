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

from src import cassandra_client


# @pytest.fixture(scope="function", autouse=True)
# def generate_data():


def test_drop_all_tables():
    client = cassandra_client.CassandraClient(["localhost"])
    client.session.execute(
        "CREATE KEYSPACE if not EXISTS cycling1  WITH REPLICATION={'class': 'NetworkTopologyStrategy',   'dc1': 1}")
    client.session.execute(
        "CREATE TABLE if not EXISTS cycling1.cyclist_name (  id UUID PRIMARY KEY,  lastname text,  firstname text )")

    tables = client.get_tables("cycling1")
    assert len(tables) == 1
    assert tables[0] == "cyclist_name"
    client.drop_all_tables("cycling1")

    tables = client.get_tables("cycling1")
    assert len(tables) == 0
