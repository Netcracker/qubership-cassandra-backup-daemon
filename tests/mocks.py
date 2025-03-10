
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
