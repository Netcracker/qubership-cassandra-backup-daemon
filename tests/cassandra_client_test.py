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
