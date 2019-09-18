from cassandra.cluster import Cluster

KEYSPACE = "membership"


def main():
    cluster = Cluster(['cassandra0'], port=9042, control_connection_timeout=10)
    session = cluster.connect()

    session.execute("""
        CREATE KEYSPACE IF NOT EXISTS %s
        WITH replication = { 'class': 'SimpleStrategy', 'replication_factor': '2' }
        """ % KEYSPACE)

    session.set_keyspace(KEYSPACE)

    session.execute("DROP TABLE IF EXISTS users")

    session.execute("""
        CREATE TABLE IF NOT EXISTS users (
        userid uuid,
        name text,
        email text,
        password text,
        refresh_token text,
        last_modified timestamp,
        PRIMARY KEY ( email )
        )
        """)


if __name__ == "__main__":
    main()
