from cassandra.cluster import Cluster

KEYSPACE = "membership"

def main():
    cluster = Cluster(['cassandra0'], port=9042, control_connection_timeout=10)
    session = cluster.connect()

    session.execute("DROP KEYSPACE IF EXISTS %s" % KEYSPACE)

    session.execute("""
        CREATE KEYSPACE IF NOT EXISTS %s
        WITH replication = { 'class': 'SimpleStrategy', 'replication_factor': '2' }
        """ % KEYSPACE)

    session.set_keyspace(KEYSPACE)

    session.execute("""
        CREATE TABLE IF NOT EXISTS users (
        userId uuid,
        name text,
        email text,
        password text,
        refresh_token text,
        PRIMARY KEY ( email )
        )
        """)

if __name__ == "__main__":
    main()