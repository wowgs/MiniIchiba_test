DROP KEYSPACE IF EXISTS demo;

CREATE KEYSPACE demo
    WITH replication = {'class': 'SimpleStrategy', 'replication_factor': '1'};


CREATE TABLE demo.users (
    email text,
    password text,
    refresh_token text,
    PRIMARY KEY ( email )
);
