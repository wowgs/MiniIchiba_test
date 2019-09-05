from flask import Flask
from flask import request
from cassandra.cluster import Cluster
from passlib.hash import pbkdf2_sha256
import jwt
import datetime

SECRET_KEY = "dxIZ1s0kprlD4MKnJnVmp2oZGf8E5SK9"
EXP_ACCESS_DELTA = datetime.timedelta(minutes=30)
EXP_REFRESH_DELTA = datetime.timedelta(days=60)


class MyJwt:
    def __init__(self, id):
        access_exp = datetime.datetime.now() + EXP_ACCESS_DELTA
        access_payload = {'email' : id, 'exp' : access_exp}
        self.access_token = jwt.encode(payload=access_payload, key=SECRET_KEY, algorithm='HS256').decode('utf-8')

        refresh_exp = datetime.datetime.now() + EXP_REFRESH_DELTA
        refresh_payload = {'email' : id, 'exp' : refresh_exp}
        self.refresh_token = jwt.encode(payload=refresh_payload, key=SECRET_KEY, algorithm='HS256').decode('utf-8')


class CassandraClient:
    def __init__(self):
        self.cluster = Cluster()
        self.session = self.cluster.connect('demo')
        self.pr_user_lookup = self.session.prepare("SELECT email, password, refresh_token FROM users WHERE email=?")
        self.pr_new_user = self.session.prepare("INSERT INTO users (email, password) VALUES (?, ?)")
        self.pr_new_token = self.session.prepare("UPDATE users SET refresh_token=? WHERE email=?")

    def execute(self, *args):
        return self.session.execute(*args)


app = Flask(__name__)
app.cassandra = CassandraClient()


@app.route('/auth/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']

    user_exists = app.cassandra.execute(app.cassandra.pr_user_lookup, [email])
    if user_exists and pbkdf2_sha256.verify(password, user_exists[0][1]):
        tokens = MyJwt(email)
        app.cassandra.execute(app.cassandra.pr_new_token, [tokens.refresh_token, email])

        resp_data = {'access_token' : tokens.access_token, 'refresh_token' : tokens.refresh_token}
        return resp_data, 200
    else:
        return "Wrong email or password", 403


@app.route('/auth/new', methods=['POST'])
def register():
    email = request.form['email']
    password = request.form['password']
    pass_hash = pbkdf2_sha256.hash(password)

    user_exists = app.cassandra.execute(app.cassandra.pr_user_lookup, [email])
    if user_exists:
        return "User already exists", 409
    else:
        app.cassandra.execute(app.cassandra.pr_new_user, [email, pass_hash])
        return "Success", 200


@app.route('/refreshToken', methods=['POST'])
def new_tokens():
    old_refresh_token = request.form['refresh_token']
    try:
        email = jwt.decode(old_refresh_token, SECRET_KEY, algorithms='HS256')['email']
    except:
        return 'Invalid or expired refresh token', 403

    tokens = MyJwt(email)
    app.cassandra.execute(app.cassandra.pr_new_token, [tokens.refresh_token, email])

    resp_data = {'access_token': tokens.access_token, 'refresh_token': tokens.refresh_token}
    return resp_data, 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9009, debug=True)


# def connect_to_database():
#     cluster = Cluster()
#     session = cluster.connect('demo')
#     return (cluster, session)
#
#
# def get_db():
#     if 'db' not in g:
#         g.db = connect_to_database()
#
#     return g.db[1]
#
#
# @app.teardown_appcontext
# def teardown_db(_):
#     db = g.pop('db', None)
#
#     if db is not None:
#         db[0].shutdown()
#
# db = LocalProxy(get_db)
