from flask import Flask
from flask import request
from flask import jsonify
from flask import make_response
from cassandra.cluster import Cluster
from cassandra import ConsistencyLevel
from passlib.hash import pbkdf2_sha256
import jwt
import datetime
import uuid
from gevent import monkey
monkey.patch_all()

SECRET_KEY = "qwertyuiopasdfghjklzxcvbnm123456"
EXP_ACCESS_DELTA = datetime.timedelta(minutes=30)
EXP_REFRESH_DELTA = datetime.timedelta(days=60)


class MyJwt:
    def __init__(self, userid, email, name):
        my_userid = str(userid)

        access_exp = datetime.datetime.now() + EXP_ACCESS_DELTA
        access_jti = str(uuid.uuid4())
        access_payload = {'userId': my_userid, 'exp': access_exp, 'jti': access_jti, 'name': name, 'email': email}
        self.access_token = jwt.encode(payload=access_payload, key=SECRET_KEY, algorithm='HS256').decode('utf-8')

        refresh_exp = datetime.datetime.now() + EXP_REFRESH_DELTA
        refresh_jti = str(uuid.uuid4())
        refresh_payload = {'userId': my_userid, 'exp': refresh_exp, 'jti': refresh_jti, 'name': name, 'email': email}
        self.refresh_token = jwt.encode(payload=refresh_payload, key=SECRET_KEY, algorithm='HS256').decode('utf-8')


class CassandraClient:
    def __init__(self):
        self.cluster = Cluster(['cassandra0'], port=9042)
        self.session = self.cluster.connect('membership')

        self.pr_user_lookup = self.session.prepare("SELECT userid, name, email, password, refresh_token FROM users WHERE email=?")
        self.pr_user_lookup.consistency_level = ConsistencyLevel.ONE

        self.pr_new_user = self.session.prepare("INSERT INTO users (userid, name, email, password) VALUES (?, ?, ?, ?)")
        self.pr_new_user.consistency_level = ConsistencyLevel.ALL

        self.pr_new_token = self.session.prepare("UPDATE users SET refresh_token=? WHERE email=?")
        self.pr_new_token.consistency_level = ConsistencyLevel.ALL

        self.pr_cur_token = self.session.prepare("SELECT refresh_token FROM users WHERE email=?")
        self.pr_cur_token.consistency_level = ConsistencyLevel.ONE

    def execute(self, *args):
        return self.session.execute(*args)


app = Flask(__name__)
app.cassandra = CassandraClient()


@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    if request.method == 'OPTIONS':
        response.headers['Access-Control-Allow-Methods'] = 'DELETE, GET, POST, PUT'
        headers = request.headers.get('Access-Control-Request-Headers')
        if headers:
            response.headers['Access-Control-Allow-Headers'] = headers
    return response


@app.route('/auth/login', methods=['POST'])
def login():
    req_data = request.get_json(force=True)
    email = req_data['email']
    password = req_data['password']

    user_exists = app.cassandra.execute(app.cassandra.pr_user_lookup, [email])
    if user_exists and pbkdf2_sha256.verify(password, user_exists[0].password):
        userid = user_exists[0].userid
        name = user_exists[0].name
        tokens = MyJwt(userid, email, name)
        app.cassandra.execute(app.cassandra.pr_new_token, [tokens.refresh_token, email])

        resp_data = {'access_token': tokens.access_token, 'refresh_token': tokens.refresh_token}
        return make_response(jsonify(resp_data), 200)
    else:
        return make_response(jsonify("Wrong email or password"), 403)


@app.route('/auth/new', methods=['POST'])
def register():
    req_data = request.get_json(force=True)
    email = req_data['email']
    password = req_data['password']
    name = req_data['name']
    pass_hash = pbkdf2_sha256.hash(password)

    user_exists = app.cassandra.execute(app.cassandra.pr_user_lookup, [email])
    if user_exists:
        return make_response(jsonify("User already exists"), 403)
    else:
        userid = uuid.uuid4()
        app.cassandra.execute(app.cassandra.pr_new_user, [userid, name, email, pass_hash])
        return make_response(jsonify("Success"), 200)


@app.route('/refreshToken', methods=['POST'])
def new_tokens():
    req_data = request.get_json(force=True)
    refresh_token = req_data['refresh_token']
    try:
        tmp_token = jwt.decode(refresh_token, SECRET_KEY, algorithms='HS256', verify_exp=True)
        email = tmp_token['email']
        name = tmp_token['name']
        userid = tmp_token['userId']
    except:
        return make_response(jsonify('Invalid or expired refresh token'), 403)

    old_refresh_token = app.cassandra.execute(app.cassandra.pr_cur_token, [email])[0].refresh_token
    if old_refresh_token != refresh_token:
        return make_response(jsonify('Invalid or expired refresh token'), 403)

    tokens = MyJwt(userid, email, name)
    app.cassandra.execute(app.cassandra.pr_new_token, [tokens.refresh_token, email])

    resp_data = {'access_token': tokens.access_token, 'refresh_token': tokens.refresh_token}
    return make_response(jsonify(resp_data), 200)


@app.route('/kek', methods=['GET'])
def kek():
    res = app.cassandra.execute("SELECT * FROM users LIMIT 1")
    lol = res[0].refresh_token
    res = app.cassandra.execute("SELECT email FROM users LIMIT 1")
    lol = res[0].email
    return make_response(jsonify(list(res)), 200)


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
