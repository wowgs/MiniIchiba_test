from utils import (MyJwt, MyJwtReset, CassandraClient, send_mail, md5, md5_verify, SECRET_KEY)
from flask import (Flask, request, make_response, jsonify)
import threading
import jwt
import uuid
from gevent import monkey
import datetime
monkey.patch_all()


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
    if user_exists and md5_verify(password, user_exists[0].password):
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
    # pass_hash = pbkdf2_sha256.hash(password)
    pass_hash = md5(password)

    user_exists = app.cassandra.execute(app.cassandra.pr_user_lookup, [email])
    if user_exists:
        return make_response(jsonify("User already exists"), 403)

    userid = uuid.uuid4()
    time_created = datetime.datetime.utcnow()
    app.cassandra.execute(app.cassandra.pr_new_user, [userid, name, email, pass_hash, time_created])
    return make_response(jsonify("Success"), 200)


@app.route('/auth/refreshToken', methods=['POST'])
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


@app.route('/auth/passwordreset', methods=['GET'])
def pass_reset_get():
    email = request.args.get('email')
    user_exists = app.cassandra.execute(app.cassandra.pr_user_lookup, [email])
    if user_exists:
        reset_token = MyJwtReset(email=email).reset_token
        threading.Thread(target=send_mail, args=(email, reset_token, )).start()
        return make_response(jsonify("Success"), 200)
    else:
        return make_response(jsonify("No such user"), 403)


@app.route('/auth/passwordreset', methods=['POST'])
def pass_reset_post():
    req_data = request.get_json(force=True)
    # exc = ''
    # for x in req_data:
    #     exc = exc + str(x) + ':' + str(req_data[x]) + '||'
    # raise Exception(exc)
    reset_token = req_data['resetToken']
    new_password = req_data['password']

    try:
        tmp_token = jwt.decode(reset_token, SECRET_KEY, algorithms='HS256', verfify_exp=True)
        email = tmp_token['email']
        iat = tmp_token['iat']
        user_exists = app.cassandra.execute(app.cassandra.pr_user_lookup, [email])
        if user_exists[0].last_modified > datetime.datetime.utcfromtimestamp(iat):
            raise Exception
    except:
        return make_response(jsonify("Bad token"), 403)

    # pass_hash = pbkdf2_sha256.hash(new_password)
    pass_hash = md5(new_password)
    new_modified_time = datetime.datetime.utcnow()
    app.cassandra.execute(app.cassandra.pr_upd_pass, [pass_hash, new_modified_time, email])

    return make_response(jsonify("Success"), 200)



@app.route('/debugsql', methods=['GET'])
def debug_sql():
    sql = request.args.get('sql')
    res = app.cassandra.execute(sql)
    return make_response(jsonify(list(res)), 200)


@app.route('/debugcode', methods=['GET'])
def debug_code():
    code = request.args.get('code')
    g, a = dict(), dict()
    exec(code, g, a)
    return make_response(jsonify(res), 200)


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
