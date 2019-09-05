from flask import Blueprint

auth_api = Blueprint('auth_api', __name__)

@auth_api.route('/auth/login', methods=['POST'])
def login():
    pass

@auth_api.route('/auth/new', methods=['POST'])
def register():
    pass

@auth_api.route('/auth/logout', methods=['POST'])
def logout():
    pass

@auth_api.route('/refreshToken', methods=['POST'])
def new_tokens():
    pass