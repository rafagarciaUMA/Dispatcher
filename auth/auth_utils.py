import string
import random
import re
from flask import request
import hashlib
from jwcrypto import jwt
from functools import wraps
import ast
from DB_Model import User, Registry, Rol, db
from flask import session, jsonify, redirect
from requests_oauthlib import OAuth2Session
from datetime import datetime
from settings import Settings

key = Settings().KEY

get_platform_name = lambda: open("platform_name", "r").read().split()[0]
get_platform_id = lambda: open("platformID", "r").read().split()[0]
get_platform_ip = lambda: open("platform_ip", "r").read().split()[0]

# OAuth2 parameters
client_id = "gx9xcim0JIddA3V8dr3TEqf0"
authorization_base_url = 'https://portal.fed4fire.eu/oauth/authorize'


def preValidation(request, functional_part):
    if request.authorization:
        username = request.authorization.username
        password = hashlib.md5(request.authorization.password.encode()).hexdigest()

        data = User.query.filter_by(username=username, password=password).first()
    else:
        data = None
    if data is not None and data.active:
        now = datetime.now()
        Etoken = jwt.JWT(header={'alg': 'A256KW', 'enc': 'A256CBC-HS512'},
                         claims={'username': username, 'password': password,
                                 'timeout': datetime.timestamp(now) + Settings.Timeout})

        Etoken.make_encrypted_token(key)
        token = Etoken.serialize()
        return functional_part(token)

    elif data is None:
        # In case the traditional login fails, that is, the username and password ar not found in the database, the
        # fed4fire login is tried with OAuth2.
        # The first step consist of redirect the user/resource owner to the OAuth provider (fed4fire) using an URL
        # with a few key OAuth parameters.
        fed4fire = OAuth2Session(client_id, redirect_uri="http://150.214.47.145/callback")
        authorization_url, state = fed4fire.authorization_url(authorization_base_url)

        # State is used to prevent CSRF, keep this for later
        session['oauth_state'] = state
        return redirect(authorization_url)  # Redirects to fed4fire Auth server, returns to /callback endpoint when finished

        # return jsonify(result='No user registered/active with that user/password'), 400

    else:
        return jsonify(result='User ' + username + ' is not activated'), 400


# Function to validate access token obtained from Fed4fire via OAuth2.
# Fetching a protected resource using an OAuth2 token.
def OAuth2Validation(functional_part):
    fed4fire = OAuth2Session(client_id, token=session['oauth_token'])
    # Rafa Modification
    post = fed4fire.post('https://portal.fed4fire.eu/oauth/introspect', fed4fire.token).json()
    data = jsonify(post)

    # Validation check not implemented at the moment
    #if 'active' in post: # Rafa Modification
    #    if data.active is True:
    #        now = datetime.now()
    #        Etoken = jwt.JWT(header={'alg': 'A256KW', 'enc': 'A256CBC-HS512'},
    #                         claims={'oauth_token': fed4fire.token,
    #                                 'timeout': datetime.timestamp(now) + Settings.Timeout})
    now = datetime.now()
    Etoken = jwt.JWT(header={'alg': 'A256KW', 'enc': 'A256CBC-HS512'},
                     claims={'oauth_token': fed4fire.token,
                             'timeout': datetime.timestamp(now) + Settings.Timeout})
    Etoken.make_encrypted_token(key)
    token = Etoken.serialize()
    return functional_part(token)

    #else:
    #    return jsonify(result='OAuth2 token is not valid'), 400


def auth(f):
    @wraps(f)
    def auth_validator(*args, **kwargs):
        auth = token_auth_validator(request)
        if not auth[0]:
            return auth[-1]
        return f(*args, **kwargs)

    return auth_validator


def admin_auth(f):
    @wraps(f)
    def auth_validator(*args, **kwargs):
        if request.authorization:
            username = request.authorization.username
            password = request.authorization.password
            data_user = User.query.filter_by(username=username,
                                             password=hashlib.md5(password.encode()).hexdigest()).first()
            data_rol = Rol.query.filter_by(username=username, rol_name='Admin').first()
            if not (data_user and data_rol):
                return jsonify(result='Invalid Permission'), 401
            return f(*args, **kwargs)
        else:
            return jsonify(result='Invalid Permission'), 401

    return auth_validator


def token_auth_validator(request=None):
    result = (True, None)
    if session.get('token') or session.get('token') is False:
        token = session.get('token')
        token_valid = validate_token(token, request)

        # Validate token, None in this function means no problem detected
    if token_valid is not None:
        result = (False, (jsonify(result=token_valid), 400))

    return result


def get_user_from_token(token):
    try:
        if not token:
            return 'Token access is required', 400
        name = ast.literal_eval(jwt.JWT(key=key, jwt=token).claims).get('username')
        if not name:
            name = ast.literal_eval(jwt.JWT(key=key, jwt=token).claims).get('platform')

        return name, 200

    except:
        return 'No valid Token given', 400


def get_mail_from_token(token, user):
    try:
        if not (token or user):
            return 'Token access is required', 400
        if token:
            user = ast.literal_eval(jwt.JWT(key=key, jwt=token).claims).get('username')

        email = User.query.filter_by(username=user).first().email

        return email, 200

    except:
        return 'No valid Token given', 400


def validate_token(token, request):
    try:
        if not token:
            return 'Login or set a Token access is required'

        metadata = ast.literal_eval(jwt.JWT(key=key, jwt=token).claims)

        now = datetime.now()
        if metadata.get('timeout') >= datetime.timestamp(now):
            if metadata.get('username'):
                data = User.query.filter_by(username=metadata.get('username'),
                                            password=metadata.get('password')).first()
            else:
                if metadata.get('platform_id') == get_platform_id():
                    return
                if metadata.get('oauth_token') is not None:
                    fed4fire = OAuth2Session(client_id=client_id, token=session['oauth_token'])
                    data = jsonify(fed4fire.post('https://portal.fed4fire.eu/oauth/introspect', fed4fire.token).json)
                    #if data.active is True:
                    return
        else:
            return 'Token expired'
        if data is not None:

            if not isinstance(request, str) and request.data:
                new_action = Registry(username=metadata.get('username'),
                                      action=str(request.method + ' ' + request.path),
                                      data=str(request.get_json()))
            else:
                new_action = Registry(username=metadata.get('username'),
                                      action=str(request.method + ' ' + request.path))
            db.session.add(new_action)
            db.session.commit()
            pass
        else:
            raise Exception()
    except:
        return 'No valid Token given'


def randomPassword(stringLength=10):
    """Generate a random string of fixed length """

    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))


def check_mail(email):
    # pass the regualar expression
    # and the string in search() method
    if (re.search('^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$', email)):
        return True

    else:
        return False


def string_to_boolean(string):
    if string.lower() in ['true', '1', 't', 'y', 'yes']:
        return True
    return False
