from flask_restful import Resource, Api

from flask import Flask
import logging
from flask_mail import Mail
from flask_cors import CORS
from waitress import serve

from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)

# ----------------------------------------
# Rafa Modification --> This part was previously in DB_Model.py
# I have changed it to here because otherwise it gave me an error: "...SQLALCHEMY_TRACK_MODIFICATIONS..." or
# "...the sqlalchemy extension was not registered to the current application. please make sure to call init_app() first..."
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auth.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
engine = db.create_engine('sqlite:///auth.db', {}) # Rafa Modification --> Before there was a second argument "echo", I have removed it for {}
# ----------------------------------------

CORS(app)
api = Api(app)
Mail(app)

logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(asctime)s\t %(module)-s\t msg="%(message)s"',
                    datefmt='%a, %d %b %Y %H:%M:%S', filemode='w')

logger = logging.getLogger('REST API')

if __name__ == '__main__':
    logger.info('Auth REST-API')

    app.secret_key = '123'
    # Indexing
    from auth_logic import auth_logic
    # We register the auth_logic application
    app.register_blueprint(auth_logic)

    # Start server
    # Rafa Modification --> This allows us to use a plain HTTP callback
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = "1"
    serve(app, host='0.0.0.0', port=2000)
