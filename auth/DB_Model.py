from auth import app
from datetime import datetime
import hashlib
from MailConfig import mail_settings
from auth import db # Rafa Modification
from flask_sqlalchemy import SQLAlchemy
from settings import Settings

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auth.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Rafa Modification
#db = SQLAlchemy(app)
#engine = db.create_engine('sqlite:///auth.db', echo=False)

settings = Settings()
key = settings.KEY


class User(db.Model):
    """ Create user table"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True)
    email = db.Column(db.String(60), unique=True)
    password = db.Column(db.String(100))
    active = db.Column(db.Boolean)
    deleted = db.Column(db.Boolean)

    def __init__(self, username, email, password):
        self.username = username
        self.password = password
        self.email = email
        self.active = False
        self.deleted = False


class Rol(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), db.ForeignKey('user.username'), nullable=False)
    rol_name = db.Column(db.String(50))

    def __init__(self, username, rol_name):
        self.username = username
        self.rol_name = rol_name


class Registry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), db.ForeignKey('user.username'), nullable=False)
    action = db.Column(db.String(40), nullable=False)
    data = db.Column(db.String(500))
    date = db.Column(db.DateTime, nullable=False)

    def __init__(self, username, action, data=None):
        self.username = username
        self.action = action
        if data:
            self.data = data
        self.date = datetime.now()


class Platform(db.Model):
    platform_id = db.Column(db.String(40), nullable=False, primary_key=True)
    platformName = db.Column(db.String(40), nullable=False, unique= True)
    ip = db.Column(db.String(40), nullable=False, unique=True)
    active = db.Column(db.Boolean)

    def __init__(self, platform_id, platformName, ip):
        self.platform_id = platform_id
        self.platformName = platformName
        self.ip = ip
        self.active = False


"""
class Subscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), db.ForeignKey('user.username'), nullable=False)
    platformName = db.Column(db.String(40), db.ForeignKey('platform.platformName'), nullable=False)

    def __init__(self, username, platformName):
        self.platformName = platformName
        self.username = username
"""

def init_db():
    admin_user = User('Admin', mail_settings.get('MAIL_USERNAME'), hashlib.md5('Admin'.encode()).hexdigest())
    admin_user.active = True
    db.session.add(admin_user)
    admin_rol = Rol(username='Admin', rol_name='Admin')
    db.session.add(admin_rol)
    db.session.commit()


def drop_users_db():
    Rol.__table__.drop(engine)
    Registry.__table__.drop(engine)
    User.__table__.drop(engine)

    User.__table__.create(engine)
    Rol.__table__.create(engine)
    Registry.__table__.create(engine)
    init_db()


db.create_all()
if len(User.query.all()) == 0:
    init_db()
