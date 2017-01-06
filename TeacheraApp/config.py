"""Application configuration.

When using app.config.from_object(obj), Flask will look for all UPPERCASE
attributes on that object and load their values into the app config. Python
modules are objects, so you can use a .py file as your configuration.
"""

import os

# Get the current working directory to place sched.db during development.
# In production, use absolute paths or a database management system.

class BaseConfig(object):
    PWD = os.path.abspath(os.curdir)
    DEBUG = True
    #SQLALCHEMY_DATABASE_URI = 'sqlite:///{}/teachera.db'.format(PWD)
    #SQLALCHEMY_DATABASE_URI = 'sqlite:////home/ziliot/webapps/appname3/sched.db'
    SQLALCHEMY_DATABASE_URI = "postgresql+psycopg2://teachera:jonsnow&harveySpect&merlin&Regina@46.101.195.232:5432/appdb";

class DefaultConfig(BaseConfig):
    SECRET_KEY = 'ndihinbosejsecretkey' # Create your own.
    SESSION_PROTECTION = 'strong'
    SECURITY_PASSWORD_HASH = 'pbkdf2_sha512'
    SECURITY_PASSWORD_SALT = 'ndihinbosejsecretkey'
    SECURITY_LOGIN_URL = '/login'
    SECURITY_LOGOUT_URL = '/logout'
    SECURITY_REGISTER_URL = '/signup'
    SECURITY_RESET_URL = '/reset'
    SECURITY_CONFIRMABLE = False
    SECURITY_REGISTERABLE = True
    SECURITY_SEND_REGISTER_EMAIL = False
    SECURITY_SEND_PASSWORD_CHANGE_EMAIL = False
    SECURITY_SEND_PASSWORD_RESET_NOTICE_EMAIL = False
    FACEBOOK_LOGIN_APP_ID = '278199585695188'  #Internly's facebook details
    FACEBOOK_LOGIN_APP_SECRET = '0d79c6473c08ce32dbfcac418014e1cc'#Internly's facebook details
    #FACEBOOK_LOGIN_APP_ID = '525684897599050'
    #FACEBOOK_LOGIN_APP_SECRET = '9bf282c5a76bca90b5777094ae35ec2b'
    MAIL_SERVER = ''
    MAIL_PORT = 465
    MAIL_USE_SSL = False
    MAIL_USERNAME = 'support@teachera.eu'
    MAIL_PASSWORD = 'Teachera+'
    SECURITY_RECOVERABLE = True
    SECURITY_SEND_PASSWORD_RESET_NOTICE_EMAIL = True
    SECURITY_RESET_SALT= 'enydM2AJAdcoKwdVaMJWvEsbPLKuQpMjf'
    DEFAULT_MAIL_SENDER = 'support@teachera.eu'
    SECURITY_EMAIL_SENDER = 'support@teachera.eu'
    MAIL_DEBUG = False
    POSITION_APPERANCE_TIME_IN_DAYS=7
    # Stripe keys
    STRIPE_SECRET_KEY = "sk_test_rjR7OBnZ0Ft3gNlKdwjP4ayZ"
    STRIPE_PUBLISHABLE_KEY = "pk_test_8oDWPvSEBSeNi1Go8xqNMuCw"
