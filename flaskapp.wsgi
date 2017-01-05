#!/usr/bin/python
import sys
import logging
logging.basicConfig(stream=sys.stderr)
sys.path.insert(0,"/var/www/FlaskApp/")

from TeacheraApp import app as application
application.secret_key = 'Jonsnwo+merlin+regina'
