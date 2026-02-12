"""Example of using django-rest-framework-client to interact with a Django REST Framework API."""

import getpass
import logging
import pprint
import sys

from drf_client.connection import Api as RestApi

logging.basicConfig(stream=sys.stdout, level=logging.INFO)

logger = logging.getLogger(__name__)

username = input("Email? ")
password = getpass.getpass()

options = {
    "DOMAIN": "http://127.0.0.1:8000",
    "API_PREFIX": "api/v1",
    "TOKEN_TYPE": "jwt",
    "TOKEN_FORMAT": "JWT {token}",
    "USERNAME_KEY": "username",
    "LOGIN": "auth/login/",
    "LOGOUT": "auth/logout/",
    "USE_DASHES": False,
    "SESSION_TRIES": 3,
    "SESSION_TIMEOUT": None,
    "SESSION_VERIFY": False,
}

c = RestApi(options)

ok = c.login(username=username, password=password)
if ok:
    # GET some data
    my_objects = c.org.get()
    assert isinstance(my_objects, dict)
    for obj in my_objects["results"]:
        logger.info(pprint.pformat(obj))
        logger.info("------------------------------")

    logger.info("------------------------------")
    # If the URL includes "-", add under parenthesis:
    # GET: /api/v1/someresource/some-path/
    my_object = c.someresource("some-path").get()
    logger.info(pprint.pformat(obj))
    logger.info("------------------------------")

    payload = {
        "data1": "val1",
        "data2": "val2",
    }

    resp = c.someresource.post(data=payload)
    logger.info(pprint.pformat(resp))

    logger.info("------------------------------")

    c.logout()
