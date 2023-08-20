import getpass
import logging
import sys
from pprint import pprint

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
}

c = RestApi(options)

ok = c.login(username=username, password=password)
if ok:
    # GET some data
    my_objects = c.org.get()
    for obj in my_objects["results"]:
        pprint(obj)
        logger.info("------------------------------")

    logger.info("------------------------------")
    logger.info("------------------------------")
    # If the URL includes "-", add under parenthesis:
    # GET: /api/v1/someresource/some-path/
    my_object = c.someresource("some-path").get()
    pprint(my_object)
    logger.info("------------------------------")
    logger.info("------------------------------")

    payload = {
        "data1": "val1",
        "data2": "val2",
    }

    resp = c.someresource.post(data=payload)
    pprint(resp)

    logger.info("------------------------------")

    c.logout()
