import getpass
import logging
import sys
from pprint import pprint
from restframeworkclient.connection import Api as RestApi

logging.basicConfig(stream=sys.stdout, level=logging.INFO)

logger = logging.getLogger(__name__)

email = input('Email? ')
password = getpass.getpass()

options = {
    'DOMAIN': 'http://127.0.0.1:8000',
    'API_PREFIX': 'api/v1',
    'TOKEN_TYPE': 'jwt',
    'TOKEN_FORMAT': 'JWT {token}',
    'LOGIN': 'auth/login/',
    'LOGOUT': 'auth/logout/',
}

c = RestApi(options)

ok = c.login(email=email, password=password)
if ok:

    # GET some data
    my_objects = c.org.get()
    for obj in my_objects['results']:
        pprint(obj)
        logger.info('------------------------------')

    logger.info('------------------------------')
    logger.info('------------------------------')
    my_object = c.org('arch-internal').get()
    pprint(my_object)
    logger.info('------------------------------')
    logger.info('------------------------------')

    payload = {
        'data1': 'val1',
        'data2': 'val2',
    }

    resp = c.org.post(data=payload)
    pprint(resp)

    logger.info('------------------------------')

    c.logout()
