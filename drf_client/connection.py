__author__ = 'dkarchmer'

"""
See https://gist.github.com/dkarchmer/d85e55f9ed5450ba58cb
This API generically supports DjangoRestFramework based APIs
It is based on https://github.com/samgiles/slumber, but customized for
Django Rest Frameworks, and the use of TokenAuthentication.
Usage:
    # Assuming
    # v1_api_router.register(r'some_model', SomeModelViewSet)
    options = {
       'DOMAIN': 'http://127.0.0.1:8000',
       'API_PREFIX': 'api/v1',
       'TOKEN_TYPE': 'jwt',
       'TOKEN_FORMAT': 'JWT {token}',
       'LOGIN': 'auth/api-jwt-auth/',
       'LOGOUT': 'auth/logout/',
       'USE_DASHES': False,
    }

    api = RestApi(options)
    api.login(email='user1@test.com', password='user1')
    obj_list = api.some_model.get()
    logger.debug('Found {0} groups'.format(obj_list['count']))
    obj_one = api.some_model(1).get()
    api.logout()
"""
import json
import requests
import logging
import os
from .exceptions import *

API_PREFIX = 'api/v1'
DEFAULT_HEADERS = {'Content-Type': 'application/json'}
DEFAULT_TOKEN_TYPE = 'jwt'
DEFAULT_TOKEN_FORMAT = 'JWT {token}'
DEFAULT_OPTIONS = {
       'DOMAIN': 'http://example.com',
       'API_PREFIX': 'api/v1',
       'TOKEN_TYPE': 'jwt',
       'TOKEN_FORMAT': 'JWT {token}',
       'LOGIN': 'auth/login/',
       'LOGOUT': 'auth/logout/',
       'USE_DASHES': False,
    }

logger = logging.getLogger(__name__)


class RestResource:
    """
    Resource provides the main functionality behind a Django Rest Framework based API. It handles the
    attribute -> url, kwarg -> query param, and other related behind the scenes
    python to HTTP transformations. It's goal is to represent a single resource
    which may or may not have children.
    """
    _store = {}
    _options = {}

    def __init__(self, *args, **kwargs):
        self._store = kwargs
        if 'options' in self._store:
            self._options = self._store['options']
        else:
            self.options = DEFAULT_OPTIONS
        if 'use_token' not in self._store:
            self._store['use_token'] = False

    def __call__(self, id=None):
        """
        Returns a new instance of self modified by one or more of the available
        parameters. These allows us to do things like override format for a
        specific request, and enables the api.resource(ID).get() syntax to get
        a specific resource by it's ID.
        """

        kwargs = {
            'token': self._store['token'],
            'use_token': self._store['use_token'],
            'base_url': self._store['base_url'],
            'options': self._options,
        }

        new_url = self._store['base_url']
        if id is not None:
            new_url = f'{new_url}{id}/'

        if not new_url.endswith('/'):
            new_url += '/'

        kwargs['base_url'] = new_url

        return self._get_resource(**kwargs)

    def __getattr__(self, item):
        # Don't allow access to 'private' by convention attributes.
        if item.startswith("_"):
            raise AttributeError(item)

        kwargs = self._copy_kwargs(self._store)
        if self._options.get('USE_DASHES', False):
            item = item.replace("_", "-")
        kwargs.update({'base_url': '{0}{1}/'.format(self._store["base_url"], item)})

        return self._get_resource(**kwargs)

    def _copy_kwargs(self, dictionary):
        kwargs = {}
        for key, value in self._iterator(dictionary):
            kwargs[key] = value

        return kwargs

    def _iterator(self, d):
        """
        Helper to get and a proper dict iterator with Py2k and Py3k
        """
        try:
            return d.iteritems()
        except AttributeError:
            return d.items()

    def _check_for_errors(self, resp, url):

        if 400 <= resp.status_code <= 499:
            exception_class = HttpNotFoundError if resp.status_code == 404 else HttpClientError
            raise exception_class("Client Error %s: %s" % (resp.status_code, url), response=resp, content=resp.content)
        elif 500 <= resp.status_code <= 599:
            raise HttpServerError("Server Error %s: %s" % (resp.status_code, url), response=resp, content=resp.content)

    def _handle_redirect(self, resp, **kwargs):
        # @@@ Hacky, see description in __call__
        resource_obj = self(url_override=resp.headers["location"])
        return resource_obj.get(**kwargs)

    def _try_to_serialize_response(self, resp):
        if resp.status_code in [204, 205]:
            return

        if resp.content:
            if type(resp.content) == bytes:
                try:
                    encoding = requests.utils.guess_json_utf(resp.content)
                    return json.loads(resp.content.decode(encoding))
                except Exception:
                    return resp.content
            return json.loads(resp.content)
        else:
            return resp.content

    def _process_response(self, resp):

        self._check_for_errors(resp, self.url())

        if 200 <= resp.status_code <= 299:
            return self._try_to_serialize_response(resp)
        else:
            return  # @@@ We should probably do some sort of error here? (Is this even possible?)

    def url(self, args=None):
        url = self._store["base_url"]
        if args:
            url += '?{0}'.format(args)
        return url

    def _get_headers(self):
        headers = DEFAULT_HEADERS
        if self._store['use_token']:
            if not "token" in self._store:
                raise RestBaseException('No Token')
            authorization_str = self._options['TOKEN_FORMAT'].format(token=self._store["token"])
            headers['Authorization'] = authorization_str

        return headers

    def get(self, extra_headers: dict = None, **kwargs):
        args = None
        if 'extra' in kwargs:
            args = kwargs['extra']
        headers = self._get_headers() | extra_headers if extra_headers else self._get_headers()

        resp = requests.get(self.url(args), headers=headers)
        return self._process_response(resp)

    def post(self, data=None, extra_headers: dict = None, **kwargs):
        payload = json.dumps(data) if data else None
        headers = self._get_headers() | extra_headers if extra_headers else self._get_headers()

        resp = requests.post(self.url(), data=payload, headers=headers, **kwargs)
        return self._process_response(resp)

    def patch(self, data=None, extra_headers: dict = None, **kwargs):
        payload = json.dumps(data) if data else None
        headers = self._get_headers() | extra_headers if extra_headers else self._get_headers()

        resp = requests.patch(self.url(), data=payload, headers=headers, **kwargs)
        return self._process_response(resp)

    def put(self, data=None, extra_headers: dict = None, **kwargs):
        payload = json.dumps(data) if data else None
        headers = self._get_headers() | extra_headers if extra_headers else self._get_headers()

        resp = requests.put(self.url(), data=payload, headers=headers, **kwargs)
        return self._process_response(resp)

    def delete(self, data=None, extra_headers: dict = None, **kwargs):
        payload = json.dumps(data) if data else None
        headers = self._get_headers() | extra_headers if extra_headers else self._get_headers()

        resp = requests.delete(self.url(), data=payload, headers=headers, **kwargs)
        if 200 <= resp.status_code <= 299:
            if resp.status_code == 204:
                return True
            else:
                return True  # @@@ Should this really be True?
        else:
            return False

    def _get_resource(self, **kwargs):
        return self.__class__(**kwargs)


class Api:
    token = None
    resource_class = RestResource
    use_token = True
    options = None

    def __init__(self, options):
        self.options = options
        if 'DOMAIN' not in self.options:
            raise RestBaseException("DOMAIN is missing in options")

        if 'API_PREFIX' not in self.options:
            self.options['API_PREFIX'] = API_PREFIX
        self.base_url = '{0}/{1}'.format(self.options['DOMAIN'], self.options['API_PREFIX'] )
        if 'TOKEN_TYPE' not in self.options:
            self.options['TOKEN_TYPE'] = DEFAULT_TOKEN_TYPE
        if 'TOKEN_FORMAT' not in self.options:
            self.options['TOKEN_FORMAT'] = DEFAULT_TOKEN_FORMAT

    def set_token(self, token):
        self.token = token

    def login(self, password, username=None):
        assert('LOGIN' in self.options)
        # This allows us to suport both a {'email': username} and {'username": username}
        # Default to 'username' which is the default DRF behavior
        username_key = self.options.get('USERNAME_KEY', 'username')
        data = {'password': password}
        data[username_key] = username
        url = '{0}/{1}'.format(self.base_url, self.options['LOGIN'])

        payload = json.dumps(data)
        r = requests.post(url, data=payload, headers=DEFAULT_HEADERS)
        if r.status_code in [200, 201]:
            content = json.loads(r.content.decode())
            self.token = content.get(self.options['TOKEN_TYPE'])
            if self.token is None:
                # Default to "token" if token_type is not used by server
                self.token = content.get('token')
            self.username = username
            return True
        else:
            logger.error('Login failed: ' + str(r.status_code) + ' ' + r.content.decode())
            return False

    def logout(self):
        assert('LOGOUT' in self.options)
        url = f"{self.base_url}/{self.options['LOGOUT']}"
        headers = DEFAULT_HEADERS
        headers['Authorization'] = self.options['TOKEN_FORMAT'].format(token=self.token)

        r = requests.post(url, headers=headers)
        if r.status_code == 204:
            logger.info(f'Goodbye @{self.username}')
            self.username = None
            self.token = None
        else:
            logger.error('Logout failed: ' + str(r.status_code) + ' ' + r.content.decode())

    def __getattr__(self, item):
        """
        Instead of raising an attribute error, the undefined attribute will
        return a Resource Instance which can be used to make calls to the
        resource identified by the attribute.
        """

        # Don't allow access to 'private' by convention attributes.
        if item.startswith("_"):
            raise AttributeError(item)

        if self.options.get('USE_DASHES', False):
            item = item.replace("_", "-")

        kwargs = {
            'token': self.token,
            'base_url': f'{self.base_url}/{item}/',
            'use_token': self.use_token,
            'options': self.options,
        }

        return self._get_resource(**kwargs)

    def _get_resource(self, **kwargs):
        return self.resource_class(**kwargs)
