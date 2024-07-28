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
import logging

import requests

from .exceptions import (
    HttpNotFoundError, 
    HttpClientError, 
    HttpServerError, 
    RestBaseException,
    HttpCouldNotVerifyServerError,
)

API_PREFIX: str = "api/v1"
DEFAULT_HEADERS: dict = {"Content-Type": "application/json"}
DEFAULT_TOKEN_TYPE: str = "jwt"
DEFAULT_TOKEN_FORMAT: str = "JWT {token}"
DEFAULT_SESSION_TRIES: int | None = None
DEFAULT_SESSION_TIMEOUT: int | None = None
DEFAULT_SESSION_VERIFY: bool = False
DEFAULT_OPTIONS: dict = {
    "DOMAIN": "http://example.com",
    "API_PREFIX": "api/v1",
    "TOKEN_TYPE": "jwt",
    "TOKEN_FORMAT": "JWT {token}",
    "LOGIN": "auth/login/",
    "LOGOUT": "auth/logout/",
    "USE_DASHES": False,
    "SESSION_TRIES": None,
    "SESSION_TIMEOUT": None,
    "SESSION_VERIFY": False,
}

logger = logging.getLogger(__name__)


class RestResource:
    """
    Resource provides the main functionality behind a Django Rest Framework based API. 
    It handles the attribute -> url, kwarg -> query param, and other related behind the 
    scenes python to HTTP transformations. It's goal is to represent a single resource
    which may or may not have children.
    """

    _store: dict = {}
    _options: dict = {}

    def __init__(self, *args, **kwargs):
        self._store = kwargs
        self._session = kwargs.get('session')

        if self._session is None:
            self._session = requests.Session()

        if "options" in self._store:
            self._options = self._store["options"]
        else:
            self.options = DEFAULT_OPTIONS
        if "use_token" not in self._store:
            self._store["use_token"] = False

    def __call__(self, id=None):
        """
        Returns a new instance of self modified by one or more of the available
        parameters. These allows us to do things like override format for a
        specific request, and enables the api.resource(ID).get() syntax to get
        a specific resource by it's ID.
        """

        kwargs = {
            "token": self._store["token"],
            "use_token": self._store["use_token"],
            "base_url": self._store["base_url"],
            "options": self._options,
            "session": self._session,
        }

        new_url = self._store["base_url"]
        if id is not None:
            new_url = f"{new_url}{id}/"

        if not new_url.endswith("/"):
            new_url += "/"

        kwargs["base_url"] = new_url

        return self._get_resource(**kwargs)

    def __getattr__(self, item: str) -> "RestResource":
        # Don't allow access to 'private' by convention attributes.
        if item.startswith("_"):
            raise AttributeError(item)

        kwargs = self._copy_kwargs(self._store)
        if self._options.get("USE_DASHES", False):
            item = item.replace("_", "-")
        kwargs.update({"base_url": "{0}{1}/".format(self._store["base_url"], item)})

        return self._get_resource(**kwargs)

    def _copy_kwargs(self, dictionary: dict) -> dict:
        kwargs = {}
        for key, value in dictionary.items():
            kwargs[key] = value

        return kwargs

    def _check_for_errors(self, resp, url):
        if 400 <= resp.status_code <= 499:
            exception_class = (
                HttpNotFoundError if resp.status_code == 404 else HttpClientError
            )
            raise exception_class(
                "Client Error %s: %s" % (resp.status_code, url),
                response=resp,
                content=resp.content,
            )
        elif 500 <= resp.status_code <= 599:
            raise HttpServerError(
                "Server Error %s: %s" % (resp.status_code, url),
                response=resp,
                content=resp.content,
            )

    def _handle_redirect(self, resp, **kwargs):
        # @@@ Hacky, see description in __call__
        resource_obj = self(url_override=resp.headers["location"])
        return resource_obj.get(**kwargs)

    def _try_to_serialize_response(self, resp):
        if resp.status_code in [204, 205]:
            return

        if resp.content:
            if isinstance(resp.content, bytes):
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
            return  # @@@ We should probably do some sort of error here?

    def url(self, args=None):
        url = self._store["base_url"]
        if args:
            url += "?{0}".format(args)
        return url

    def _get_headers(self):
        headers = DEFAULT_HEADERS
        if self._store["use_token"]:
            if "token" not in self._store:
                raise RestBaseException("No Token")
            authorization_str = self._options["TOKEN_FORMAT"].format(
                token=self._store["token"]
            )
            headers["Authorization"] = authorization_str

        return headers

    def raw_get(self, extra_headers: dict = None, **kwargs):
        """Call get and return raw request respond."""
        args = None
        if "extra" in kwargs:
            args = kwargs["extra"]
        headers = (
            self._get_headers() | extra_headers
            if extra_headers
            else self._get_headers()
        )

        return self._session.get(self.url(args), headers=headers)

    def get(self, extra_headers: dict = None, **kwargs):
        """Call get and process respond."""
        resp = self.raw_get(extra_headers, **kwargs)
        return self._process_response(resp)

    def raw_post(self, data: dict = None, extra_headers: dict = None, **kwargs):
        """Call requests post and return raw respond."""
        payload = json.dumps(data) if data and "files" not in kwargs else data
        headers = (
            self._get_headers() | extra_headers
            if extra_headers
            else self._get_headers()
        )
        try:
            resp = self._session.post(self.url(), data=payload, headers=headers, **kwargs)
        except requests.exceptions.SSLError as err:
            raise HttpCouldNotVerifyServerError(
                "Could not verify the server's SSL certificate", err,
            )
        return resp

    def post(self, data: dict = None, extra_headers: dict = None, **kwargs):
        """Call post and process respond."""
        resp = self.raw_post(data, extra_headers, **kwargs)
        return self._process_response(resp)

    def raw_patch(self, data=None, extra_headers: dict = None, **kwargs):
        """Call patch and return raw request respond."""
        payload = json.dumps(data) if data and "files" not in kwargs else data
        headers = (
            self._get_headers() | extra_headers
            if extra_headers
            else self._get_headers()
        )

        try:
            resp = self._session.patch(self.url(), data=payload, headers=headers, **kwargs)
        except requests.exceptions.SSLError as err:
            raise HttpCouldNotVerifyServerError(
                "Could not verify the server's SSL certificate", err,
            )
        return resp

    def patch(self, data=None, extra_headers: dict = None, **kwargs):
        """Call patch and process respond."""
        resp = self.raw_patch(data, extra_headers, **kwargs)
        return self._process_response(resp)

    def raw_put(self, data=None, extra_headers: dict = None, **kwargs):
        """Call Put and return raw request respond."""
        payload = json.dumps(data) if data and "files" not in kwargs else data
        headers = (
            self._get_headers() | extra_headers
            if extra_headers
            else self._get_headers()
        )

        try:
            resp = self._session.put(self.url(), data=payload, headers=headers, **kwargs)
        except requests.exceptions.SSLError as err:
            raise HttpCouldNotVerifyServerError(
                "Could not verify the server's SSL certificate", err,
            )
        return resp

    def put(self, data=None, extra_headers: dict = None, **kwargs):
        """Call Put and process respond."""
        resp = self.raw_put(data, extra_headers, **kwargs)
        return self._process_response(resp)

    def raw_delete(self, data=None, extra_headers: dict = None, **kwargs):
        """Call Delete and return raw request respond."""
        payload = json.dumps(data) if data and "files" not in kwargs else data
        headers = (
            self._get_headers() | extra_headers
            if extra_headers
            else self._get_headers()
        )

        try:
            resp = self._session.delete(self.url(), data=payload, headers=headers, **kwargs)
        except requests.exceptions.SSLError as err:
            raise HttpCouldNotVerifyServerError(
                "Could not verify the server's SSL certificate", err,
            )
        return resp

    def delete(self, data=None, extra_headers: dict = None, **kwargs):
        """Call Delete and process respond. Return True if ok"""
        resp = self.raw_delete(data, extra_headers, **kwargs)
        if 200 <= resp.status_code <= 299:
            if resp.status_code == 204:
                return True
            else:
                return True  # @@@ Should this really be True?
        else:
            return False

    def _get_resource(self, **kwargs):
        return self.__class__(**kwargs)


class _TimeoutHTTPAdapter(requests.adapters.HTTPAdapter):
    """
    Custom http adapter to allow setting timeouts on http verbs.
    See https://github.com/psf/requests/issues/2011#issuecomment-64440818
    and surrounding discussion in that thread for why this is necessary.
    Short answer is that Session() objects don't support timeouts.
    """
    def __init__(self, timeout=None, *args, **kwargs):
        self.timeout = timeout
        super(_TimeoutHTTPAdapter, self).__init__(*args, **kwargs)

    def send(self, *args, **kwargs):
        kwargs['timeout'] = self.timeout
        return super(_TimeoutHTTPAdapter, self).send(*args, **kwargs)


class Api:
    """
    Entry level class to access the API.

    It utilizes request sessions to handle retries
    """
    token: str | None = None
    resource_class: RestResource = RestResource
    use_token: bool = True
    options: dict | None = None

    def __init__(self, options: dict):
        self.options = options
        if "DOMAIN" not in self.options:
            raise RestBaseException("DOMAIN is missing in options")

        if "API_PREFIX" not in self.options:
            self.options["API_PREFIX"] = API_PREFIX
        self.base_url = "{0}/{1}".format(
            self.options["DOMAIN"], self.options["API_PREFIX"]
        )
        if "TOKEN_TYPE" not in self.options:
            self.options["TOKEN_TYPE"] = DEFAULT_TOKEN_TYPE
        if "TOKEN_FORMAT" not in self.options:
            self.options["TOKEN_FORMAT"] = DEFAULT_TOKEN_FORMAT

        # Create session and initialize to handle timeouts and retries
        self.session = requests.Session()
        self.session.verify = self.options.get("SESSION_VERIFY", DEFAULT_SESSION_VERIFY)
        retries = self.options.get("SESSION_TRIES", DEFAULT_SESSION_TRIES)
        timeout = self.options.get("SESSION_TIMEOUT", DEFAULT_SESSION_TIMEOUT)
        if retries is not None or timeout is not None:
            adapter = _TimeoutHTTPAdapter(max_retries=retries, timeout=timeout)
            self.session.mount('https://', adapter)
            self.session.mount('http://', adapter)

    def set_token(self, token):
        self.token = token

    def login(self, password, username=None):
        assert "LOGIN" in self.options
        # This allows us to support both {'email': username} and {'username": username}
        # Default to 'username' which is the default DRF behavior
        username_key = self.options.get("USERNAME_KEY", "username")
        data = {"password": password}
        data[username_key] = username
        url = "{0}/{1}".format(self.base_url, self.options["LOGIN"])

        payload = json.dumps(data)
        try:
            r = self.session.post(url, data=payload, headers=DEFAULT_HEADERS)
        except requests.exceptions.SSLError as err:
            raise HttpCouldNotVerifyServerError(
                "Could not verify the server's SSL certificate", err,
            )
        if r.status_code in [200, 201]:
            content = json.loads(r.content.decode())
            self.token = content.get(self.options["TOKEN_TYPE"])
            if self.token is None:
                # Default to "token" if token_type is not used by server
                self.token = content.get("token")
            self.username = username
            return True
        else:
            logger.error(
                "Login failed: " + str(r.status_code) + " " + r.content.decode()
            )
            return False

    def logout(self):
        assert "LOGOUT" in self.options
        url = f"{self.base_url}/{self.options['LOGOUT']}"
        headers = DEFAULT_HEADERS
        headers["Authorization"] = self.options["TOKEN_FORMAT"].format(token=self.token)

        try:
            r = self.session.post(url, headers=headers)
        except requests.exceptions.SSLError as err:
            raise HttpCouldNotVerifyServerError(
                "Could not verify the server's SSL certificate", err,
            )
        if r.status_code == 204:
            logger.info(f"Goodbye @{self.username}")
            self.username = None
            self.token = None
        else:
            logger.error(
                "Logout failed: " + str(r.status_code) + " " + r.content.decode()
            )

    def __getattr__(self, item):
        """
        Instead of raising an attribute error, the undefined attribute will
        return a Resource Instance which can be used to make calls to the
        resource identified by the attribute.
        """

        # Don't allow access to 'private' by convention attributes.
        if item.startswith("_"):
            raise AttributeError(item)

        if self.options.get("USE_DASHES", False):
            item = item.replace("_", "-")

        kwargs = {
            "token": self.token,
            "base_url": f"{self.base_url}/{item}/",
            "use_token": self.use_token,
            "options": self.options,
        }

        return self._get_resource(**kwargs)

    def _get_resource(self, **kwargs):
        return self.resource_class(**kwargs)
