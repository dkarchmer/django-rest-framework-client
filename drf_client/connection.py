"""
See https://gist.github.com/dkarchmer/d85e55f9ed5450ba58cb.

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
    }.

    api = RestApi(options)
    api.login(email='user1@test.com', password='user1')
    obj_list = api.some_model.get()
    logger.debug('Found {0} groups'.format(obj_list['count']))
    obj_one = api.some_model(1).get()
    api.logout()

    # Running get as coroutine (Asyncio)
    obj_list = asyncio.run(self.api.some_model.async_get())
"""

from __future__ import annotations

import json
import logging

import httpx
import requests
import requests.adapters

from .exceptions import (
    HttpClientError,
    HttpCouldNotVerifyServerError,
    HttpNotFoundError,
    HttpServerError,
    RestBaseException,
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
    scenes python to HTTP transformations. Its goal is to represent a single resource
    which may or may not have children.
    """

    _store: dict
    _options: dict
    _session: requests.Session

    def __init__(self, **kwargs) -> None:
        """Initialize the RestResource with configuration from kwargs."""
        self._store = kwargs
        session = kwargs.get("session")
        if session is None:
            session = requests.Session()
        self._session = session

        if "options" in self._store:
            self._options = self._store["options"]
        else:
            self.options = DEFAULT_OPTIONS
        if "use_token" not in self._store:
            self._store["use_token"] = False

    def __call__(self, id_: str | int | None = None, url_override: str | None = None) -> RestResource:
        """
        Return a new instance of self modified by one or more of the available parameters.

        This allows us to do things like override format for a
        specific request, and enables the api.resource(ID).get() syntax to get
        a specific resource by its ID.

        Returns:
            A new RestResource instance with modified parameters.

        """
        kwargs = {
            "token": self._store["token"],
            "use_token": self._store["use_token"],
            "base_url": self._store["base_url"],
            "options": self._options,
            "session": self._session,
        }

        if url_override is not None:
            new_url = url_override
        else:
            new_url = self._store["base_url"]
            if id_ is not None:
                new_url = f"{new_url}{id_}/"

        if not new_url.endswith("/"):
            new_url += "/"

        kwargs["base_url"] = new_url

        return self._get_resource(**kwargs)

    def __getattr__(self, item: str) -> RestResource:
        """
        Get a nested resource by attribute name.

        Args:
            item: The attribute name to access.

        Returns:
            A new RestResource for the nested endpoint.

        Raises:
            AttributeError: If the attribute starts with underscore.

        """
        # Don't allow access to 'private' by convention attributes.
        if item.startswith("_"):
            raise AttributeError(item)

        kwargs = dict(self._store)
        if self._options.get("USE_DASHES", False):
            item = item.replace("_", "-")
        kwargs.update({"base_url": f"{self._store['base_url']}{item}/"})

        return self._get_resource(**kwargs)

    def _check_for_errors(self, resp: requests.Response | httpx.Response, url: str) -> None:
        if 400 <= resp.status_code <= 499:  # ty: ignore[unsupported-operator]
            exception_class = HttpNotFoundError if resp.status_code == 404 else HttpClientError
            msg = f"Client Error {resp.status_code}: {url}"
            raise exception_class(
                msg,
                response=resp,
                content=resp.content,
            )
        if 500 <= resp.status_code <= 599:  # ty: ignore[unsupported-operator]
            msg = f"Server Error {resp.status_code}: {url}"
            raise HttpServerError(msg, response=resp, content=resp.content)

    def _handle_redirect(self, resp: requests.Response | httpx.Response, **kwargs) -> dict | list | bytes | None:
        # @@@ Hacky, see description in __call__
        resource_obj = self(url_override=resp.headers["location"])
        return resource_obj.get(**kwargs)

    def _try_to_serialize_response(self, resp: requests.Response | httpx.Response) -> dict | list | bytes | None:
        if resp.status_code in {204, 205}:
            return None

        if resp.content:
            if isinstance(resp.content, bytes):
                try:
                    encoding = requests.utils.guess_json_utf(resp.content)
                    return json.loads(resp.content.decode(encoding))
                except json.JSONDecodeError, UnicodeDecodeError:
                    return resp.content
            return json.loads(resp.content)
        return resp.content

    def _process_response(self, resp: requests.Response | httpx.Response) -> dict | list | bytes | None:
        self._check_for_errors(resp, self.url())

        if 200 <= resp.status_code <= 299:  # ty: ignore[unsupported-operator]
            return self._try_to_serialize_response(resp)
        return None  # @@@ We should probably do some sort of error here?

    def url(self, args: str | None = None) -> str:
        """
        Build the full URL for the resource.

        Args:
            args: Optional query string arguments to append to the URL.

        Returns:
            The complete URL string for this resource.

        """
        url = self._store["base_url"]
        if args:
            url += f"?{args}"
        return url

    def _get_headers(self) -> dict:
        headers = DEFAULT_HEADERS
        if self._store["use_token"]:
            if "token" not in self._store:
                msg = "No Token"
                raise RestBaseException(msg)
            authorization_str = self._options["TOKEN_FORMAT"].format(token=self._store["token"])
            headers["Authorization"] = authorization_str

        return headers

    def raw_get(self, extra_headers: dict | None = None, **kwargs) -> requests.Response:
        """
        Call get and return raw request respond.

        Returns:
            The raw HTTP response object.

        """
        args = None
        if "extra" in kwargs:
            args = kwargs["extra"]
        headers = self._get_headers() | extra_headers if extra_headers else self._get_headers()

        return self._session.get(self.url(args), headers=headers)

    def get(self, extra_headers: dict | None = None, **kwargs) -> dict | list | bytes | None:
        """
        Call get and process respond.

        Returns:
            The deserialized response data (dict, list, bytes, or None).

        """
        resp = self.raw_get(extra_headers, **kwargs)
        return self._process_response(resp)

    def raw_post(self, data: dict | None = None, extra_headers: dict | None = None, **kwargs) -> requests.Response:
        """
        Call requests post and return raw respond.

        Returns:
            The raw HTTP response object.

        Raises:
            HttpCouldNotVerifyServerError: If SSL certificate verification fails.

        """
        payload = json.dumps(data) if data and "files" not in kwargs else data
        headers = self._get_headers() | extra_headers if extra_headers else self._get_headers()
        try:
            resp = self._session.post(self.url(), data=payload, headers=headers, **kwargs)
        except requests.exceptions.SSLError as e:
            msg = "Could not verify the server's SSL certificate"
            raise HttpCouldNotVerifyServerError(msg) from e
        return resp

    def post(self, data: dict | None = None, extra_headers: dict | None = None, **kwargs) -> dict | list | bytes | None:
        """
        Call post and process respond.

        Returns:
            The deserialized response data (dict, list, bytes, or None).

        """
        resp = self.raw_post(data, extra_headers, **kwargs)
        return self._process_response(resp)

    def raw_patch(self, data: dict | None = None, extra_headers: dict | None = None, **kwargs) -> requests.Response:
        """
        Call patch and return raw request respond.

        Returns:
            The raw HTTP response object.

        Raises:
            HttpCouldNotVerifyServerError: If SSL certificate verification fails.

        """
        payload = json.dumps(data) if data and "files" not in kwargs else data
        headers = self._get_headers() | extra_headers if extra_headers else self._get_headers()

        try:
            resp = self._session.patch(self.url(), data=payload, headers=headers, **kwargs)
        except requests.exceptions.SSLError as e:
            msg = "Could not verify the server's SSL certificate"
            raise HttpCouldNotVerifyServerError(msg) from e
        return resp

    def patch(
        self, data: dict | None = None, extra_headers: dict | None = None, **kwargs
    ) -> dict | list | bytes | None:
        """
        Call patch and process respond.

        Returns:
            The deserialized response data (dict, list, bytes, or None).

        """
        resp = self.raw_patch(data, extra_headers, **kwargs)
        return self._process_response(resp)

    def raw_put(self, data: dict | None = None, extra_headers: dict | None = None, **kwargs) -> requests.Response:
        """
        Call Put and return raw request respond.

        Returns:
            The raw HTTP response object.

        Raises:
            HttpCouldNotVerifyServerError: If SSL certificate verification fails.

        """
        payload = json.dumps(data) if data and "files" not in kwargs else data
        headers = self._get_headers() | extra_headers if extra_headers else self._get_headers()

        try:
            resp = self._session.put(self.url(), data=payload, headers=headers, **kwargs)
        except requests.exceptions.SSLError as e:
            msg = "Could not verify the server's SSL certificate"
            raise HttpCouldNotVerifyServerError(msg) from e
        return resp

    def put(self, data: dict | None = None, extra_headers: dict | None = None, **kwargs) -> dict | list | bytes | None:
        """
        Call Put and process respond.

        Returns:
            The deserialized response data (dict, list, bytes, or None).

        """
        resp = self.raw_put(data, extra_headers, **kwargs)
        return self._process_response(resp)

    def raw_delete(self, data: dict | None = None, extra_headers: dict | None = None, **kwargs) -> requests.Response:
        """
        Call Delete and return raw request respond.

        Returns:
            The raw HTTP response object.

        Raises:
            HttpCouldNotVerifyServerError: If SSL certificate verification fails.

        """
        payload = json.dumps(data) if data and "files" not in kwargs else data
        headers = self._get_headers() | extra_headers if extra_headers else self._get_headers()

        try:
            resp = self._session.delete(self.url(), data=payload, headers=headers, **kwargs)
        except requests.exceptions.SSLError as e:
            msg = "Could not verify the server's SSL certificate"
            raise HttpCouldNotVerifyServerError(msg) from e
        return resp

    def delete(self, data: dict | None = None, extra_headers: dict | None = None, **kwargs) -> bool:
        """
        Call Delete and process respond.

        Returns:
            True if the deletion was successful (status code 2xx), False otherwise.

        """
        resp = self.raw_delete(data, extra_headers, **kwargs)
        if 200 <= resp.status_code <= 299:  # ty: ignore[unsupported-operator]
            if resp.status_code == 204:
                return True
            return True  # @@@ Should this really be True?
        return False

    async def async_raw_get(self, extra_headers: dict | None = None, **kwargs) -> httpx.Response:
        """
        Call async get and return raw request respond.

        Returns:
            The raw HTTP response object.

        """
        args = kwargs.get("extra")
        headers = self._get_headers() | (extra_headers or {})
        async with httpx.AsyncClient() as client:
            return await client.get(self.url(args), headers=headers)

    async def async_get(self, extra_headers: dict | None = None, **kwargs) -> dict | list | bytes | None:
        """
        Call async get and process respond.

        Returns:
            The deserialized response data (dict, list, bytes, or None).

        """
        resp = await self.async_raw_get(extra_headers, **kwargs)
        return self._process_response(resp)

    async def async_raw_post(
        self, data: dict | None = None, extra_headers: dict | None = None, **kwargs
    ) -> httpx.Response:
        """
        Call async raw post and return raw request respond.

        Returns:
            The raw HTTP response object.

        """
        payload = json.dumps(data) if data and "files" not in kwargs else data
        headers = self._get_headers() | (extra_headers or {})
        async with httpx.AsyncClient() as client:
            return await client.post(self.url(), content=payload, headers=headers, **kwargs)

    async def async_post(
        self, data: dict | None = None, extra_headers: dict | None = None, **kwargs
    ) -> dict | list | bytes | None:
        """
        Call async post and process respond.

        Returns:
            The deserialized response data (dict, list, bytes, or None).

        """
        resp = await self.async_raw_post(data, extra_headers, **kwargs)
        return self._process_response(resp)

    async def async_raw_patch(
        self, data: dict | None = None, extra_headers: dict | None = None, **kwargs
    ) -> httpx.Response:
        """
        Call async raw patch and process respond.

        Returns:
            The raw HTTP response object.

        """
        payload = json.dumps(data) if data and "files" not in kwargs else data
        headers = self._get_headers() | (extra_headers or {})
        async with httpx.AsyncClient() as client:
            return await client.patch(self.url(), content=payload, headers=headers, **kwargs)

    async def async_patch(
        self, data: dict | None = None, extra_headers: dict | None = None, **kwargs
    ) -> dict | list | bytes | None:
        """
        Call async patch and process respond.

        Returns:
            The deserialized response data (dict, list, bytes, or None).

        """
        resp = await self.async_raw_patch(data, extra_headers, **kwargs)
        return self._process_response(resp)

    async def async_raw_put(
        self, data: dict | None = None, extra_headers: dict | None = None, **kwargs
    ) -> httpx.Response:
        """
        Call async raw put and process respond.

        Returns:
            The raw HTTP response object.

        """
        payload = json.dumps(data) if data and "files" not in kwargs else data
        headers = self._get_headers() | (extra_headers or {})
        async with httpx.AsyncClient() as client:
            return await client.put(self.url(), content=payload, headers=headers, **kwargs)

    async def async_put(
        self, data: dict | None = None, extra_headers: dict | None = None, **kwargs
    ) -> dict | list | bytes | None:
        """
        Call async put and process respond.

        Returns:
            The deserialized response data (dict, list, bytes, or None).

        """
        resp = await self.async_raw_put(data, extra_headers, **kwargs)
        return self._process_response(resp)

    async def async_raw_delete(self, extra_headers: dict | None = None, **kwargs) -> httpx.Response:
        """
        Call async raw delete and process respond.

        Returns:
            The raw HTTP response object.

        """
        headers = self._get_headers() | (extra_headers or {})
        async with httpx.AsyncClient() as client:
            return await client.delete(self.url(), headers=headers, **kwargs)

    async def async_delete(self, extra_headers: dict | None = None, **kwargs) -> bool:
        """
        Call async delete and process respond.

        Returns:
            True if the deletion was successful (status code 2xx), False otherwise.

        """
        resp = await self.async_raw_delete(extra_headers, **kwargs)
        if 200 <= resp.status_code <= 299:
            if resp.status_code == 204:
                return True
            return True  # @@@ Should this really be True?
        return False

    def _get_resource(self, **kwargs) -> RestResource:
        return self.__class__(**kwargs)


class _TimeoutHTTPAdapter(requests.adapters.HTTPAdapter):
    """
    Custom http adapter to allow setting timeouts on http verbs.

    See https://github.com/psf/requests/issues/2011#issuecomment-64440818
    and surrounding discussion in that thread for why this is necessary.
    Short answer is that Session() objects don't support timeouts.
    """

    def __init__(self, timeout: int | None = None, *args, **kwargs) -> None:
        """Initialize the adapter with a timeout value."""
        self.timeout = timeout
        super().__init__(*args, **kwargs)

    def send(self, *args, **kwargs) -> requests.Response:
        kwargs["timeout"] = self.timeout
        return super().send(*args, **kwargs)


class Api:
    """
    Entry level class to access the API.

    It utilizes request sessions to handle retries
    """

    token: str | None = None
    resource_class: type[RestResource] = RestResource
    use_token: bool = True
    options: dict

    def __init__(self, options: dict) -> None:
        """
        Initialize the API client with configuration options.

        Args:
            options: Configuration dictionary with API settings like DOMAIN,
                API_PREFIX, TOKEN_TYPE, etc.

        Raises:
            RestBaseException: If DOMAIN is missing in options.

        """
        self.options = options
        if "DOMAIN" not in self.options:
            msg = "DOMAIN is missing in options"
            raise RestBaseException(msg)

        if "API_PREFIX" not in self.options:
            self.options["API_PREFIX"] = API_PREFIX
        self.base_url = f"{self.options['DOMAIN']}/{self.options['API_PREFIX']}"
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
            self.session.mount("https://", adapter)
            self.session.mount("http://", adapter)

    def set_token(self, token: str) -> None:
        """
        Set the authentication token for API requests.

        Args:
            token: The authentication token to use for subsequent API calls.

        """
        self.token = token

    def login(self, password: str, username: str | None = None) -> bool:
        """
        Authenticate with the API using username and password.

        Sends credentials to the login endpoint and stores the authentication
        token if successful.

        Args:
            password: The user's password.
            username: The username or email for authentication. Optional if
                already set in previous login.

        Returns:
            True if login was successful, False otherwise.

        Raises:
            HttpCouldNotVerifyServerError: If SSL certificate verification fails.

        """
        assert "LOGIN" in self.options
        # This allows us to support both {'email': username} and {'username": username}
        # Default to 'username' which is the default DRF behavior
        username_key = self.options.get("USERNAME_KEY", "username")
        data = {"password": password}
        data[username_key] = username
        url = f"{self.base_url}/{self.options['LOGIN']}"

        payload = json.dumps(data)
        try:
            r = self.session.post(url, data=payload, headers=DEFAULT_HEADERS)
        except requests.exceptions.SSLError as e:
            msg = "Could not verify the server's SSL certificate"
            raise HttpCouldNotVerifyServerError(msg) from e
        if r.status_code in {200, 201}:
            content = json.loads(r.content.decode())
            self.token = content.get(self.options["TOKEN_TYPE"])
            if self.token is None:
                # Default to "token" if token_type is not used by server
                self.token = content.get("token")
            self.username = username
            return True
        logger.error("Login failed: %s %s", r.status_code, r.content.decode())
        return False

    def logout(self) -> None:
        """
        Logout the current user and clear authentication credentials.

        Sends a POST request to the logout endpoint and clears the stored
        username and token if successful.

        Raises:
            HttpCouldNotVerifyServerError: If SSL certificate verification fails.

        """
        assert "LOGOUT" in self.options
        url = f"{self.base_url}/{self.options['LOGOUT']}"
        headers = DEFAULT_HEADERS
        headers["Authorization"] = self.options["TOKEN_FORMAT"].format(token=self.token)

        try:
            r = self.session.post(url, headers=headers)
        except requests.exceptions.SSLError as e:
            msg = "Could not verify the server's SSL certificate"
            raise HttpCouldNotVerifyServerError(msg) from e
        if r.status_code == 204:
            logger.info("Goodbye @%s", self.username)
            self.username = None
            self.token = None
        else:
            logger.error("Logout failed: %s %s", r.status_code, r.content.decode())

    def __getattr__(self, item: str) -> RestResource:
        """
        Return a Resource Instance for the requested attribute.

        Instead of raising an attribute error, the undefined attribute will
        return a Resource Instance which can be used to make calls to the
        resource identified by the attribute.

        Returns:
            A RestResource instance for the requested API endpoint.

        Raises:
            AttributeError: If the attribute name starts with an underscore.

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

    def _get_resource(self, **kwargs) -> RestResource:
        return self.resource_class(**kwargs)
