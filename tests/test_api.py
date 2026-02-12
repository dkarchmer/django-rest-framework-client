"""Test cases for the Api class."""

import asyncio
import json

import httpx
import pytest
import respx
from requests_mock import Mocker

from drf_client.connection import Api
from drf_client.exceptions import HttpClientError, HttpServerError


@pytest.fixture
def api_options() -> dict:
    """
    Provide API configuration options for tests.

    Returns:
        A dictionary containing API configuration options.

    """
    return {
        "DOMAIN": "https://example.com",
        "API_PREFIX": "api/v1",
        "TOKEN_TYPE": "jwt",
        "TOKEN_FORMAT": "JWT {token}",
        "LOGIN": "auth/login/",
        "LOGOUT": "auth/logout/",
        "USE_DASHES": False,
    }


@pytest.fixture
def api(api_options: dict) -> Api:
    """
    Provide an Api instance for tests.

    Returns:
        A configured Api instance for testing.

    """
    return Api(options=api_options)


class TestApi:
    """Test the Api class for DRF client functionality."""

    def test_init(self, api: Api) -> None:
        """Test Api initialization with correct base URL and options."""
        assert api.base_url == "https://example.com/api/v1"
        assert api.use_token
        assert api.options["TOKEN_TYPE"] == "jwt"
        assert api.options["TOKEN_FORMAT"] == "JWT {token}"

    def test_set_token(self, api: Api) -> None:
        """Test setting authentication token."""
        assert api.token is None
        api.set_token("big-token")
        assert api.token == "big-token"

    def test_login(self, api: Api, requests_mock: Mocker) -> None:
        """Test successful login with username and password."""
        payload = {"jwt": "big-token", "username": "user1"}
        requests_mock.post("https://example.com/api/v1/auth/login/", text=json.dumps(payload))

        ok = api.login(username="user1@test.com", password="pass")
        assert ok
        assert api.username == "user1@test.com"
        assert api.token == "big-token"

    def test_logout(self, api: Api, requests_mock: Mocker) -> None:
        """Test logout clears username and token."""
        payload = {"jwt": "big-token", "username": "user1"}
        requests_mock.post("https://example.com/api/v1/auth/login/", text=json.dumps(payload))
        requests_mock.post("https://example.com/api/v1/auth/logout/", status_code=204)

        ok = api.login(username="user1@test.com", password="pass")
        assert ok

        api.logout()
        assert api.username is None
        assert api.token is None

    def test_get_list(self, api: Api, requests_mock: Mocker) -> None:
        """Test GET request to list endpoint."""
        payload = {"result": ["a", "b", "c"]}
        requests_mock.get("https://example.com/api/v1/test/", text=json.dumps(payload))

        resp = api.test.get()
        assert isinstance(resp, dict)
        assert resp["result"] == ["a", "b", "c"]

    def test_get_detail(self, api: Api, requests_mock: Mocker) -> None:
        """Test GET request to detail endpoint with resource ID."""
        payload = {"a": "b", "c": "d"}
        requests_mock.get("https://example.com/api/v1/test/my-detail/", text=json.dumps(payload))

        resp = api.test("my-detail").get()
        assert resp == {"a": "b", "c": "d"}

    def test_get_detail_with_action(self, api: Api, requests_mock: Mocker) -> None:
        """Test GET request to detail endpoint with custom action."""
        payload = {"a": "b", "c": "d"}
        requests_mock.get(
            "https://example.com/api/v1/test/my-detail/action/",
            text=json.dumps(payload),
        )

        resp = api.test("my-detail").action.get()
        assert resp == {"a": "b", "c": "d"}

    def test_get_with_use_dashes(self, api: Api, requests_mock: Mocker) -> None:
        """Test that we can replace underscore with dashes."""
        api.options["USE_DASHES"] = True
        payload = {"a": "b", "c": "d"}
        requests_mock.get(
            "https://example.com/api/v1/test-one/my-detail/action/",
            text=json.dumps(payload),
        )

        resp = api.test_one.my_detail.action.get()
        assert resp == {"a": "b", "c": "d"}

    def test_get_detail_with_extra_args(self, api: Api, requests_mock: Mocker) -> None:
        """Test GET request with extra query arguments."""
        payload = {"a": "b", "c": "d"}
        requests_mock.get("https://example.com/api/v1/test/my-detail/", text=json.dumps(payload))

        resp = api.test("my-detail").get(foo="bar")
        assert resp == {"a": "b", "c": "d"}

    def test_post(self, api: Api, requests_mock: Mocker) -> None:
        """Test POST request to create a resource."""
        payload = {"foo": ["a", "b", "c"]}
        result = {"id": 1}
        requests_mock.post("https://example.com/api/v1/test/", text=json.dumps(result))

        resp = api.test.post(payload)
        assert isinstance(resp, dict)
        assert resp["id"] == 1

    def test_patch(self, api: Api, requests_mock: Mocker) -> None:
        """Test PATCH request to partially update a resource."""
        payload = {"foo": ["a", "b", "c"]}
        result = {"id": 1}
        requests_mock.patch("https://example.com/api/v1/test/my-detail/", text=json.dumps(result))

        resp = api.test("my-detail").patch(payload)
        assert isinstance(resp, dict)
        assert resp["id"] == 1

    def test_put(self, api: Api, requests_mock: Mocker) -> None:
        """Test PUT request to fully update a resource."""
        payload = {"foo": ["a", "b", "c"]}
        result = {"id": 1}
        requests_mock.put("https://example.com/api/v1/test/my-detail/", text=json.dumps(result))

        resp = api.test("my-detail").put(payload)
        assert isinstance(resp, dict)
        assert resp["id"] == 1

    def test_delete(self, api: Api, requests_mock: Mocker) -> None:
        """Test DELETE request to remove a resource."""
        result = {"id": 1}
        requests_mock.delete("https://example.com/api/v1/test/my-detail/", text=json.dumps(result))

        deleted = api.test("my-detail").delete()
        assert deleted

        result = {"id": 2}
        requests_mock.delete("https://example.com/api/v1/test/my-detail2/", text=json.dumps(result))

        deleted = api.test("my-detail2").delete(data={"foo": "bar"})
        assert deleted

    def test_post_with_error(self, api: Api, requests_mock: Mocker) -> None:
        """Test POST request error handling for 4xx and 5xx responses."""
        payload = {"foo": ["a", "b", "c"]}
        result = {"id": 1}
        requests_mock.post("https://example.com/api/v1/test/", status_code=400, text=json.dumps(result))

        with pytest.raises(HttpClientError):
            api.test.post(payload)

        requests_mock.post("https://example.com/api/v1/test/", status_code=404, text=json.dumps(result))

        with pytest.raises(HttpClientError):
            api.test.post(payload)

        requests_mock.post("https://example.com/api/v1/test/", status_code=500, text=json.dumps(result))

        with pytest.raises(HttpServerError):
            api.test.post(payload)

    @respx.mock
    def test_async_get_list(self, api: Api) -> None:
        """Test async GET request to list endpoint."""
        payload = {"result": ["a", "b", "c"]}
        respx.get("https://example.com/api/v1/test/").mock(return_value=httpx.Response(200, json=payload))

        resp = asyncio.run(api.test.async_get())
        assert isinstance(resp, dict)
        assert resp["result"] == ["a", "b", "c"]

    @respx.mock
    def test_async_get_detail(self, api: Api) -> None:
        """Test async GET request to detail endpoint."""
        payload = {"a": "b", "c": "d"}
        respx.get("https://example.com/api/v1/test/my-detail/").mock(return_value=httpx.Response(200, json=payload))
        resp = asyncio.run(api.test("my-detail").async_get())
        assert resp == {"a": "b", "c": "d"}

    @respx.mock
    def test_async_get_detail_with_action(self, api: Api) -> None:
        """Test async GET request with custom action and URL verification."""
        payload = {"a": "b", "c": "d"}
        respx.get("https://example.com/api/v1/test/my-detail/").mock(return_value=httpx.Response(200, json=payload))
        resp = api.test("my-detail").action.url()
        assert resp == "https://example.com/api/v1/test/my-detail/action/"
        resp = asyncio.run(api.test("my-detail").async_get())
        assert resp == {"a": "b", "c": "d"}

    @respx.mock
    def test_async_get_with_use_dashes(self, api: Api) -> None:
        """Test that we can replace underscore with dashes in async requests."""
        api.options["USE_DASHES"] = True
        payload = {"a": "b", "c": "d"}
        respx.get("https://example.com/api/v1/test-one/my-detail/action/").mock(
            return_value=httpx.Response(200, json=payload)
        )
        resp = asyncio.run(api.test_one.my_detail.action.async_get())
        assert resp == {"a": "b", "c": "d"}

    @respx.mock
    def test_async_get_detail_with_extra_args(self, api: Api) -> None:
        """Test async GET request with extra query arguments."""
        payload = {"a": "b", "c": "d"}
        respx.get("https://example.com/api/v1/test/my-detail/").mock(return_value=httpx.Response(200, json=payload))
        resp = asyncio.run(api.test("my-detail").async_get(foo="bar"))
        assert resp == {"a": "b", "c": "d"}

    @respx.mock
    def test_async_post(self, api: Api) -> None:
        """Test async POST request to create a resource."""
        payload = {"foo": ["a", "b", "c"]}
        result = {"id": 1}
        respx.post("https://example.com/api/v1/test/").mock(return_value=httpx.Response(200, json=result))
        resp = asyncio.run(api.test.async_post(payload))
        assert isinstance(resp, dict)
        assert resp["id"] == 1

    @respx.mock
    def test_async_patch(self, api: Api) -> None:
        """Test async PATCH request to partially update a resource."""
        payload = {"foo": ["a", "b", "c"]}
        result = {"id": 1}
        respx.patch("https://example.com/api/v1/test/my-detail/").mock(return_value=httpx.Response(200, json=result))
        resp = asyncio.run(api.test("my-detail").async_patch(payload))

        assert isinstance(resp, dict)
        assert resp["id"] == 1

    @respx.mock
    def test_async_put(self, api: Api) -> None:
        """Test async PUT request to fully update a resource."""
        payload = {"foo": ["a", "b", "c"]}
        result = {"id": 1}
        respx.put("https://example.com/api/v1/test/my-detail/").mock(return_value=httpx.Response(200, json=result))

        resp = asyncio.run(api.test("my-detail").async_put(payload))
        assert isinstance(resp, dict)
        assert resp["id"] == 1

    @respx.mock
    def test_async_delete(self, api: Api) -> None:
        """Test async DELETE request with various response codes."""
        result = {"id": 1}
        respx.delete("https://example.com/api/v1/test/my-detail/").mock(return_value=httpx.Response(200, json=result))

        deleted = asyncio.run(api.test("my-detail").async_delete())

        assert deleted
        respx.delete("https://example.com/api/v1/test/my-detail/").mock(return_value=httpx.Response(204, json=result))

        deleted = asyncio.run(api.test("my-detail").async_delete())
        assert deleted

        respx.delete("https://example.com/api/v1/test/my-detail/").mock(return_value=httpx.Response(400, json=result))

        deleted = asyncio.run(api.test("my-detail").async_delete())
        assert not deleted

    @respx.mock
    def test_async_post_with_error(self, api: Api) -> None:
        """Test async POST request error handling for 4xx and 5xx responses."""
        payload = {"foo": ["a", "b", "c"]}
        result = {"id": 1}

        # 400 Bad Request
        respx.post("https://example.com/api/v1/test/").mock(return_value=httpx.Response(400, json=result))
        with pytest.raises(HttpClientError):
            asyncio.run(api.test.async_post(payload))

        # 404 Not Found
        respx.post("https://example.com/api/v1/test/").mock(return_value=httpx.Response(404, json=result))
        with pytest.raises(HttpClientError):
            asyncio.run(api.test.async_post(payload))

        # 500 Internal Server Error
        respx.post("https://example.com/api/v1/test/").mock(return_value=httpx.Response(500, json=result))
        with pytest.raises(HttpServerError):
            asyncio.run(api.test.async_post(payload))
