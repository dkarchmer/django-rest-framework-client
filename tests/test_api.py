"""Test cases for the Api class."""

import asyncio
import json
import unittest

import httpx
import pytest
import requests_mock
import respx

from drf_client.connection import Api
from drf_client.exceptions import HttpClientError, HttpServerError


class ApiTestCase(unittest.TestCase):
    """Test the Api class for DRF client functionality."""

    def setUp(self) -> None:
        """Set up test fixtures with Api instance and configuration."""
        options = {
            "DOMAIN": "https://example.com",
            "API_PREFIX": "api/v1",
            "TOKEN_TYPE": "jwt",
            "TOKEN_FORMAT": "JWT {token}",
            "LOGIN": "auth/login/",
            "LOGOUT": "auth/logout/",
            "USE_DASHES": False,
        }

        self.api = Api(options=options)

    def test_init(self) -> None:
        """Test Api initialization with correct base URL and options."""
        assert self.api.base_url == "https://example.com/api/v1"
        assert self.api.use_token
        assert self.api.options["TOKEN_TYPE"] == "jwt"
        assert self.api.options["TOKEN_FORMAT"] == "JWT {token}"

    def test_set_token(self) -> None:
        """Test setting authentication token."""
        assert self.api.token is None
        self.api.set_token("big-token")
        assert self.api.token == "big-token"

    @requests_mock.Mocker()
    def test_login(self, m: requests_mock.Mocker) -> None:
        """Test successful login with username and password."""
        payload = {"jwt": "big-token", "username": "user1"}
        m.post("https://example.com/api/v1/auth/login/", text=json.dumps(payload))

        ok = self.api.login(username="user1@test.com", password="pass")
        assert ok
        assert self.api.username == "user1@test.com"
        assert self.api.token == "big-token"

    @requests_mock.Mocker()
    def test_logout(self, m: requests_mock.Mocker) -> None:
        """Test logout clears username and token."""
        payload = {"jwt": "big-token", "username": "user1"}
        m.post("https://example.com/api/v1/auth/login/", text=json.dumps(payload))
        m.post("https://example.com/api/v1/auth/logout/", status_code=204)

        ok = self.api.login(username="user1@test.com", password="pass")
        assert ok

        self.api.logout()
        assert self.api.username is None
        assert self.api.token is None

    @requests_mock.Mocker()
    def test_get_list(self, m: requests_mock.Mocker) -> None:
        """Test GET request to list endpoint."""
        payload = {"result": ["a", "b", "c"]}
        m.get("https://example.com/api/v1/test/", text=json.dumps(payload))

        resp = self.api.test.get()
        assert resp["result"] == ["a", "b", "c"]

    @requests_mock.Mocker()
    def test_get_detail(self, m: requests_mock.Mocker) -> None:
        """Test GET request to detail endpoint with resource ID."""
        payload = {"a": "b", "c": "d"}
        m.get("https://example.com/api/v1/test/my-detail/", text=json.dumps(payload))

        resp = self.api.test("my-detail").get()
        assert resp == {"a": "b", "c": "d"}

    @requests_mock.Mocker()
    def test_get_detail_with_action(self, m: requests_mock.Mocker) -> None:
        """Test GET request to detail endpoint with custom action."""
        payload = {"a": "b", "c": "d"}
        m.get(
            "https://example.com/api/v1/test/my-detail/action/",
            text=json.dumps(payload),
        )

        resp = self.api.test("my-detail").action.get()
        assert resp == {"a": "b", "c": "d"}

    @requests_mock.Mocker()
    def test_get_with_use_dashes(self, m: requests_mock.Mocker) -> None:
        """Test that we can replace underscore with dashes."""
        self.api.options["USE_DASHES"] = True
        payload = {"a": "b", "c": "d"}
        m.get(
            "https://example.com/api/v1/test-one/my-detail/action/",
            text=json.dumps(payload),
        )

        resp = self.api.test_one.my_detail.action.get()
        assert resp == {"a": "b", "c": "d"}

    @requests_mock.Mocker()
    def test_get_detail_with_extra_args(self, m: requests_mock.Mocker) -> None:
        """Test GET request with extra query arguments."""
        payload = {"a": "b", "c": "d"}
        m.get("https://example.com/api/v1/test/my-detail/", text=json.dumps(payload))

        resp = self.api.test("my-detail").get(foo="bar")
        assert resp == {"a": "b", "c": "d"}

    @requests_mock.Mocker()
    def test_post(self, m: requests_mock.Mocker) -> None:
        """Test POST request to create a resource."""
        payload = {"foo": ["a", "b", "c"]}
        result = {"id": 1}
        m.post("https://example.com/api/v1/test/", text=json.dumps(result))

        resp = self.api.test.post(payload)
        assert resp["id"] == 1

    @requests_mock.Mocker()
    def test_patch(self, m: requests_mock.Mocker) -> None:
        """Test PATCH request to partially update a resource."""
        payload = {"foo": ["a", "b", "c"]}
        result = {"id": 1}
        m.patch("https://example.com/api/v1/test/my-detail/", text=json.dumps(result))

        resp = self.api.test("my-detail").patch(payload)
        assert resp["id"] == 1

    @requests_mock.Mocker()
    def test_put(self, m: requests_mock.Mocker) -> None:
        """Test PUT request to fully update a resource."""
        payload = {"foo": ["a", "b", "c"]}
        result = {"id": 1}
        m.put("https://example.com/api/v1/test/my-detail/", text=json.dumps(result))

        resp = self.api.test("my-detail").put(payload)
        assert resp["id"] == 1

    @requests_mock.Mocker()
    def test_delete(self, m: requests_mock.Mocker) -> None:
        """Test DELETE request to remove a resource."""
        result = {"id": 1}
        m.delete("https://example.com/api/v1/test/my-detail/", text=json.dumps(result))

        deleted = self.api.test("my-detail").delete()
        assert deleted

        result = {"id": 2}
        m.delete("https://example.com/api/v1/test/my-detail2/", text=json.dumps(result))

        deleted = self.api.test("my-detail2").delete(data={"foo": "bar"})
        assert deleted

    @requests_mock.Mocker()
    def test_post_with_error(self, m: requests_mock.Mocker) -> None:
        """Test POST request error handling for 4xx and 5xx responses."""
        payload = {"foo": ["a", "b", "c"]}
        result = {"id": 1}
        m.post("https://example.com/api/v1/test/", status_code=400, text=json.dumps(result))

        with pytest.raises(HttpClientError):
            self.api.test.post(payload)

        m.post("https://example.com/api/v1/test/", status_code=404, text=json.dumps(result))

        with pytest.raises(HttpClientError):
            self.api.test.post(payload)

        m.post("https://example.com/api/v1/test/", status_code=500, text=json.dumps(result))

        with pytest.raises(HttpServerError):
            self.api.test.post(payload)

    @respx.mock
    def test_async_get_list(self) -> None:
        """Test async GET request to list endpoint."""
        payload = {"result": ["a", "b", "c"]}
        respx.get("https://example.com/api/v1/test/").mock(return_value=httpx.Response(200, json=payload))

        resp = asyncio.run(self.api.test.async_get())
        assert resp["result"] == ["a", "b", "c"]

    @respx.mock
    def test_async_get_detail(self) -> None:
        """Test async GET request to detail endpoint."""
        payload = {"a": "b", "c": "d"}
        respx.get("https://example.com/api/v1/test/my-detail/").mock(return_value=httpx.Response(200, json=payload))
        resp = asyncio.run(self.api.test("my-detail").async_get())
        assert resp == {"a": "b", "c": "d"}

    @respx.mock
    def test_async_get_detail_with_action(self) -> None:
        """Test async GET request with custom action and URL verification."""
        payload = {"a": "b", "c": "d"}
        respx.get("https://example.com/api/v1/test/my-detail/").mock(return_value=httpx.Response(200, json=payload))
        resp = self.api.test("my-detail").action.url()
        assert resp == "https://example.com/api/v1/test/my-detail/action/"
        resp = asyncio.run(self.api.test("my-detail").async_get())
        assert resp == {"a": "b", "c": "d"}

    @respx.mock
    def test_async_get_with_use_dashes(self) -> None:
        """Test that we can replace underscore with dashes in async requests."""
        self.api.options["USE_DASHES"] = True
        payload = {"a": "b", "c": "d"}
        respx.get("https://example.com/api/v1/test-one/my-detail/action/").mock(
            return_value=httpx.Response(200, json=payload)
        )
        resp = asyncio.run(self.api.test_one.my_detail.action.async_get())
        assert resp == {"a": "b", "c": "d"}

    @respx.mock
    def test_async_get_detail_with_extra_args(self) -> None:
        """Test async GET request with extra query arguments."""
        payload = {"a": "b", "c": "d"}
        respx.get("https://example.com/api/v1/test/my-detail/").mock(return_value=httpx.Response(200, json=payload))
        resp = asyncio.run(self.api.test("my-detail").async_get(foo="bar"))
        assert resp == {"a": "b", "c": "d"}

    @respx.mock
    def test_async_post(self) -> None:
        """Test async POST request to create a resource."""
        payload = {"foo": ["a", "b", "c"]}
        result = {"id": 1}
        respx.post("https://example.com/api/v1/test/").mock(return_value=httpx.Response(200, json=result))
        resp = asyncio.run(self.api.test.async_post(payload))
        assert resp["id"] == 1

    @respx.mock
    def test_async_patch(self) -> None:
        """Test async PATCH request to partially update a resource."""
        payload = {"foo": ["a", "b", "c"]}
        result = {"id": 1}
        respx.patch("https://example.com/api/v1/test/my-detail/").mock(return_value=httpx.Response(200, json=result))
        resp = asyncio.run(self.api.test("my-detail").async_patch(payload))

        assert resp["id"] == 1

    @respx.mock
    def test_async_put(self) -> None:
        """Test async PUT request to fully update a resource."""
        payload = {"foo": ["a", "b", "c"]}
        result = {"id": 1}
        respx.put("https://example.com/api/v1/test/my-detail/").mock(return_value=httpx.Response(200, json=result))

        resp = asyncio.run(self.api.test("my-detail").async_put(payload))
        assert resp["id"] == 1

    @respx.mock
    def test_async_delete(self) -> None:
        """Test async DELETE request with various response codes."""
        result = {"id": 1}
        respx.delete("https://example.com/api/v1/test/my-detail/").mock(return_value=httpx.Response(200, json=result))

        deleted = asyncio.run(self.api.test("my-detail").async_delete())

        assert deleted
        respx.delete("https://example.com/api/v1/test/my-detail/").mock(return_value=httpx.Response(204, json=result))

        deleted = asyncio.run(self.api.test("my-detail").async_delete())
        assert deleted

        respx.delete("https://example.com/api/v1/test/my-detail/").mock(return_value=httpx.Response(400, json=result))

        deleted = asyncio.run(self.api.test("my-detail").async_delete())
        assert not deleted

    @respx.mock
    def test_async_post_with_error(self) -> None:
        """Test async POST request error handling for 4xx and 5xx responses."""
        payload = {"foo": ["a", "b", "c"]}
        result = {"id": 1}

        # 400 Bad Request
        respx.post("https://example.com/api/v1/test/").mock(return_value=httpx.Response(400, json=result))
        with pytest.raises(HttpClientError):
            asyncio.run(self.api.test.async_post(payload))

        # 404 Not Found
        respx.post("https://example.com/api/v1/test/").mock(return_value=httpx.Response(404, json=result))
        with pytest.raises(HttpClientError):
            asyncio.run(self.api.test.async_post(payload))

        # 500 Internal Server Error
        respx.post("https://example.com/api/v1/test/").mock(return_value=httpx.Response(500, json=result))
        with pytest.raises(HttpServerError):
            asyncio.run(self.api.test.async_post(payload))
