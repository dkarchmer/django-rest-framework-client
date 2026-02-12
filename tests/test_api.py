import asyncio
import json
import unittest

import httpx
import requests_mock
import respx

from drf_client.connection import Api
from drf_client.exceptions import HttpClientError, HttpServerError


class ApiTestCase(unittest.TestCase):
    def setUp(self):
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

    def test_init(self):
        self.assertEqual(self.api.base_url, "https://example.com/api/v1")
        self.assertTrue(self.api.use_token)
        self.assertEqual(self.api.options["TOKEN_TYPE"], "jwt")
        self.assertEqual(self.api.options["TOKEN_FORMAT"], "JWT {token}")

    def test_set_token(self):
        self.assertEqual(self.api.token, None)
        self.api.set_token("big-token")
        self.assertEqual(self.api.token, "big-token")

    @requests_mock.Mocker()
    def test_login(self, m):
        payload = {"jwt": "big-token", "username": "user1"}
        m.post("https://example.com/api/v1/auth/login/", text=json.dumps(payload))

        ok = self.api.login(username="user1@test.com", password="pass")
        self.assertTrue(ok)
        self.assertEqual(self.api.username, "user1@test.com")
        self.assertEqual(self.api.token, "big-token")

    @requests_mock.Mocker()
    def test_logout(self, m):
        payload = {"jwt": "big-token", "username": "user1"}
        m.post("https://example.com/api/v1/auth/login/", text=json.dumps(payload))
        m.post("https://example.com/api/v1/auth/logout/", status_code=204)

        ok = self.api.login(username="user1@test.com", password="pass")
        self.assertTrue(ok)

        self.api.logout()
        self.assertEqual(self.api.username, None)
        self.assertEqual(self.api.token, None)

    @requests_mock.Mocker()
    def test_get_list(self, m):
        payload = {"result": ["a", "b", "c"]}
        m.get("https://example.com/api/v1/test/", text=json.dumps(payload))

        resp = self.api.test.get()
        self.assertEqual(resp["result"], ["a", "b", "c"])

    @requests_mock.Mocker()
    def test_get_detail(self, m):
        payload = {"a": "b", "c": "d"}
        m.get("https://example.com/api/v1/test/my-detail/", text=json.dumps(payload))

        resp = self.api.test("my-detail").get()
        self.assertEqual(resp, {"a": "b", "c": "d"})

    @requests_mock.Mocker()
    def test_get_detail_with_action(self, m):
        payload = {"a": "b", "c": "d"}
        m.get(
            "https://example.com/api/v1/test/my-detail/action/",
            text=json.dumps(payload),
        )

        # resp = self.api.test('my-detail').action.url()
        # self.assertEqual(resp, 'https://example.com/api/v1/test/my-detail/action/')
        resp = self.api.test("my-detail").action.get()
        self.assertEqual(resp, {"a": "b", "c": "d"})

    @requests_mock.Mocker()
    def test_get_with_use_dashes(self, m):
        """test that we can replace underscore with dashes."""
        self.api.options["USE_DASHES"] = True
        payload = {"a": "b", "c": "d"}
        m.get(
            "https://example.com/api/v1/test-one/my-detail/action/",
            text=json.dumps(payload),
        )

        # resp = self.api.test('my-detail').action.url()
        # self.assertEqual(resp, 'https://example.com/api/v1/test/my-detail/action/')
        resp = self.api.test_one.my_detail.action.get()
        self.assertEqual(resp, {"a": "b", "c": "d"})

    @requests_mock.Mocker()
    def test_get_detail_with_extra_args(self, m):
        payload = {"a": "b", "c": "d"}
        m.get("https://example.com/api/v1/test/my-detail/", text=json.dumps(payload))

        resp = self.api.test("my-detail").get(foo="bar")
        self.assertEqual(resp, {"a": "b", "c": "d"})

    @requests_mock.Mocker()
    def test_post(self, m):
        payload = {"foo": ["a", "b", "c"]}
        result = {"id": 1}
        m.post("https://example.com/api/v1/test/", text=json.dumps(result))

        resp = self.api.test.post(payload)
        self.assertEqual(resp["id"], 1)

    @requests_mock.Mocker()
    def test_patch(self, m):
        payload = {"foo": ["a", "b", "c"]}
        result = {"id": 1}
        m.patch("https://example.com/api/v1/test/my-detail/", text=json.dumps(result))

        resp = self.api.test("my-detail").patch(payload)
        self.assertEqual(resp["id"], 1)

    @requests_mock.Mocker()
    def test_put(self, m):
        payload = {"foo": ["a", "b", "c"]}
        result = {"id": 1}
        m.put("https://example.com/api/v1/test/my-detail/", text=json.dumps(result))

        resp = self.api.test("my-detail").put(payload)
        self.assertEqual(resp["id"], 1)

    @requests_mock.Mocker()
    def test_delete(self, m):
        result = {"id": 1}
        m.delete("https://example.com/api/v1/test/my-detail/", text=json.dumps(result))

        deleted = self.api.test("my-detail").delete()
        self.assertTrue(deleted)

        result = {"id": 2}
        m.delete("https://example.com/api/v1/test/my-detail2/", text=json.dumps(result))

        deleted = self.api.test("my-detail2").delete(data={"foo": "bar"})
        self.assertTrue(deleted)

    @requests_mock.Mocker()
    def test_post_with_error(self, m):
        payload = {"foo": ["a", "b", "c"]}
        result = {"id": 1}
        m.post("https://example.com/api/v1/test/", status_code=400, text=json.dumps(result))

        with self.assertRaises(HttpClientError):
            self.api.test.post(payload)

        m.post("https://example.com/api/v1/test/", status_code=404, text=json.dumps(result))

        with self.assertRaises(HttpClientError):
            self.api.test.post(payload)

        m.post("https://example.com/api/v1/test/", status_code=500, text=json.dumps(result))

        with self.assertRaises(HttpServerError):
            self.api.test.post(payload)

    @respx.mock
    def test_async_get_list(self):
        payload = {"result": ["a", "b", "c"]}
        respx.get("https://example.com/api/v1/test/").mock(return_value=httpx.Response(200, json=payload))

        resp = asyncio.run(self.api.test.async_get())
        self.assertEqual(resp["result"], ["a", "b", "c"])

    @respx.mock
    def test_async_get_detail(self):
        payload = {"a": "b", "c": "d"}
        respx.get("https://example.com/api/v1/test/my-detail/").mock(return_value=httpx.Response(200, json=payload))
        resp = asyncio.run(self.api.test("my-detail").async_get())
        self.assertEqual(resp, {"a": "b", "c": "d"})

    @respx.mock
    def test_async_get_detail_with_action(self):
        payload = {"a": "b", "c": "d"}
        respx.get("https://example.com/api/v1/test/my-detail/").mock(return_value=httpx.Response(200, json=payload))
        resp = self.api.test("my-detail").action.url()
        self.assertEqual(resp, "https://example.com/api/v1/test/my-detail/action/")
        resp = asyncio.run(self.api.test("my-detail").async_get())
        self.assertEqual(resp, {"a": "b", "c": "d"})

    @respx.mock
    def test_async_get_with_use_dashes(self):
        """test that we can replace underscore with dashes."""
        self.api.options["USE_DASHES"] = True
        payload = {"a": "b", "c": "d"}
        respx.get("https://example.com/api/v1/test-one/my-detail/action/").mock(
            return_value=httpx.Response(200, json=payload)
        )
        resp = asyncio.run(self.api.test_one.my_detail.action.async_get())
        self.assertEqual(resp, {"a": "b", "c": "d"})

    @respx.mock
    def test_async_get_detail_with_extra_args(self):
        payload = {"a": "b", "c": "d"}
        respx.get("https://example.com/api/v1/test/my-detail/").mock(return_value=httpx.Response(200, json=payload))
        resp = asyncio.run(self.api.test("my-detail").async_get(foo="bar"))
        self.assertEqual(resp, {"a": "b", "c": "d"})

    @respx.mock
    def test_async_post(self):
        payload = {"foo": ["a", "b", "c"]}
        result = {"id": 1}
        respx.post("https://example.com/api/v1/test/").mock(return_value=httpx.Response(200, json=result))
        resp = asyncio.run(self.api.test.async_post(payload))
        self.assertEqual(resp["id"], 1)

    @respx.mock
    def test_async_patch(self):
        payload = {"foo": ["a", "b", "c"]}
        result = {"id": 1}
        respx.patch("https://example.com/api/v1/test/my-detail/").mock(return_value=httpx.Response(200, json=result))
        resp = asyncio.run(self.api.test("my-detail").async_patch(payload))

        self.assertEqual(resp["id"], 1)

    @respx.mock
    def test_async_put(self):
        payload = {"foo": ["a", "b", "c"]}
        result = {"id": 1}
        respx.put("https://example.com/api/v1/test/my-detail/").mock(return_value=httpx.Response(200, json=result))

        resp = asyncio.run(self.api.test("my-detail").async_put(payload))
        self.assertEqual(resp["id"], 1)

    @respx.mock
    def test_async_delete(self):
        result = {"id": 1}
        respx.delete("https://example.com/api/v1/test/my-detail/").mock(return_value=httpx.Response(200, json=result))

        deleted = asyncio.run(self.api.test("my-detail").async_delete())

        self.assertTrue(deleted)
        respx.delete("https://example.com/api/v1/test/my-detail/").mock(return_value=httpx.Response(204, json=result))

        deleted = asyncio.run(self.api.test("my-detail").async_delete())
        self.assertTrue(deleted)

        respx.delete("https://example.com/api/v1/test/my-detail/").mock(return_value=httpx.Response(400, json=result))

        deleted = asyncio.run(self.api.test("my-detail").async_delete())
        self.assertFalse(deleted)

    @respx.mock
    def test_async_post_with_error(self):
        payload = {"foo": ["a", "b", "c"]}
        result = {"id": 1}

        # 400 Bad Request
        respx.post("https://example.com/api/v1/test/").mock(return_value=httpx.Response(400, json=result))
        with self.assertRaises(HttpClientError):
            asyncio.run(self.api.test.async_post(payload))

        # 404 Not Found
        respx.post("https://example.com/api/v1/test/").mock(return_value=httpx.Response(404, json=result))
        with self.assertRaises(HttpClientError):
            asyncio.run(self.api.test.async_post(payload))

        # 500 Internal Server Error
        respx.post("https://example.com/api/v1/test/").mock(return_value=httpx.Response(500, json=result))
        with self.assertRaises(HttpServerError):
            asyncio.run(self.api.test.async_post(payload))
