"""Test Resource class."""

import json
import unittest

import requests_mock

from drf_client.connection import RestResource


class ResourceTestCase(unittest.TestCase):
    """Test the RestResource class functionality."""

    def setUp(self) -> None:
        """Set up test fixtures with RestResource instance and configuration."""
        self.options = {
            "DOMAIN": "https://example.com",
            "API_PREFIX": "api/v1",
            "TOKEN_TYPE": "jwt",
            "TOKEN_FORMAT": "JWT {token}",
            "USERNAME_KEY": "username",
            "LOGIN": "auth/login/",
            "LOGOUT": "auth/logout/",
            "USE_DASHES": False,
        }
        self.base_resource = RestResource(
            base_url="https://example.com/api/v1/test/",
            use_token=True,
            options=self.options,
            token="my-token",
        )

    def test_url(self) -> None:
        """Test URL generation for resource."""
        url = self.base_resource.url()
        assert url == "https://example.com/api/v1/test/"

    def test_headers(self) -> None:
        """Test authorization header generation with JWT token."""
        expected_headers = {
            "Content-Type": "application/json",
            "Authorization": "JWT my-token",
        }

        headers = self.base_resource._get_headers()
        assert headers == expected_headers

    @requests_mock.Mocker()
    def test_get_200(self, m: requests_mock.Mocker) -> None:
        """Test successful GET request with 200 response."""
        payload = {"result": ["a", "b", "c"]}
        m.get("https://example.com/api/v1/test/", text=json.dumps(payload))

        resp = self.base_resource.get()
        assert resp["result"] == ["a", "b", "c"]
