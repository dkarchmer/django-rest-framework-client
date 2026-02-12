"""Test Resource class."""

import json

import pytest
from requests_mock import Mocker

from drf_client.connection import RestResource


@pytest.fixture
def resource_options() -> dict:
    """
    Provide resource configuration options for tests.

    Returns:
        A dictionary containing API configuration options.

    """
    return {
        "DOMAIN": "https://example.com",
        "API_PREFIX": "api/v1",
        "TOKEN_TYPE": "jwt",
        "TOKEN_FORMAT": "JWT {token}",
        "USERNAME_KEY": "username",
        "LOGIN": "auth/login/",
        "LOGOUT": "auth/logout/",
        "USE_DASHES": False,
    }


@pytest.fixture
def base_resource(resource_options: dict) -> RestResource:
    """
    Provide a RestResource instance for tests.

    Returns:
        A configured RestResource instance for testing.

    """
    return RestResource(
        base_url="https://example.com/api/v1/test/",
        use_token=True,
        options=resource_options,
        token="my-token",
    )


class TestResource:
    """Test the RestResource class functionality."""

    def test_url(self, base_resource: RestResource) -> None:
        """Test URL generation for resource."""
        url = base_resource.url()
        assert url == "https://example.com/api/v1/test/"

    def test_headers(self, base_resource: RestResource) -> None:
        """Test authorization header generation with JWT token."""
        expected_headers = {
            "Content-Type": "application/json",
            "Authorization": "JWT my-token",
        }

        headers = base_resource._get_headers()
        assert headers == expected_headers

    def test_get_200(self, base_resource: RestResource, requests_mock: Mocker) -> None:
        """Test successful GET request with 200 response."""
        payload = {"result": ["a", "b", "c"]}
        requests_mock.get("https://example.com/api/v1/test/", text=json.dumps(payload))

        resp = base_resource.get()
        assert isinstance(resp, dict)
        assert resp["result"] == ["a", "b", "c"]
