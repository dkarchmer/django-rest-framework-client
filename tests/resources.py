import sys
import json
import mock
import requests
import requests_mock
import unittest

from drf_client.connection import Api, RestResource
from drf_client import exceptions


class ResourceTestCase(unittest.TestCase):

    def setUp(self):
        self.options = {
            'DOMAIN': "https://example.com",
            'API_PREFIX': 'api/v1',
            'TOKEN_TYPE': 'jwt',
            'TOKEN_FORMAT': 'JWT {token}',
            'USERNAME_KEY': 'username',
            'LOGIN': 'auth/login/',
            'LOGOUT': 'auth/logout/',
            'USE_DASHES': False,
        }
        self.base_resource = RestResource(base_url="https://example.com/api/v1/test/",
                                          use_token=True,
                                          options=self.options,
                                          token='my-token')

    def test_url(self):

        url = self.base_resource.url()
        self.assertEqual(url, 'https://example.com/api/v1/test/')

    def test_headers(self):
        expected_headers = {
            'Content-Type': 'application/json',
            'Authorization': 'JWT my-token'
        }

        headers = self.base_resource._get_headers()
        self.assertEqual(headers, expected_headers)

    @requests_mock.Mocker()
    def test_get_200(self, m):
        payload = {
            "result": ["a", "b", "c"]
        }
        m.get('https://example.com/api/v1/test/', text=json.dumps(payload))

        resp = self.base_resource.get()
        self.assertEqual(resp['result'], ['a', 'b', 'c'])

