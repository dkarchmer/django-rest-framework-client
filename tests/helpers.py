"""test Resource class."""

import unittest

from drf_client.helpers.base_facade import BaseFacade


class FacadeTestCase(unittest.TestCase):
    """Test static facade class."""

    def test_initialize_facade(self):
        """Test Initializer."""
        BaseFacade.initialize_api(api_options={"DOMAIN": "https://example.com"})
        assert BaseFacade.api_options is not None
        assert BaseFacade.api_options["DOMAIN"] == "https://example.com"
        assert BaseFacade.api is not None
