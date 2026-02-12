"""Hold static information that can be accessed by any part of the package.

A facade is an object that serves as a front-facing interface masking more complex
underlying or structural code.
"""

from argparse import Namespace

from drf_client.connection import Api as RestApi


class BaseFacade:
    """Stores key static information used across the package."""

    api: RestApi | None = None
    api_options: dict | None = None
    cmd_args: Namespace | None = None

    @staticmethod
    def initialize_api(api_options: dict, cmd_args: Namespace | None = None):
        """Initialize API with the given options."""
        if BaseFacade.api is None:
            # Only initialize ones
            BaseFacade.api_options = api_options.copy()
            BaseFacade.api = RestApi(api_options)
            BaseFacade.cmd_args = cmd_args
