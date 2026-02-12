"""Boilerplate code for basic scripts."""

import argparse
import getpass
import logging
import os
import sys
import typing
from urllib.parse import urlparse

from .base_facade import BaseFacade

if typing.TYPE_CHECKING:
    from drf_client.connection import Api

logger = logging.getLogger(__name__)


class BaseMain:
    """
    Boilerplate code for basic scripts.

    The class assumes that most scripts include the basic following flow:

    - Parse arguments
    - Setup LOG configuration
    - Login
    - Do something after logging in
    """

    parser: argparse.ArgumentParser
    args: argparse.Namespace
    api: Api
    options: typing.ClassVar[dict] = {
        "DOMAIN": None,
        "API_PREFIX": "api/v1",
        "TOKEN_TYPE": "jwt",
        "TOKEN_FORMAT": "JWT {token}",
        "USERNAME_KEY": "username",
        "LOGIN": "auth/login/",
        "LOGOUT": "auth/logout/",
        "USE_DASHES": False,
    }
    logging_level = logging.INFO

    def __init__(self) -> None:
        """
        Initialize the BaseMain class.

        Initialize logging configuration.
        Initialize argument parsing.
        Process any extra arguments.
        Only hard codes one required argument: --user.
        Additional arguments can be configured by overwriting the add_extra_args() method.
        Logging configuration can be changed by overwriting the config_logging() method.
        """
        self.parser = argparse.ArgumentParser(description=__doc__)
        self.parser.add_argument(
            "-u",
            "--user",
            dest="username",
            type=str,
            required=False,
            help="Username used for login",
        )
        self.parser.add_argument(
            "-t",
            "--use-token",
            dest="use_token",
            action="store_true",
            help="Use token (expects DRF_CLIENT_AUTH_TOKEN to be defined as an env variable)",
        )
        self.parser.add_argument(
            "--server",
            dest="server",
            type=str,
            required=True,
            help="Server Domain Name to use",
        )

        self.add_extra_args()

        self.args = self.parser.parse_args()
        self.config_logging()
        self.domain = ""

    def _critical_exit(self, msg: str) -> None:
        """Exit with an error."""
        logger.error(msg)
        sys.exit(1)

    def main(self) -> None:
        """
        Initiate execution.

        1. Get domain name and use to instantiate Api object
        2. Call before_login to allow for work before logging in
        3. Logging into the server
        4. Call after_loging to do actual work with server data.
        """
        self.domain = self.get_domain()
        # Create a static pointer to the API for global access
        BaseFacade.initialize_api(api_options=self.get_options(), cmd_args=self.args)
        assert BaseFacade.api is not None
        self.api = BaseFacade.api
        self.before_login()
        ok = self.login()
        if ok:
            self.after_login()

    # Following functions can be overwritten if needed
    # ================================================

    def get_options(self) -> dict:
        """
        Add domain to Api options.

        Returns:
            A dictionary of options to use for the API connection.

        """
        options = self.options
        options["DOMAIN"] = self.domain
        return options

    def config_logging(self) -> None:
        """Overwrite to change the way the logging package is configured."""
        logging.basicConfig(
            level=self.logging_level,
            format="[%(asctime)-15s] %(levelname)-6s %(message)s",
            datefmt="%d/%b/%Y %H:%M:%S",
        )

    def add_extra_args(self) -> None:
        """
        Overwrite to change the way extra arguments are added to the args parser.

        :return: Nothing
        """

    def get_domain(self) -> str:
        """
        Figure out server domain URL based on --server and --customer args.

        Returns:
            The domain name to use for the API connection.

        """
        if not urlparse(self.args.server).scheme:
            return f"https://{self.args.server}"
        return self.args.server

    def login(self) -> bool:
        """
        Log in to the server using either a token from an environment variable or by asking the user for a password.

        Returns:
            True if login was successful, False otherwise.

        """
        if self.args.use_token:
            token = os.getenv("DRF_CLIENT_AUTH_TOKEN")
            if not token:
                self._critical_exit("DRF_CLIENT_AUTH_TOKEN must be defined as environment variable.")
            self.api.set_token(token)
            logger.info("Bearer Token has been set.")
            ok = True
        else:
            password = getpass.getpass()
            ok = self.api.login(username=self.args.username, password=password)
            if ok:
                logger.info("Welcome %s", self.args.username)
        return ok

    def before_login(self) -> None:
        """
        Overwrite to do work after parsing, but before logging in to the server.

        This is a good place to do additional custom argument checks

        :return: Nothing
        """

    def after_login(self) -> None:
        """
        Do work after logging in to the server.

        This function MUST be overwritten to do actual work after logging into the Server.

        :return: Nothing
        """
        logger.warning("No actual work done")
