import argparse
import getpass
import logging
import sys
from urllib.parse import urlparse

from .base_facade import BaseFacade

LOG = logging.getLogger(__name__)


class BaseMain:
    """Boiler plate code for basic scripts.

    The class assumes that most scripts include the basic following flow:

    - Parse arguments
    - Setup LOG configuration
    - Login
    - Do something after logging in
"""

    parser = None
    args = None
    api = None
    options = {
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

    def __init__(self):
        """
        Initialize Logging configuration
        Initialize argument parsing
        Process any extra arguments
        Only hard codes one required argument: --user
        Additional arguments can be configured by overwriting the add_extra_args() method
        Logging configuration can be changed by overwritting the config_logging() method
        """
        self.parser = argparse.ArgumentParser(description=__doc__)
        self.parser.add_argument(
            "-u",
            "--user",
            dest="username",
            type=str,
            required=True,
            help="Username used for login",
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

    def _critical_exit(self, msg):
        """Exit with an error."""
        LOG.error(msg)
        sys.exit(1)

    def main(self):
        """
        Main function to call to initiate execution.
        1. Get domain name and use to instantiate Api object
        2. Call before_login to allow for work before logging in
        3. Logging into the server
        4. Call after_loging to do actual work with server data
        """
        self.domain = self.get_domain()
        # Create a static pointer to the API for global access
        BaseFacade.initialize_api(api_options=self.get_options(), cmd_args=self.args)
        self.api = BaseFacade.api
        self.before_login()
        ok = self.login()
        if ok:
            self.after_login()

    # Following functions can be overwritten if needed
    # ================================================

    def get_options(self):
        """Add domain to Api options."""
        options = self.options
        options["DOMAIN"] = self.domain
        return options

    def config_logging(self):
        """
        Overwrite to change the way the logging package is configured
        :return: Nothing
        """
        logging.basicConfig(
            level=self.logging_level,
            format="[%(asctime)-15s] %(levelname)-6s %(message)s",
            datefmt="%d/%b/%Y %H:%M:%S",
        )

    def add_extra_args(self):
        """
        Overwrite to change the way extra arguments are added to the args parser
        :return: Nothing
        """
        pass

    def get_domain(self) -> str:
        """
        Figure out server domain URL based on --server and --customer args
        """
        if not urlparse(self.args.server).scheme:
            return f"https://{self.args.server}"
        return self.args.server

    def login(self) -> bool:
        """
        Get password from user and login
        """
        password = getpass.getpass()
        ok = self.api.login(username=self.args.username, password=password)
        if ok:
            LOG.info("Welcome {0}".format(self.args.username))
        return ok

    def before_login(self):
        """
        Overwrite to do work after parsing, but before logging in to the server
        This is a good place to do additional custom argument checks
        :return: Nothing
        """
        pass

    def after_login(self):
        """
        This function MUST be overwritten to do actual work after logging into the Server
        :return: Nothing
        """
        LOG.warning("No actual work done")
