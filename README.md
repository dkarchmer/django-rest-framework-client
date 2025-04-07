# Django Rest Framework Python API Package

[![PyPI version](https://img.shields.io/pypi/v/django-rest-framework-client.svg)](https://pypi.python.org/pypi/django-rest-framework-client)

A python library for interacting with any Django web server base on django-rest-framework

Package is based on https://github.com/samgiles/slumber, but enhanced to support tokens and other features.

## Features

* Support for tokens. Both
    * django-rest-framework's own tokens: `rest_framework.authentication.TokenAuthentication`
    * JWT tokens: `rest_framework_jwt.authentication.JSONWebTokenAuthentication`

* Support for arguments (e.g. `?name1=val1&name2=val2`)

* Support for custom methods (e.g. ``/ap1/v1/object/custom/`)

## Requirements

restframeworkclient requires the following modules.

    * Python 3.10+
    * requests

## Installation

```bash
python3 -m venv ~/.virtualenv/drf_client
source ~/.virtualenv/drf_client/bin/activate
pip install django-rest-framework-client
```

## Usage Guide

Example

```
from drf_client.connection import Api as RestApi

options = {
    'DOMAIN': 'http://127.0.0.1:8000',
    'API_PREFIX': 'api/v1',
    'TOKEN_TYPE': 'jwt',
    'TOKEN_FORMAT': 'JWT {token}',
    'USERNAME_KEY': 'username',
    'LOGIN': 'auth/login/',
    'LOGOUT': 'auth/logout/',
    'USE_DASHES': False,    # Set to True to tell API to replace undercore ("_") with dashes ("-")
    'SESSION_TRIES': 3,     # Enable retry
    'SESSION_TIMEOUT': None,   # No timeout
    'SESSION_VERIFY': False,   # Do not verify SSL
}

c = RestApi(options)

ok = c.login(username=username, password=password)
if ok:

    # GET some data
    my_object = c.myresourcename.get()
    for obj in my_object['results']:
        pprint(obj)
        logger.info('------------------------------')

    payload = {
        'data1': 'val1',
        'data2': 'val2',
    }

    resp = c.myresourcename.post(data=payload)

    # If the URL includes "-", add under parenthesis:
    # GET: /api/v1/someresource/some-path/
    my_object = c.someresource('some-path').get()

```

<<<<<<< Updated upstream
### Example using Tokens

```
from drf_client.helpers.base_main import BaseMain

class MyClass(Main):

    options = {
        'DOMAIN': None,
        'API_PREFIX': 'api/v1',
        'TOKEN_TYPE': 'bearer',
        'TOKEN_FORMAT': 'Bearer {token}',
        'USERNAME_KEY': 'username',
        'LOGIN': 'auth/login/',
        'LOGOUT': 'auth/logout/',
        'USE_DASHES': False,
        "SESSION_TRIES": 3,
        'SESSION_TIMEOUT': None,
        'SESSION_VERIFY': False,
    }

export DRF_CLIENT_AUTH_TOKEN=1fe171f65917db0072abc6880196989dd2a20025
python -m my_script.MyClass --server https://mysite.com --use-token t
```

=======
>>>>>>> Stashed changes
## Django Setup

Client assumes by default that all urls should end with a slash (tested with the default
router: `routers.DefaultRouter()`)

Apart from the regular Django and Rest Framework setup, this package currently relies on the following custom
login and logout API functions:

```
class AccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'username')


class APILogoutViewSet(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request, format=None):
        logout(request)
        return Response({}, status=status.HTTP_204_NO_CONTENT)


urlpatterns = [
    url(r'^auth/logout/$', APILogoutViewSet.as_view(), name='api-logout'),
]
```

## Helpers

### BaseMain Helper

This class helps write a script with a flexible template that helps avoid having to duplicate
boiler plate code from script to script.

The class assumes that most scripts include the basic folliwing flow:

```
# Parse arguments
# Setup LOG configuration
# Login
# Do something after logging in
```

The opinionated class will execute the basic main flow:

```python
   # Initialize arguments and LOG in the init function
   # Add additional arguments by implemenenting self.add_extra_args()
   self.domain = self.get_domain()
   self.api = Api(self.domain)
   self.before_login()
   ok = self.login()
   if ok:
       self.after_login()
```

Any of the above functions can be overwritten by deriving from this class.

Here is a sample script:

```python
from drf_client.helper.base_main import BaseMain
from drf_client.helper.base_facade import BaseFacade

class MyScript(BaseMain):

    def add_extra_args(self):
        # Add extra positional argument (as example)
        self.parser.add_argument('foo', metavar='foo', type=str, help='RTFM')

    def before_login(self):
        logger.info('-----------')

    def after_login(self):
        # Main function to OVERWITE and do real work
        resp = self.api.foo.bar.get()
        # You can also access the API from the global Facade
        resp = BaseFacade.api.foo.bar.get()


if __name__ == '__main__':

    work = MyScript()
    work.main()
```

If you wish to implement coroutines to run multiple tasks in parallel, you can use the `asyncio` library.

```python
import asyncio
from drf_client.helper.base_main import BaseMain
from drf_client.helper.base_facade import BaseFacade

class MyScript(BaseMain):

    def add_extra_args(self):
        # Add extra positional argument (as example)
        self.parser.add_argument('foo', metavar='foo', type=str, help='RTFM')

    def before_login(self):
        logger.info('-----------')

    async def process(self):
        """Main async test"""
        # foo_bar and foo_baz are coroutines
        foo_bar = await self.api.foo.bar.async_get()
        foo_baz = await self.api.foo.baz.async_get()


    def  after_login(self):
        # Main function to OVERWITE and do real work
        resp = asyncio.run(self.process())


if __name__ == '__main__':

    work = MyScript()
    work.main()
```

Given the above script, you will run it with

```bash
python myscript.py -u <USERNAME> --foo bar
```

## Development

To test, run python setup.py test or to run coverage analysis:

```bash
pip install pdm
pdm sync

pdm run test

# Install pre-commit hooks
pre-commit install
pre-commit install --hook-type prepare-commit-msg
pre-commit install --hook-type commit-msg
```

## CI Deployment

1. Update `setup.py` with new version
2. Update `CHANGELOG.md` with description of new version
2. Create new tag with same version

```
git tag v0.4.1 -m "v0.4.1"
git push --tags
```

3. Create new release using GitHub Web Site. Github action will run automatically to deploy to PyPi.
