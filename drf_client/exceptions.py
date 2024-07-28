"""Custom Exception."""


class RestBaseException(Exception):
    """
    All Rest exceptions inherit from this exception.
    """


class RestHttpBaseException(RestBaseException):
    """
    All Rest HTTP Exceptions inherit from this exception.
    """

    def __init__(self, *args, **kwargs):
        """
        Helper to get and a proper dict iterator with Py2k and Py3k
        """
        try:
            iter = kwargs.iteritems()
        except AttributeError:
            iter = kwargs.items()

        for key, value in iter:
            setattr(self, key, value)
        super(RestHttpBaseException, self).__init__(*args)


class HttpClientError(RestHttpBaseException):
    """
    Called when the server tells us there was a client error (4xx).
    """


class HttpNotFoundError(HttpClientError):
    """
    Called when the server sends a 404 error.
    """


class HttpServerError(RestHttpBaseException):
    """
    Called when the server tells us there was a server error (5xx).
    """


class SerializerNoRestailable(RestBaseException):
    """
    There are no Restailable Serializers.
    """


class SerializerNotRestailable(RestBaseException):
    """
    The chosen Serializer is not Restailable.
    """


class ImproperlyConfigured(RestBaseException):
    """
    Rest is somehow improperly configured.
    """


class HttpCouldNotVerifyServerError(RestHttpBaseException):
    """
    Called when the server identifies itself with a self-signed or untrusted certificate.
    """
