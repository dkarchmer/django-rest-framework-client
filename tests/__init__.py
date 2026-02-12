"""Init tests."""

import unittest

from .test_api import ApiTestCase
from .test_resources import ResourceTestCase


def get_tests():
    return full_suite()


def full_suite():
    resourcesuite = unittest.TestLoader().loadTestsFromTestCase(ResourceTestCase)
    apisuite = unittest.TestLoader().loadTestsFromTestCase(ApiTestCase)

    return unittest.TestSuite([resourcesuite, apisuite])
