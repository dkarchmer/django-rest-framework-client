import os.path
import unittest


def get_tests():
    return full_suite()


def full_suite():
    from .api import ApiTestCase
    from .resources import ResourceTestCase

    resourcesuite = unittest.TestLoader().loadTestsFromTestCase(ResourceTestCase)
    apisuite = unittest.TestLoader().loadTestsFromTestCase(ApiTestCase)

    return unittest.TestSuite([resourcesuite, apisuite])
