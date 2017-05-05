import os.path
import unittest


def get_tests():
    return full_suite()

def full_suite():
    from .resources import ResourceTestCase
    from .api import ApiTestCase

    resourcesuite = unittest.TestLoader().loadTestsFromTestCase(ResourceTestCase)
    apisuite = unittest.TestLoader().loadTestsFromTestCase(ApiTestCase)

    return unittest.TestSuite([resourcesuite, apisuite])