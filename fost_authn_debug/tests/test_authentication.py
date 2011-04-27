from unittest2 import TestCase
from mock_request import MockRequest

from fost_authn import FostBackend


class TestAuthentication(TestCase):
    """
        Unit tests for the FostBackend itself.
    """
    def setUp(self):
        self.backend = FostBackend()


    def test_signed_request(self):
        request = MockRequest()
        request.sign('key-value', 'secret-value')
