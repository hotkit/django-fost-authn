from datetime import datetime
from unittest2 import TestCase
import mock

from django.conf import settings

from mock_request import MockRequest

from fost_authn import FostBackend, Middleware


class TestAuthentication(TestCase):
    """
        Unit tests for the FostBackend itself.
    """
    def setUp(self):
        self.middleware = Middleware()
        self.backend = FostBackend()
        self.request = MockRequest()
        self.key = 'key-value'
        self.request.sign(self.key, self.secret())
        key, self.hmac = self.middleware.key_hmac(self.request)
        settings.FOST_AUTHN_GET_SECRET = self.secret
    def tearDown(self):
        delattr(settings, 'FOST_AUTHN_GET_SECRET')

    def secret(self, r = None, k = None):
        return 'secret-value'


    def test_signed_request_missing_timestamp_header(self):
        del self.request.META['HTTP_X_FOST_TIMESTAMP']
        forbidden = []
        def forbid(error):
            forbidden.append(True)
        with mock.patch('fost_authn.authentication._forbid', forbid):
            result = self.backend.authenticate(request = self.request,
                    key = self.key, hmac = self.hmac)
        self.assertTrue(forbidden)

    def test_signed_request(self):
        with mock.patch('fost_authn.authentication._forbid', self.fail):
            result = self.backend.authenticate(request = self.request,
                key = self.key, hmac = self.hmac)
