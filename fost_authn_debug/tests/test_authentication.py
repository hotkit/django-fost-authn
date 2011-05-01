from datetime import datetime
from unittest2 import TestCase
import mock

from django.conf import settings
from django.contrib.auth.models import User

from mock_request import MockRequest

from fost_authn import FostBackend, Middleware


class _TestBase(TestCase):
    """
        Base class for handling some common test set up.
    """
    def setUp(self):
        self.middleware = Middleware()
        self.backend = FostBackend()
        self.request = MockRequest()
        self.key = 'key-value'
        settings.FOST_AUTHN_GET_SECRET = self.secret
    def tearDown(self):
        delattr(settings, 'FOST_AUTHN_GET_SECRET')

    def secret(self, r = None, k = None):
        return 'secret-value'


    
class TestAuthentication(_TestBase):
    """
        Unit tests for the FostBackend itself.
    """
    def setUp(self):
        super(TestAuthentication, self).setUp()
        self.request.sign(self.key, self.secret())
        key, self.hmac = self.middleware.key_hmac(self.request)


    def test_signed_request_missing_timestamp_header(self):
        forbidden = []
        def forbid(error):
            forbidden.append(True)
        del self.request.META['HTTP_X_FOST_TIMESTAMP']
        with mock.patch('fost_authn.authentication._forbid', forbid):
            result = self.backend.authenticate(request = self.request,
                    key = self.key, hmac = self.hmac)
        self.assertTrue(forbidden)
        self.assertEquals(self.request.SIGNED, {})


    def test_signed_request(self):
        with mock.patch('fost_authn.authentication._forbid', self.fail):
            result = self.backend.authenticate(request = self.request,
                key = self.key, hmac = self.hmac)
        self.assertTrue(hasattr(self.request, 'SIGNED'))
        for key in ['X-FOST-Headers']:
            self.assertTrue(self.request.SIGNED.has_key(key), (key, self.request.SIGNED))


class TestSigned(_TestBase):
    def test_signed_request(self):
        user, created = User.objects.get_or_create(username='test-user')
        headers = {'X-FOST-User': user.username}
        self.request.sign(self.key, self.secret(), headers)
        key, self.hmac = self.middleware.key_hmac(self.request)
        with mock.patch('fost_authn.authentication._forbid', self.fail):
            result = self.backend.authenticate(request = self.request,
                key = self.key, hmac = self.hmac)
        self.assertTrue(hasattr(self.request, 'SIGNED'))
        for key in ['X-FOST-Headers', 'X-FOST-User']:
            self.assertTrue(self.request.SIGNED.has_key(key), (key, self.request.SIGNED))
