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

    def add_users(self, *users):
        for user in users:
            u, c = User.objects.get_or_create(username=user)
        return u


class _TestBaseWithGetSecret(_TestBase):
    """
        Adds in the mechanism for determining the secret.
    """
    def setUp(self):
        super(_TestBaseWithGetSecret, self).setUp()
        self.key = self.add_users('key-value').username
        settings.FOST_AUTHN_GET_SECRET = self.secret
    def tearDown(self):
        delattr(settings, 'FOST_AUTHN_GET_SECRET')
        super(_TestBaseWithGetSecret, self).tearDown()

    def secret(self, r = None, k = None):
        return 'secret-value'


class TestAuthentication(_TestBaseWithGetSecret):
    """
        Unit tests for the FostBackend itself.
    """
    def setUp(self):
        super(TestAuthentication, self).setUp()
        u, c = User.objects.get_or_create(username='test-user')
        self.request.sign_request(self.key, self.secret())
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


class TestSigned(_TestBaseWithGetSecret):
    """
        Perform various tests on the signed headers
    """
    def test_signed_request(self):
        user = self.add_users('test-user1', 'test-user2')
        headers = {'X-FOST-User': user.username}
        self.request.sign_request(self.key, self.secret(), headers)
        key, self.hmac = self.middleware.key_hmac(self.request)
        with mock.patch('fost_authn.authentication._forbid', self.fail):
            result = self.backend.authenticate(request = self.request,
                key = self.key, hmac = self.hmac)
        self.assertTrue(hasattr(self.request, 'SIGNED'))
        for key in ['X-FOST-Headers', 'X-FOST-User']:
            self.assertTrue(self.request.SIGNED.has_key(key), (key, self.request.SIGNED))
        self.assertEquals(result, user)


class TestSignedWithUserKey(_TestBase):
    def test_signed_request(self):
        user = self.add_users('test-user1')
        self.request.sign_request(user.username, user.password.encode('utf-8'), {})
        self.key, self.hmac = self.middleware.key_hmac(self.request)
        with mock.patch('fost_authn.authentication._forbid', self.fail):
            result = self.backend.authenticate(request = self.request,
                key = self.key, hmac = self.hmac)
        self.assertTrue(hasattr(self.request, 'SIGNED'))
        self.assertEqual(result, user)

    def test_signed_request_with_odd_username(self):
        user = self.add_users('test:user1')
        self.request.sign_request(user.username, user.password.encode('utf-8'), {})
        self.key, self.hmac = self.middleware.key_hmac(self.request)
        with mock.patch('fost_authn.authentication._forbid', self.fail):
            result = self.backend.authenticate(request = self.request,
                key = self.key, hmac = self.hmac)
        self.assertTrue(hasattr(self.request, 'SIGNED'))
        self.assertEqual(result, user)
