from unittest2 import TestCase
import mock

from django.conf import settings
from django.test.client import Client


class TestFakeHTTPClientUnsigned(TestCase):
    """Tests that don't even try to sign the client requests."""

    def setUp(self):
        self.ua = Client()


    def test_get_root(self):
        called = []
        def authenticate(*a, **kw):
            called.append(True)
        with mock.patch('fost_authn.FostBackend.authenticate', authenticate):
            self.ua.get('/debug/')
        # Nothing calls the Django authenticate function so the Fost backend is never called
        self.assertFalse(called)

    def test_get_anonymous(self):
        response = self.ua.get('/debug/anonymous/')
        self.assertEquals(response.status_code, 200)

    def test_get_unsigned_404(self):
        response = self.ua.get('/debug/not-a-url/')
        self.assertEquals(response.status_code, 404)


class TestFakeHTTPClientMissigned(TestCase):
    """ These tests sign the client requests, but not in a valid way."""

    def setUp(self):
        self.ua = Client()


    def test_get_root_ensure_sleep(self):
        slept = []
        def sleep(t):
            self.assertTrue(t, 0.5)
            slept.append(True)
        with mock.patch('time.sleep', sleep):
            self.ua.get('/debug/', HTTP_AUTHORIZATION='FOST key:hmac')
        self.assertTrue(slept)

    def test_get_root_ensure_sleep_configured(self):
        slept = []
        def sleep(t):
            self.assertTrue(t, 1)
            slept.append(True)
        try:
            setattr(settings, 'FOST_AUTHN_MISSIGNED_SLEEP_TIME', 1)
            with mock.patch('time.sleep', sleep):
                self.ua.get('/debug/', HTTP_AUTHORIZATION='FOST key:hmac')
        finally:
            delattr(settings, 'FOST_AUTHN_MISSIGNED_SLEEP_TIME')
        self.assertTrue(slept)

    def test_get_root_can_get_secret(self):
        secret_fetched = []
        def get_secret(request, key):
            secret_fetched.append(True)
            return 'secret-value'
        try:
            setattr(settings, 'FOST_AUTHN_GET_SECRET', get_secret)
            self.ua.get('/debug/', HTTP_AUTHORIZATION='FOST key:hmac')
        finally:
            delattr(settings, 'FOST_AUTHN_GET_SECRET')
        self.assertTrue(secret_fetched)
