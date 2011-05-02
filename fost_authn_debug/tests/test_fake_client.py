from datetime import datetime
from unittest2 import TestCase
import mock

from django.conf import settings
from django.test.client import Client
from django.contrib.auth.models import User

from fost_authn.signature import fost_hmac_signature


class TestFakeHTTPClientUnsigned(TestCase):
    """
        Tests that don't even try to sign the client requests.
    """

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
    """
        These tests sign the client requests, but not in a valid way.
    """

    def setUp(self):
        self.ua = Client()
        self.headers = dict(
            HTTP_AUTHORIZATION='FOST key:hmac',
            HTTP_X_FOST_TIMESTAMP='2011-04-27 11:10:00',
            HTTP_X_FOST_HEADERS = 'X-FOST-Headers')

    def test_get_root_ensure_sleep(self):
        slept = []
        def sleep(t):
            self.assertTrue(t, 0.5)
            slept.append(True)
        with mock.patch('time.sleep', sleep):
            self.ua.get('/debug/', **self.headers)
        self.assertTrue(slept)

    def test_get_root_ensure_sleep_configured(self):
        slept = []
        def sleep(t):
            self.assertTrue(t, 1)
            slept.append(True)
        try:
            setattr(settings, 'FOST_AUTHN_MISSIGNED_SLEEP_TIME', 1)
            with mock.patch('time.sleep', sleep):
                self.ua.get('/debug/', **self.headers)
        finally:
            delattr(settings, 'FOST_AUTHN_MISSIGNED_SLEEP_TIME')
        self.assertTrue(slept)

    def test_get_root_can_get_secret_but_clock_skew_too_high(self):
        secret_fetched, forbidden = [], []
        def get_secret(request, key):
            secret_fetched.append(True)
            return 'secret-value'
        def clock_skew_error(error):
            forbidden.append(True)
            self.assertEquals(error, 'Clock skew too high')
        try:
            setattr(settings, 'FOST_AUTHN_GET_SECRET', get_secret)
            with mock.patch('fost_authn.authentication._forbid', clock_skew_error):
                self.ua.get('/debug/', **self.headers)
        finally:
            delattr(settings, 'FOST_AUTHN_GET_SECRET')
        self.assertTrue(secret_fetched)
        self.assertTrue(forbidden)

    def test_get_root_can_get_secret_clock_skew_in_range(self):
        secret_fetched, forbidden = [], []
        def get_secret(request, key):
            secret_fetched.append(True)
            return 'secret-value'
        def forbid(error):
            self.assertEquals(error, "Signature didn't match provided hmac")
            forbidden.append(True)
        try:
            settings.FOST_AUTHN_GET_SECRET = get_secret
            with mock.patch('fost_authn.authentication._forbid', forbid):
                self.headers['HTTP_X_FOST_TIMESTAMP'] = str(datetime.utcnow())
                self.ua.get('/debug/', **self.headers)
        finally:
            delattr(settings, 'FOST_AUTHN_GET_SECRET')
        self.assertTrue(secret_fetched)
        self.assertTrue(forbidden)


class TestSignedRequests(TestCase):
    """
        Make sure that the requests that are properly signed work as they should.
    """
    def setUp(self):
        self.ua = Client()
        user, created = User.objects.get_or_create(username='test-user1')
        self.user, created = User.objects.get_or_create(username='test-user2')
        self.now = str(datetime.utcnow())
        self.url = '/debug/signed/'
        self.secret = 'secret-value'

    def get_secret(self, request, key):
        return self.secret

    def forbid(error):
        self.fail(error)

    def _root_signed(self, method, body_to_sign, *body_for_ua, **extra_heads):
        document, signature = \
            fost_hmac_signature(self.secret, method.upper(), self.url, self.now,
                headers = extra_heads, body=body_to_sign)
        headers = dict(HTTP_X_FOST_TIMESTAMP = self.now,
            HTTP_X_FOST_HEADERS = 'X-FOST-Headers',
            HTTP_AUTHORIZATION = 'FOST key-value:%s' % signature)
        for key, value in extra_heads.items():
            headers['HTTP_%s' % key.upper().replace('-', '_')] = value
            headers['HTTP_X_FOST_HEADERS'] += ' %s' % key
        try:
            settings.FOST_AUTHN_GET_SECRET = self.get_secret
            with mock.patch('fost_authn.authentication._forbid', self.forbid):
                response = getattr(self.ua, method)(self.url, *body_for_ua, **headers)
        finally:
            delattr(settings, 'FOST_AUTHN_GET_SECRET')
        self.assertEquals(response.status_code, 200)
        return response

    def test_get_root_signed(self):
        self._root_signed('get', '', {})
    def test_get_root_signed_with_user_header(self):
        response = self._root_signed('get', '', **{
                'X-FOST-User': self.user.username})
        self.assertEquals(response.content, self.user.username)

    def test_post_root_signed(self):
        self._root_signed('post', '--BoUnDaRyStRiNg\r\n'
            'Content-Disposition: form-data; name="body"\r\n\r\n'
            'data\r\n--BoUnDaRyStRiNg--\r\n', {'body': 'data'})
    def test_post_root_signed(self):
        response = self._root_signed('post', '--BoUnDaRyStRiNg\r\n'
            'Content-Disposition: form-data; name="body"\r\n\r\n'
            'data\r\n--BoUnDaRyStRiNg--\r\n', {'body': 'data'}, **{
                'X-FOST-User': self.user.username})
        self.assertEquals(response.content, self.user.username)

