from datetime import datetime
from unittest2 import TestCase
import mock

from django.conf import settings
from django.test.client import Client
from django.contrib.auth.models import User

from fost_authn.signature import fost_hmac_request_signature


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


class _Signed(TestCase):
    url = '/debug/signed/'
    secret = 'secret-value'

    def setUp(self):
        self.ua = Client()
        user, created = User.objects.get_or_create(username='test-user1')
        self.user, created = User.objects.get_or_create(username='test-user2')
        self.now = str(datetime.utcnow())

    def get_secret(self, request, key):
        return self.secret


class TestSignedRequests(_Signed):
    """
        Make sure that the requests that are properly signed work as they should.
    """

    def _root_signed(self, method, body_to_sign, *body_for_ua, **extra_heads):
        document, signature = fost_hmac_request_signature(
            self.secret, method.upper(), self.url, self.now,
            headers = extra_heads, body=body_to_sign)
        headers = dict(HTTP_X_FOST_TIMESTAMP = self.now,
            HTTP_X_FOST_HEADERS = 'X-FOST-Headers',
            HTTP_AUTHORIZATION = 'FOST key-value:%s' % signature)
        for key, value in extra_heads.items():
            headers['HTTP_%s' % key.upper().replace('-', '_')] = value
            headers['HTTP_X_FOST_HEADERS'] += ' %s' % key
        try:
            settings.FOST_AUTHN_GET_SECRET = self.get_secret
            with mock.patch('fost_authn.authentication._forbid', self.fail):
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


class TestMissignedURL(_Signed):
    def test_expired(self):
        forbidden = []
        def expired(error):
            forbidden.append(True)
            self.assertEqual(error, "This URL has already expired")
        with mock.patch('fost_authn.authentication._forbid', expired):
            with self.assertRaises(AssertionError):
                self.ua.get('%s?_k=%s&_e=123&_s=signature' %
                    (self.url, self.user.username))
        self.assertTrue(forbidden)


class TestSignedURL(_Signed):
    headers = dict(HTTP_HOST='www.example.com')

    def _test_document(self, query_string = '', **query_params):
        checked = []
        def check_doc(with_e):
            def check_fn(secret, document):
                checked.append(True)
                self.assertEquals(secret, self.secret)
                if with_e:
                    self.assertEquals(document,
                        'www.example.com/debug/signed/%s\n1590379249' % query_string)
                else:
                    self.assertEquals(document,
                        'www.example.com/debug/signed/%s\n' % query_string)
                return 'signature'
            return check_fn
        try:
            settings.FOST_AUTHN_GET_SECRET = self.get_secret
            with mock.patch('fost_authn.authentication._forbid', self.fail):
                with mock.patch('fost_authn.signature.sha1_hmac', check_doc(True)):
                    response = self.ua.get(self.url, dict(_k=self.user.username, _e='1590379249',
                        _s='signature', **query_params), **self.headers)
                with mock.patch('fost_authn.signature.sha1_hmac', check_doc(False)):
                    response = self.ua.get(self.url, dict(_k=self.user.username,
                        _s='signature', **query_params), **self.headers)
        finally:
            delattr(settings, 'FOST_AUTHN_GET_SECRET')
        self.assertTrue(checked)
        self.assertEquals(response.content, self.user.username)

    def test_document_without_querystring(self):
        self._test_document()
    def test_document_with_querystring(self):
        self._test_document('?query=string&hello=there', query='string', hello='there')


    def test_signature_with_expiry(self):
        try:
            settings.FOST_AUTHN_GET_SECRET = self.get_secret
            # expiry set to a date in 2020
            response = self.ua.get(self.url, dict(_k=self.user.username, _e='1590379249',
                        _s='RGemZfy39Wshz+iQnHR2/0Rtfq8='), **self.headers)
        finally:
            delattr(settings, 'FOST_AUTHN_GET_SECRET')
        self.assertEquals(response.content, self.user.username)


class TestMissignedURL(_Signed):
    headers = dict(HTTP_HOST='www.example.com')
    url = '/debug/anonymous/'

    def _check_reason(self, reason = "Signatures didn't match", **_e):
        def check_forbid(error):
            self.assertEquals(error, reason)
        try:
            settings.FOST_AUTHN_GET_SECRET = self.get_secret
            with mock.patch('fost_authn.authentication._forbid', check_forbid):
                # expiry set to a date in 2020
                response = self.ua.get(self.url, dict(_k=self.user.username, _s='signature', **_e),
                    **self.headers)
        finally:
            delattr(settings, 'FOST_AUTHN_GET_SECRET')
        self.assertEquals(response.status_code, 200)

    def test_with_expiry_in_future(self):
        self._check_reason(_e='1590379249')

    def test_without_expiry(self):
        self._check_reason(_e='1590379249')

    def test_with_expiry_in_the_past(self):
        self._check_reason("This URL has already expired", _e="123")
