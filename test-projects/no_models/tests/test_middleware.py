from unittest2 import TestCase
import mock

from fost_authn import Middleware


class _Mockrequest(object):
    def __init__(self, authz):
        self.META = {}
        if authz:
            self.META['HTTP_AUTHORIZATION'] = authz


class AuthorizationParser(TestCase):
    def setUp(self):
        self.m = Middleware()

    def test_no_authorization_header(self):
        r = _Mockrequest(None)
        u = self.m.get_mechanism(r)
        self.assertEquals(u, [None, None])

    def test_with_authorization_header(self):
        r = _Mockrequest('BASIC user:pass')
        u = self.m.get_mechanism(r)
        self.assertEquals(u, ['BASIC', 'user:pass'])

    def test_userpass(self):
        u = self.m.get_userpass('user:pass')
        self.assertEquals(u, ['user', 'pass'])

    def test_userpass_malformed(self):
        u = self.m.get_userpass('userpass')
        self.assertEquals(u, [None, None])


class InvalidHeader(TestCase):
    def setUp(self):
        self.m = Middleware()

    def _do_test(self, header, gets_user=False):
        self.request = _Mockrequest(header)
        u = self.m.process_request(self.request)
        self.assertEquals(hasattr(self.request, 'user'), gets_user)

    def test_no_authorization_header(self):
        self._do_test(None)

    def test_fost_authz_no_creds(self):
        self._do_test('FOST')

    def test_fost_authz_no_secret(self):
        self._do_test('FOST key')

    def test_fost_authz_key_and_secret(self):
        def authenticate(**kwargs):
            return True
        with mock.patch('django.contrib.auth.authenticate', authenticate):
            self._do_test('FOST key:secret', gets_user=True)
        self.assertTrue(self.request.user)
