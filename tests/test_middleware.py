from unittest2 import TestCase

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


class RequestHandler(TestCase):
    def setUp(self):
        self.m = Middleware()

    def test_no_authorization_header(self):
        r = _Mockrequest(None)
        u = self.m.process_request(r)
        self.assertEquals(u, None)

