from unittest2 import TestCase

from django.test.client import Client


class TestFakeHTTPClientUnsigned(TestCase):
    """Tests that don't even try to sign the client requests."""

    def setUp(self):
        self.ua = Client()

    def test_get_root(self):
        self.ua.get('/debug/')

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
        old_get = self.ua.get
        self.ua.get = lambda p, d = {}: old_get(p, d, HTTP_AUTHORIZATION='FOST key:hmac')

    def test_get_root(self):
        self.ua.get('/debug/')
