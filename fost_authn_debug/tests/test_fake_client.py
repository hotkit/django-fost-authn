from unittest2 import TestCase

from django.test.client import Client


class TestFakeHTTPClientUnsigned(TestCase):
    def setUp(self):
        self.ua = Client()

    def test_get_root(self):
        self.ua.get('/debug/')

    def test_get_unsigned(self):
        response = self.ua.get('/debug/anonymous/')
        self.assertEquals(response.status_code, 200)

    def test_get_unsigned_404(self):
        response = self.ua.get('/debug/not-a-url/')
        self.assertEquals(response.status_code, 404)
