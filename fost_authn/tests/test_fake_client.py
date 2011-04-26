from unittest2 import TestCase

from django.test.client import Client


class TestFakeHTTPClientUnsigned(TestCase):
    def setUp(self):
        self.ua = Client()

    def test_get_unsigned(self):
        response = self.ua.get('/debug/')
        self.assertEquals(response.status_code, 200)
