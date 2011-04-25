from unittest2 import TestCase

from django.test.client import Client


class TestFakeHTTPClient(TestCase):
    def setUp(self):
        self.ua = Client()

    def test_get_unsigned(self):
        response = self.ua.get('/')
        self.assertEquals(response.status_code, 200)
