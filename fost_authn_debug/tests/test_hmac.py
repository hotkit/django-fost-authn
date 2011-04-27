from unittest2 import TestCase

from fost_authn.signature import fost_hmac_signature


class TestSignature(TestCase):
    def test_get(self):
        signature = fost_hmac_signature('secret', 'GET', '/', '2010-04-05 14:45:34')
