from unittest2 import TestCase

from fost_authn.hmac import fost_hmac_signature


class TestSignature(TestCase):
    def test_get(self):
        signature = fost_hmac_signature('GET', '/', None)
