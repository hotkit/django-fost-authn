from unittest2 import TestCase

from fost_authn.signature import fost_hmac_signature, sha1_hmac


class TestSignature(TestCase):
    document = """GET /\n2011-04-27 03:26:37.625618\nX-FOST-Headers\n"""
    def test_sha1_hmac(self):
        signature = sha1_hmac('secret-value', self.document)
        self.assertEquals(signature, 'Ttq8K3g/jm7sOAVzCN+3k4FVAso=')

    def test_get(self):
        document, signature, headers  = \
            fost_hmac_signature('secret-value', 'GET', '/', '2011-04-27 03:26:37.625618')
        self.assertEquals(document, self.document)
        self.assertEquals(signature, 'Ttq8K3g/jm7sOAVzCN+3k4FVAso=')


class TestHeaderSignatures(TestCase):
    def test_get_with_user(self):
        document, signature, headers = \
            fost_hmac_signature('secret-value', 'GET', '/', '2011-04-27 03:26:37.625618', {
                'X-FOST-User': 'admin'})
        self.assertEquals(document,
            """GET /\n2011-04-27 03:26:37.625618\nX-FOST-Headers X-FOST-User\nadmin\n""")