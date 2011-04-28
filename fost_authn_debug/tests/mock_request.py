from datetime import datetime

from fost_authn.signature import fost_hmac_signature


class MockRequest(object):
    def __init__(self, authz = None, method = 'GET', path = '/', body = ''):
        self.method, self.path, self.raw_post_data = method, path, body
        self.META = {}
        if authz:
            self.META['HTTP_AUTHORIZATION'] = authz

    def sign(self, key, secret):
        if not self.META.has_key('HTTP_X_FOST_TIMESTAMP'):
            self.META['HTTP_X_FOST_TIMESTAMP'] = str(datetime.utcnow())
        if not self.META.has_key('HTTP_X_FOST_HEADERS'):
            self.META['HTTP_X_FOST_HEADERS'] = 'X-FOST-Headers'
        to_sign = {}
        document, signature, headers = \
            fost_hmac_signature(secret, self.method, self.path,
                self.META['HTTP_X_FOST_TIMESTAMP'], to_sign, self.raw_post_data)
        self.META['HTTP_AUTHORIZATION'] = 'FOST %s:%s' % (key, signature)
