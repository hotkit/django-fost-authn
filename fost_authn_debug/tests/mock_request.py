from datetime import datetime

from fost_authn.signature import fost_hmac_signature


class MockRequest(object):
    def __init__(self, authz = None, method = 'GET', path = '/', body = ''):
        self.method, self.path, self.raw_post_data = method, path, body
        self.META = {}
        if authz:
            self.META['HTTP_AUTHORIZATION'] = authz

    def sign(self, key, secret, headers = {}):
        if not self.META.has_key('HTTP_X_FOST_TIMESTAMP'):
            self.META['HTTP_X_FOST_TIMESTAMP'] = str(datetime.utcnow())
        if not self.META.has_key('HTTP_X_FOST_HEADERS'):
            self.META['HTTP_X_FOST_HEADERS'] = 'X-FOST-Headers'
        for key, value in headers.items():
            self.META['HTTP_%s' % key.upper().replace('-', '_')] = value
            self.META['HTTP_X_FOST_HEADERS'] += ' %s' % key
        document, signature, headers = \
            fost_hmac_signature(secret, self.method, self.path,
                self.META['HTTP_X_FOST_TIMESTAMP'], headers, self.raw_post_data)
        self.META['HTTP_AUTHORIZATION'] = 'FOST %s:%s' % (key, signature)
