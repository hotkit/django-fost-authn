from datetime import datetime
from urllib import quote

from fost_authn.signature import fost_hmac_request_signature


class MockRequest(object):
    def __init__(self, authz = None, host = 'www.example.com',
            method = 'GET', path = '/', query_string = '', body = ''):
        self.method, self.path, self.raw_post_data = method, path, body
        self.META = {}
        self.META['HTTP_HOST'] = host
        self.META['QUERY_STRING'] = query_string
        self.GET = {}
        if authz:
            self.META['HTTP_AUTHORIZATION'] = authz

    def sign_request(self, key, secret, headers = {}):
        if not self.META.has_key('HTTP_X_FOST_TIMESTAMP'):
            self.META['HTTP_X_FOST_TIMESTAMP'] = str(datetime.utcnow())
        if not self.META.has_key('HTTP_X_FOST_HEADERS'):
            self.META['HTTP_X_FOST_HEADERS'] = 'X-FOST-Headers'
        for key, value in headers.items():
            self.META['HTTP_%s' % key.upper().replace('-', '_')] = value
            self.META['HTTP_X_FOST_HEADERS'] += ' %s' % key
        query = self.META.get('QUERY_STRING', '')
        document, signature = \
            fost_hmac_request_signature(secret, self.method, self.path,
                self.META['HTTP_X_FOST_TIMESTAMP'], headers, self.raw_post_data or query)
        self.META['HTTP_AUTHORIZATION'] = 'FOST %s:%s' % (quote(key), signature)

    def sign_url(self, key, secret):
        pass
