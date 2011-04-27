from datetime import datetime


class MockRequest(object):
    def __init__(self, authz):
        self.META = {}
        if authz:
            self.META['HTTP_AUTHORIZATION'] = authz
            self.META['HTTP_X_FOST_TIMESTAMP'] = str(datetime.utcnow())
