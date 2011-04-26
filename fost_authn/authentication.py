

class FostBackend(object):
    def authenticate(self, **kwargs):
        if kwargs.has_key('request') and kwargs.has_key('key') and kwargs.has_key('hmac'):
            pass

    def get_user(self, user_id):
        pass
