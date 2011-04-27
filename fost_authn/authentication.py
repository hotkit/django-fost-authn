import time

from django.conf import settings

from fost_authn.signature import fost_hmac_signature


class FostBackend(object):
    def _forbid(self):
        time.sleep(getattr(settings, 'FOST_AUTHN_MISSIGNED_SLEEP_TIME', 0.5))


    def authenticate(self, **kwargs):
        if kwargs.has_key('request') and kwargs.has_key('key') and kwargs.has_key('hmac'):
            request = kwargs['request']
            key = kwargs['key']
            hmac = kwargs['hmac']
            if not hasattr(settings, 'FOST_AUTHN_GET_SECRET'):
                return self._forbid()
            secret = settings.FOST_AUTHN_GET_SECRET(request, key)

    def get_user(self, user_id):
        pass
