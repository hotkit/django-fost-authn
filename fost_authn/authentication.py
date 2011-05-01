import logging
import time
from datetime import datetime, timedelta

from django.conf import settings
from django.contrib.auth.models import User

from fost_authn.signature import fost_hmac_signature_with_headers


def _forbid(error):
    logging.info(error)
    time.sleep(getattr(settings, 'FOST_AUTHN_MISSIGNED_SLEEP_TIME', 0.5))


class FostBackend(object):
    def authenticate(self, **kwargs):
        if kwargs.has_key('request') and kwargs.has_key('key') and kwargs.has_key('hmac'):
            request = kwargs['request']
            key = kwargs['key']
            hmac = kwargs['hmac']
            request.SIGNED = {}
            if not hasattr(settings, 'FOST_AUTHN_GET_SECRET'):
                return _forbid("FOST_AUTHN_GET_SECRET is not defined")
            elif not request.META.has_key('HTTP_X_FOST_TIMESTAMP'):
                return _forbid("No HTTP_X_FOST_TIMESTAMP was found")
            secret = settings.FOST_AUTHN_GET_SECRET(request, key)
            logging.info("Found secret %s for key %s", secret, key)
            logging.info("About to parse time stamp from %s",
                request.META['HTTP_X_FOST_TIMESTAMP'][:19])
            signed_time = datetime.strptime(
                request.META['HTTP_X_FOST_TIMESTAMP'][:19], '%Y-%m-%d %H:%M:%S')
            utc_now = datetime.utcnow()
            delta = timedelta(0, getattr(settings,
                'FOST_AUTHN_MAXIMUM_CLOCK_SKEW', 300))
            skew = max(signed_time - utc_now, utc_now - signed_time)
            logging.info(
                "Clock skew is %s based on signed time %s and current time %s "
                    "(maximum skew is %s) %s",
                skew, signed_time, utc_now, delta,
                "skew is too high" if skew > delta else "skew is ok")
            if skew < delta:
                signed_headers, signed = [], {}
                for header in request.META['HTTP_X_FOST_HEADERS'].split():
                    name = 'HTTP_%s' % header.upper().replace('-', '_')
                    value = request.META[name]
                    signed[header] = value
                    signed_headers.append(value)
                document, signature, headers = \
                    fost_hmac_signature_with_headers(secret,
                        request.method, request.path,
                        request.META['HTTP_X_FOST_TIMESTAMP'],
                        signed_headers,
                        request.raw_post_data)
                if signature == hmac:
                    request.SIGNED = signed
                    if request.SIGNED.has_key('X-FOST-User'):
                        return self.get_user(request.SIGNED['X-FOST-User'])
                    else:
                        return self.get_user(1)
                else:
                    return _forbid("Signature didn't match provided hmac")
            else:
                return _forbid("Clock skew too high")
        else:
            _forbid("Not FOST signed")

    def get_user(self, user_id):
        if user_id:
            if type(user_id) == str or type(user_id) == unicode:
                return User.objects.get(username=user_id)
            else:
                return User.objects.get(pk=user_id)

