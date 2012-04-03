from datetime import datetime, timedelta
import logging
import time
from urllib import unquote

from django.conf import settings
from django.contrib.auth.models import User

from fost_authn.signature import fost_hmac_url_signature, \
    fost_hmac_request_signature_with_headers, filter_query_string


class FostBackend(object):
    def authenticate(self, **kwargs):
        try:
            if kwargs.has_key('request'):
                if kwargs.has_key('key') and kwargs.has_key('hmac'):
                    return _request_signature(self, **kwargs)
                else:
                    return _url_signature(self, **kwargs)
            else:
                _forbid("Not FOST signed")
        except User.DoesNotExist:
            _forbid("User not found")

    def get_user(self, user_id):
        if user_id:
            return User.objects.get(username=user_id)


def _forbid(error):
    logging.info(error)
    time.sleep(getattr(settings, 'FOST_AUTHN_MISSIGNED_SLEEP_TIME', 0.5))


def _url_signature(backend, request):
    if request.GET.has_key('_e'):
        _e = request.GET['_e']
        expires = datetime.utcfromtimestamp(long(_e))
        now = datetime.utcnow()
        logging.info("URL expires at %s and server time is now %s", expires, now)
        if expires < now:
            return _forbid('This URL has already expired')
    else:
        _e = ''
    key = request.GET['_k']
    secret = settings.FOST_AUTHN_GET_SECRET(request, key)
    query = filter_query_string(request.META['QUERY_STRING'])
    logging.info("Query string %s changed to %s for signing",
        request.META['QUERY_STRING'], query)
    signature = fost_hmac_url_signature(key, secret,
        request.META['HTTP_HOST'], request.path, query, _e)
    if signature == request.GET['_s']:
        return backend.get_user(key)
    else:
        return _forbid("Signatures didn't match")


def _default_authn_get_secret(request, key):
    user = User.objects.get(username=unquote(key))
    return str(user.password)


def _request_signature(backend, request, key, hmac):
    if not request.META.has_key('HTTP_X_FOST_TIMESTAMP'):
        return _forbid("No HTTP_X_FOST_TIMESTAMP was found")
    secret = getattr(settings, 'FOST_AUTHN_GET_SECRET',
        _default_authn_get_secret)(request, key)
    logging.info("Found secret %s for key %s", secret, key)
    logging.info("About to parse time stamp from %s",
        request.META['HTTP_X_FOST_TIMESTAMP'][:19])
    signed_time = datetime.strptime(
        request.META['HTTP_X_FOST_TIMESTAMP'][:19].replace('T', ' '),
        '%Y-%m-%d %H:%M:%S')
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
        logging.debug("Signed headers: %s", request.META['HTTP_X_FOST_HEADERS'])
        for header in request.META['HTTP_X_FOST_HEADERS'].split():
            logging.info("Header %s included in signed set", header)
            name = 'HTTP_%s' % header.upper().replace('-', '_')
            value = request.META[name]
            signed[header] = value
            signed_headers.append(value)
        document, signature = fost_hmac_request_signature_with_headers(
            secret,
            request.method, request.path,
            request.META['HTTP_X_FOST_TIMESTAMP'],
            signed_headers,
            request.raw_post_data or request.META.get('QUERY_STRING', ''))
        if signature == hmac:
            request.SIGNED = signed
            if request.SIGNED.has_key('X-FOST-User'):
                return backend.get_user(request.SIGNED['X-FOST-User'])
            else:
                return backend.get_user(unquote(key))
        else:
            return _forbid("Signature didn't match provided hmac")
    else:
        return _forbid("Clock skew too high")
