import logging


class Middleware:
    def get_mechanism(self, request):
        if request.META.has_key('HTTP_AUTHORIZATION'):
            parsed = request.META['HTTP_AUTHORIZATION'].split()
            logging.debug("Found HTTP authorization header with values %s", parsed)
            if len(parsed) == 2:
                return parsed
        return [None, None]

    def get_userpass(self, authorization):
        credentials = authorization.split(':')
        if len(credentials) == 2:
            return credentials
        return [None, None]

    def process_request(self, request):
        [mechanism, authorization] = self.get_mechanism(request)
        if mechanism == "FOST":
            [key, hmac] = self.get_userpass(authorization)
