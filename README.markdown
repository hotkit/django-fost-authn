# Django Fost Authentication #


An authentication back-end for Django implementing request signing using strong cryptography. It is based on the request signing mechanism implemented by Amazon for s3.

# To use in a Django project #

Add the git repository to your pip install file and then use:

    pip install -r setup.pip

To your settings.py you need to add the middleware. It doesn't matter where in the middleware list it is added:

    MIDDLEWARE_CLASSES = (
        'django.middleware.common.CommonMiddleware',
        'django.contrib.sessions.middleware.SessionMiddleware',
        'django.middleware.csrf.CsrfViewMiddleware',
        'django.contrib.auth.middleware.AuthenticationMiddleware',
        'django.contrib.messages.middleware.MessageMiddleware',
        'fost_authn.Middleware',
    )

Unless you've already added a custom authentication backend your settings.py probably doesn't already have the authentication backends set on it. The following will enable the normal Django authentication (forms/session based) and the Fost authentication:

    AUTHENTICATION_BACKENDS = (
        'django.contrib.auth.backends.ModelBackend',
        'fost_authn.FostBackend',
    )

In order to be able to authenticate requests the authentication backend needs to know how to map API keys to secrets and to users.

Finding a secret from an API key is done by giving a function to the FOST_AUTHN_GET_SECRET setting. If this is not configured then no requests can be authenticated. The following is an example of what can be put in the settings.py.

    def FOST_AUTHN_GET_SECRET(request, key):
        from myapp.models import api_keys
        return api_keys.objects.get(key=key).secret


## Changes to existing Django classes ##

After installing the authentication middleware the Django HttpRequest object is augmented with a new member, SIGNED, which is a `dict` holding the signed request header members. If the request has not been properly signed this `dict` will be empty.


## Optional settings ##

FOST_AUTHN_MISSIGNED_SLEEP_TIME

The amount of time to sleep when a FOST Authorization header is incorrect. Defaults to 0.5 seconds.

FOST_AUTHN_MAXIMUM_CLOCK_SKEW

The maximum allowed difference between the time when the request was signed and the time on the server. Defaults to 300 seconds.


# Signing requests #

In order to authenticate against the back end requests must be properly signed. `fost_auth.signature' includes two functions for doing this that can be used.

## `fost_hmac_signature(secret, method, path, timestamp, headers = {}, body = '')` ##

The headers are in the form of a dict giving the header name and values. The function returns both the signature and the document that was signed.

It is the responsibility of the caller to correctly place the header values into the request object that is to be used, including the `Authorization` header.


# Running tests #

For best results create a virtualenv, then initialise it with test.pip.:

    mkvirtualenv django-fost-authn
    pip install -r test.pip

Run the tests using:

    ./runtest

