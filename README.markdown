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

# Running tests #

For best results create a virtualenv, then initialise it with test.pip.:

    mkvirtualenv django-fost-authn
    pip install -r test.pip

Run the tests using:

    ./runtest

