import os
from setuptools import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "django-fost-authn",
    version = "0.2.1.1",
    author = "Kirit Saelensminde",
    author_email = "kirit@felspar.com",
    description = ("HTTP SHA1 HMAC authentication backend for Django"),
    license = "Boost Software License - Version 1.0 - August 17th, 2003",
    keywords = "django authentication hmac sha1 fost",
    packages=['fost_authn', 'fost_authn_debug'],
    long_description=read('README.markdown'),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Framework :: Django",
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: Boost Software License - Version 1.0 - August 17th, 2003",
    ],
)
