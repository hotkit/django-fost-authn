import os
from setuptools import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "django_fost_authn",
    version = "0.1",
    author = "Kirit Saelensminde",
    author_email = "kirit@felspar.com",
    description = ("HTTP SHA1 HMAC authentication backend for Django"),
    license = "Boost Software License - Version 1.0 - August 17th, 2003",
    keywords = "django authentication hmac sha1 fost",
    # url = "http://packages.python.org/an_example_pypi_project",
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
