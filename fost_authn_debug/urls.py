try:
    # This API has changed.
    from django.conf.urls import url
except ImportError:
    from django.conf.urls.defaults import url


urlpatterns = [
    url(r'^$', 'fost_authn_debug.views.root'),
    url(r'^anonymous/$', 'fost_authn_debug.views.anonymous'),
    url(r'^signed/$', 'fost_authn_debug.views.signed'),
]
