try:
    # This API has changed.
    from django.conf.urls import patterns
except ImportError:
    from django.conf.urls.defaults import patterns


urlpatterns = patterns('',
    (r'^$', 'fost_authn_debug.views.root'),
    (r'^anonymous/$', 'fost_authn_debug.views.anonymous'),
    (r'^signed/$', 'fost_authn_debug.views.signed'),
)
