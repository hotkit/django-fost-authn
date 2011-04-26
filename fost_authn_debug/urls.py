from django.conf.urls.defaults import *

urlpatterns = patterns('',
    (r'^$', 'fost_authn_debug.views.root'),
)
