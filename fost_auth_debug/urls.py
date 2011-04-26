from django.conf.urls.defaults import *

urlpatterns = patterns('',
    (r'^$', 'fost_auth_debug.views.root'),
)
