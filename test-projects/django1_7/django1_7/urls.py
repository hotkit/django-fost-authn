from django.conf.urls import patterns, include, url
from django.contrib import admin

urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'django1_7.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),

    (r'^debug/', include('fost_authn_debug.urls')),

    url(r'^admin/', include(admin.site.urls)),
)