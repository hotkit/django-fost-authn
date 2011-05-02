from django.http import HttpResponse
from django.shortcuts import render_to_response


def root(request):
    return render_to_response('ok.html')


def anonymous(request):
    assert not request.user.is_authenticated()
    return render_to_response('ok.html')


def signed(request):
    assert request.user.is_authenticated()
    return HttpResponse(request.user.username, mimetype='text/plain')
