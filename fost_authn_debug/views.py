from django.http import HttpResponse
from django.shortcuts import render_to_response


def root(request):
    return HttpResponse("Debug helper", mimetype='text/plain')


def anonymous(request):
    assert not request.user.is_authenticated()
    return render_to_response('ok.html')
