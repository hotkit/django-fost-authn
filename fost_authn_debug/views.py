from django.http import HttpResponse


def root(request):
    return HttpResponse("Debug helper", mimetype='text/plain')
