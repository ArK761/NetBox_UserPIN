"""
Protect views of any plugin with the user's PIN.

Class based views::

    from netbox_user_pin.mixins import PinRequiredMixin

    class ProjectView(PinRequiredMixin, generic.ObjectView):
        pin_scope = 'projects'

Function based views::

    from netbox_user_pin.mixins import pin_required

    @pin_required(scope='projects')
    def my_view(request): ...
"""
from functools import wraps
from urllib.parse import urlencode

from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse

from . import service

__all__ = (
    'PinRequiredMixin',
    'not_allowed_response',
    'pin_gate',
    'pin_required',
)


def _redirect(request, url):
    if request.headers.get('HX-Request'):
        response = HttpResponse(status=204)
        response['HX-Redirect'] = url
        return response
    return HttpResponseRedirect(url)


def not_allowed_response(request):
    return render(request, 'netbox_user_pin/not_allowed.html', status=403)


def pin_gate(request, scope=None):
    """
    Return a redirect response when the PIN still has to be set, changed or entered for ``scope``;
    None when the request may proceed.
    """
    user = getattr(request, 'user', None)
    if user is None or not user.is_authenticated:
        return None  # let the regular login handling deal with it
    if not service.is_allowed(user):
        return not_allowed_response(request)
    params = {'next': request.get_full_path()}
    if scope:
        params['scope'] = scope
    query = urlencode(params)
    if not service.has_pin(user):
        return _redirect(request, f"{reverse('plugins:netbox_user_pin:set_pin')}?{query}")
    if service.pin_expired(user):
        return _redirect(request, f"{reverse('plugins:netbox_user_pin:change_pin')}?{query}&expired=1")
    if not service.is_unlocked(request, scope=scope):
        return _redirect(request, f"{reverse('plugins:netbox_user_pin:unlock')}?{query}")
    return None


class PinRequiredMixin:
    """
    View mixin requiring an unlocked PIN. Place it before the NetBox/Django view class.
    """
    pin_scope = None

    def get_pin_scope(self):
        return self.pin_scope

    def dispatch(self, request, *args, **kwargs):
        if (response := pin_gate(request, scope=self.get_pin_scope())) is not None:
            return response
        return super().dispatch(request, *args, **kwargs)


def pin_required(view_func=None, *, scope=None):
    def decorator(func):
        @wraps(func)
        def wrapper(request, *args, **kwargs):
            if (response := pin_gate(request, scope=scope)) is not None:
                return response
            return func(request, *args, **kwargs)
        return wrapper

    if view_func is not None:
        return decorator(view_func)
    return decorator
