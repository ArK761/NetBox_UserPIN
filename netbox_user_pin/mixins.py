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

Sensitive actions (fresh PIN + 2FA confirmation, "step-up")::

    class ProjectDeleteView(StepUpRequiredMixin, generic.ObjectDeleteView): ...

    @step_up_required
    def delete(request, pk): ...
"""
from functools import wraps
from urllib.parse import urlencode

from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import render
from django.urls import reverse

from . import service

__all__ = (
    'PinRequiredMixin',
    'StepUpRequiredMixin',
    'not_allowed_response',
    'pin_gate',
    'pin_required',
    'step_up_gate',
    'step_up_required',
)


def _redirect(request, url):
    if request.headers.get('HX-Request'):
        response = HttpResponse(status=204)
        response['HX-Redirect'] = url
        return response
    return HttpResponseRedirect(url)


def not_allowed_response(request):
    return render(request, 'netbox_user_pin/not_allowed.html', status=403)


def suspended_response(request):
    return render(request, 'netbox_user_pin/not_allowed.html', {'suspended': True}, status=403)


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
    if service.is_suspended(user):
        return suspended_response(request)
    params = {'next': request.get_full_path()}
    if scope:
        params['scope'] = scope
    query = urlencode(params)
    if not service.has_pin(user):
        return _redirect(request, f"{reverse('plugins:netbox_user_pin:set_pin')}?{query}")
    if service.pin_expired(user):
        return _redirect(request, f"{reverse('plugins:netbox_user_pin:change_pin')}?{query}&expired=1")
    if service.get_settings().require_2fa_unlock and not service.has_2fa(user):
        return _redirect(request, f"{reverse('plugins:netbox_user_pin:totp_setup')}?{query}")
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


def step_up_gate(request, level='full'):
    """
    Return a redirect to the confirmation page unless a step-up is currently valid (``level='full'``: PIN + 2FA,
    ``level='settings'``: PIN, see service.step_up_needs_2fa).
    """
    user = getattr(request, 'user', None)
    if user is None or not user.is_authenticated:
        return None
    if not service.is_allowed(user):
        return not_allowed_response(request)
    if service.has_step_up(request, level):
        return None
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({'ok': False, 'step_up': True}, status=403)
    next_url = request.get_full_path() if request.method == 'GET' else request.META.get('HTTP_REFERER', '')
    query = urlencode({'next': next_url, 'level': level})
    return _redirect(request, f"{reverse('plugins:netbox_user_pin:step_up')}?{query}")


class StepUpRequiredMixin:
    """View mixin requiring a fresh PIN (+ 2FA) confirmation. Place it before the NetBox/Django view class."""

    def dispatch(self, request, *args, **kwargs):
        if (response := step_up_gate(request)) is not None:
            return response
        return super().dispatch(request, *args, **kwargs)


def step_up_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if (response := step_up_gate(request)) is not None:
            return response
        return view_func(request, *args, **kwargs)
    return wrapper
