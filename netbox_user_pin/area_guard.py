"""
Enforcement of the protected areas.

* ``has_perm`` of the logged-in user is replaced for the objects of protected areas (menu items, tabs and every
  permission check of NetBox use it), so that a superuser has no access without a PIN grant either.
* ``process_view`` refuses requests (pages and the REST API) to the objects of a protected area.

Not covered: GraphQL and places that list objects of other types together (global search, dashboard widgets,
the change log). Keep that in mind when an area contains sensitive data.
"""
import logging
import time

from django.conf import settings as django_settings
from django.core.cache import cache
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.utils.functional import SimpleLazyObject
from django.utils import translation
from django.utils.http import urlencode

from . import areas, service
from .models import AreaRequest, AreaRequestStatus, PinEventAction

logger = logging.getLogger('netbox_user_pin')

def arm_user(user):
    """
    Replace ``has_perm`` of this user object (not of the class): for the objects of a protected area the PIN grants
    decide, otherwise NetBox does. ``has_perms`` and every permission check of NetBox go through ``has_perm``.
    """
    if getattr(user, '_userpin_armed', False):
        return user
    original = user.has_perm

    def has_perm(perm, obj=None):
        verdict = areas.check_perm(user, perm)
        if verdict is None:
            return original(perm, obj)
        allowed, area = verdict
        if not allowed:
            return False
        # A plugin area is decided by PIN alone; a NetBox area still needs the NetBox permission as well.
        return True if area.plugin else original(perm, obj)

    user.has_perm = has_perm
    user._userpin_armed = True
    return user


def arm(request):
    """Arm the request's user while an area is active."""
    user = getattr(request, 'user', None)
    if user is None or not areas.active_areas():
        return
    try:
        if isinstance(user, SimpleLazyObject):
            user.is_authenticated  # noqa: B018  (evaluates the lazy object)
            user = user._wrapped
        if user.is_authenticated:
            arm_user(user)
    except Exception:
        logger.exception('Cannot arm the area guard')


def _is_api(request, view_func):
    return request.path_info.startswith('/api/') or hasattr(getattr(view_func, 'cls', None), 'authentication_classes')


def _api_user(request, cls):
    """Authenticate like the REST framework does, to learn who a token request is."""
    from rest_framework.request import Request
    try:
        return Request(request, authenticators=[a() for a in cls.authentication_classes]).user
    except Exception:
        return None


def _model_of(cls):
    queryset = getattr(cls, 'queryset', None)
    if queryset is not None:
        return queryset.model
    return getattr(cls, 'model', None)


def _throttled_log(user, area, right, request):
    key = f'userpin-area-blocked-{user.pk}-{area.pk}'
    if cache.add(key, 1, 3600):
        try:
            service.log_event(PinEventAction.AREA_BLOCKED, user=user, request=request, scope=area.key,
                              detail=f'needs {right}: {request.method} {request.path[:150]}')
        except Exception:
            logger.exception('Cannot log the refused access')


def denied_response(request, area, right='view'):
    user = request.user
    wants_json = request.path_info.startswith('/api/') or 'application/json' in request.headers.get('Accept', '')
    if wants_json:
        return JsonResponse({'detail': f'Access to the protected area "{area.name}" requires a PIN grant.'}, status=403)
    pending = (AreaRequest.objects.filter(area=area, user=user, status=AreaRequestStatus.PENDING).first()
               if getattr(user, 'is_authenticated', False) else None)
    # the page is shown on an ordinary NetBox URL, so the language of the plugin is switched on by hand
    with translation.override(service.get_settings().language or 'en'):
        response = render(request, 'netbox_user_pin/area_denied.html', {
            'area': area, 'right': right, 'pending': pending, 'has_owners': bool(areas.owners(area)),
            'next': request.get_full_path(),
        }, status=403)
        response.render() if hasattr(response, 'render') else None
    return response


class AreaGuardMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        arm(request)
        return self.get_response(request)

    def process_view(self, request, view_func, view_args, view_kwargs):
        if not areas.active_areas():
            return None
        cls = getattr(view_func, 'view_class', None) or getattr(view_func, 'cls', None)
        model = _model_of(cls) if cls is not None else None
        package = (cls.__module__ if cls is not None else getattr(view_func, '__module__', '') or '').split('.')[0]
        if model is None and package not in getattr(django_settings, 'PLUGINS', ()):
            return None  # views without objects (login, logout, own profile ...) are never refused; plugin pages are
        area = areas.area_for(model._meta.app_label if model else None, model._meta.model_name if model else None,
                              package=package)
        if area is None:
            return None
        api = _is_api(request, view_func)
        user = _api_user(request, cls) if api and cls is not None else request.user
        if user is None or not getattr(user, 'is_authenticated', False):
            if api:
                return JsonResponse({'detail': 'Authentication required.'}, status=403)
            return redirect(f'{django_settings.LOGIN_URL}?{urlencode({"next": request.get_full_path()})}')
        right = areas.right_for_request(request, cls, view_kwargs)
        if areas.can(user, area, right):
            return None
        _throttled_log(user, area, right, request)
        return denied_response(request, area, right)
