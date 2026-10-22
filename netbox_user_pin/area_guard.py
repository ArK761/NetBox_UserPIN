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

from django.apps import apps
from django.conf import settings as django_settings
from django.core.cache import cache
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.utils.functional import SimpleLazyObject
from django.utils import translation
from django.utils.translation import gettext as _
from django.utils.http import urlencode

from . import areas, roles, service
from .models import AreaRequest, AreaRequestStatus, PinEventAction

logger = logging.getLogger('netbox_user_pin')

# Pages and API paths of NetBox without any object type behind them (background tasks, system information, the
# plugin catalogue): NetBox lets every superuser in, so "deny everything not allowed" refuses them here.
SYSTEM_PATHS = ('/core/background-', '/core/system', '/core/plugins', '/api/core/background-', '/api/core/system',
                '/api/plugins/installed-plugins', '/api/plugins/catalog')


def _plugin_perm(user, perm):
    """
    The administration of the plugin follows the roles in the PIN, not the NetBox permissions of the user: CORE and the
    heads / delegates of departments see Users, Departments, Approvals and the Audit log; CORE the Settings and Mail.
    ``None``: not a permission of this kind (NetBox decides).
    """
    app_label, _dot, codename = perm.partition('.')
    if app_label != 'netbox_user_pin':
        return None
    action, _underscore, model = codename.partition('_')
    if action != 'view':
        return None
    if areas.keepers():  # with protection keepers a superuser is no PIN authority by being a superuser
        if user.is_superuser and not roles.core_roles().filter(user=user).exists():
            if model in ('userpin', 'pinevent'):
                return roles.managed_departments(user).exists()
            if model == 'pinsettings':
                return False
    if model in ('userpin', 'pinevent'):
        return roles.is_manager(user)
    if model == 'pinsettings':
        return roles.is_core(user)
    return None


def arm_user(user):
    """
    Replace ``has_perm`` of this user object (not of the class): for the objects of a protected area the PIN grants
    decide, otherwise NetBox does. ``has_perms`` and every permission check of NetBox go through ``has_perm``.
    """
    if getattr(user, '_userpin_armed', False):
        return user
    original = user.has_perm

    def has_perm(perm, obj=None):
        decided = _plugin_perm(user, perm)
        if decided is not None:
            return decided
        if perm == 'netbox_user_pin.change_pinsettings' and not roles.is_core(user):
            return False  # settings of the PIN: CORE only, whatever NetBox permission somebody gave himself
        verdict = areas.check_perm(user, perm)
        if verdict is None:
            return original(perm, obj)
        return verdict[0]  # inside a protected area the PIN decides alone

    user.has_perm = has_perm
    user._userpin_armed = True
    return user


def arm(request):
    """Arm the request's user while an area is active."""
    user = getattr(request, 'user', None)
    if user is None:
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


def _request_context(request, area, right, target):
    """What the "no access" page needs for the request form: the blocked object type and the rights to choose."""
    from .area_views import _target_label
    rights = areas.rights_available(area) if area else list(areas.GENERIC_RIGHTS)
    return {
        'target': target or '', 'target_label': _target_label(target) if target else '',
        'right': right, 'rights': [(r, areas.right_label(area, r)) for r in rights],
    }


def _overview(user, blocked):
    """
    What the user is allowed (his groups: rights, visible fields, tabs) and, when the blocked object type is only a
    value of a field he sees (Device › Role), which field - so that the refusal can be explained.
    """
    from .fieldrules import compute_policy, fields_of
    from .models import AreaFieldMode, AreaGrant
    entries, via = [], []
    if not getattr(user, 'is_authenticated', False):
        return {'entries': entries, 'via': via}
    for grant in AreaGrant.objects.filter(user=user, revoked__isnull=True).select_related('area', 'profile'):
        if not grant.is_active or not grant.target:
            continue
        app_label, _dot, model_name = grant.target.partition('.')
        try:
            model = apps.get_model(app_label, model_name)
            policy = compute_policy(user, grant.area, app_label, model_name)
        except LookupError:
            continue
        visible = []
        for key, label, _kind in fields_of(app_label, model_name):
            mode = policy.mode(key) if policy else None
            if mode != AreaFieldMode.HIDDEN:
                visible.append((label, mode))
        tabs = areas.tabs_of(grant.target)
        allowed_tabs = [t['label'] for t in tabs if not t['plugin'] and (
            grant.profile.tabs is None or t['name'] in grant.profile.tabs)]
        entries.append({
            'type': areas.target_label(grant.target),
            'group': grant.profile.name if not grant.profile.private else _('individually'),
            'rights': [str(areas.right_label(grant.area, r)) for r in grant.profile.rights],
            'fields': visible, 'all_fields': policy is None, 'tabs': allowed_tabs,
        })
        if blocked and blocked != grant.target:
            for field in model._meta.get_fields():
                related = getattr(field, 'related_model', None)
                if (related is not None and getattr(field, 'concrete', False) and
                        f'{related._meta.app_label}.{related._meta.model_name}' == blocked and
                        (policy is None or policy.mode(field.name) != AreaFieldMode.HIDDEN)):
                    via.append({'type': areas.target_label(grant.target),
                                'field': str(getattr(field, 'verbose_name', field.name)).capitalize()})
    return {'entries': entries, 'via': via}


def _scope_hint(overview, blocked):
    """The text offered in "What exactly" of the request: what the user needs to see the blocked type as a value."""
    if not overview['via'] or not blocked:
        return ''
    via = overview['via'][0]
    return _('Show %(blocked)s - the value of the field %(field)s of %(type)s') % {
        'blocked': areas.target_label(blocked), 'field': via['field'], 'type': via['type']}


def denied_response(request, area, right='view', target=None, tab_label=None):
    """``area=None``: refused by "deny everything not allowed"."""
    user = request.user
    wants_json = request.path_info.startswith('/api/') or 'application/json' in request.headers.get('Accept', '')
    if area is None:
        if wants_json:
            return JsonResponse({'detail': 'Denied: nothing allows this and everything else is denied.'}, status=403)
        with translation.override(service.get_settings().language or 'en'):
            response = render(request, 'netbox_user_pin/area_denied.html', {
                'area': None, 'deny': True, 'keepers': areas.keepers(), 'next': request.get_full_path(),
                **_request_context(request, None, right, target), 'tab_label': tab_label,
                'pending': AreaRequest.objects.filter(user=user, target=target or '', status=AreaRequestStatus.PENDING
                                                      ).first() if getattr(user, 'is_authenticated', False) else None,
                'overview': (overview := _overview(user, target)), 'scope_hint': _scope_hint(overview, target),
            }, status=403)
            response.render() if hasattr(response, 'render') else None
        return response
    if wants_json:
        return JsonResponse({'detail': f'Access to the protected area "{area.name}" requires a PIN grant.'}, status=403)
    pending = (AreaRequest.objects.filter(area=area, user=user, target=target or '',
                                          status=AreaRequestStatus.PENDING).first()
               if getattr(user, 'is_authenticated', False) else None)
    # the page is shown on an ordinary NetBox URL, so the language of the plugin is switched on by hand
    with translation.override(service.get_settings().language or 'en'):
        response = render(request, 'netbox_user_pin/area_denied.html', {
            'area': area, 'right': right, 'pending': pending, 'owners': areas.owners(area),
            'has_owners': True,
            'next': request.get_full_path(), **_request_context(request, area, right, target),
            'tab_label': tab_label, 'overview': (overview := _overview(user, target)),
            'scope_hint': _scope_hint(overview, target),
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
        if not areas.protection_on() or _is_token_request(request):
            return None
        cls = getattr(view_func, 'view_class', None) or getattr(view_func, 'cls', None)
        model = _model_of(cls) if cls is not None else None
        if model is None:  # the views of the changelog, journal, contacts ... get the model from the URL
            candidate = (view_kwargs or {}).get('model')
            model = candidate if hasattr(candidate, '_meta') else None
        package = (cls.__module__ if cls is not None else getattr(view_func, '__module__', '') or '').split('.')[0]
        if model is None and package not in getattr(django_settings, 'PLUGINS', ()):
            if areas.default_deny_active() and request.path_info.startswith(SYSTEM_PATHS):
                user = request.user
                if getattr(user, 'is_authenticated', False) and not areas.is_keeper(user):
                    return denied_response(request, None, right='view', target=None)
            return None  # views without objects (login, logout, own profile ...) are never refused; plugin pages are
        app_label = model._meta.app_label if model else None
        model_name = model._meta.model_name if model else None
        api = _is_api(request, view_func)
        target = f'{app_label}.{model_name}' if model_name else None
        ask = target or package  # what the "no access" page offers to request
        # a tab of the detail page: (name, label, is_plugin) - a plugin's tab follows the area of that plugin
        tab = None if api else areas.tab_info(cls, app_label, model_name)
        area, rights_target = areas.area_for(app_label, model_name, package=package), target
        if tab and tab[2]:
            plugin_area = areas.area_for(None, None, package=package)
            ask = package
            if plugin_area is not None:
                area, rights_target = plugin_area, None
            elif areas.default_deny_active():
                area = None  # nothing allows the plugin: refused by "deny everything not allowed"
        if area is None and not areas.default_deny_active():
            return None
        user = _api_user(request, cls) if api and cls is not None else request.user
        if user is None or not getattr(user, 'is_authenticated', False):
            if api:
                return JsonResponse({'detail': 'Authentication required.'}, status=403)
            return redirect(f'{django_settings.LOGIN_URL}?{urlencode({"next": request.get_full_path()})}')
        right = areas.right_for_request(request, cls, view_kwargs)
        if area is None:  # "deny everything not allowed" reaches what no area covers
            if not areas.default_deny_blocks(user, app_label, model_name, package):
                return None
            return denied_response(request, None, right=right, target=ask, tab_label=tab[1] if tab else None)
        if areas.can(user, area, right, rights_target):
            if tab and not tab[2] and not areas.tab_allowed(user, area, target, tab[0]):
                _throttled_log(user, area, right, request)
                return denied_response(request, area, right, ask, tab_label=tab[1])
            if (response := _child_denied(request, user, cls, tab)) is not None:
                return response
            # whoever holds access unlocks the PIN to enter (not before the owners exist, and the REST API has no
            # unlock step)
            if not api and areas.owners(area):
                from .mixins import pin_gate
                if service.is_allowed(user) and not service.has_pin(user):
                    from django.contrib import messages
                    with translation.override(service.get_settings().language or 'en'):
                        messages.info(request, _('You have access to "%(area)s". To enter you need a PIN: set it '
                                                 'here and you will continue.') % {'area': area.name})
                if (response := pin_gate(request, scope=f'area-{area.key}')) is not None:
                    return response
            return None
        _throttled_log(user, area, right, request)
        return denied_response(request, area, right, ask, tab_label=tab[1] if tab else None)


def _child_denied(request, user, cls, tab=None):
    """
    A page that lists objects of another type (a device's interfaces) also needs the right on that type - unless it is
    a tab of the object that the group allows: the tab (Interfaces) is then the permission, the rows are those of
    this object.
    """
    child = getattr(cls, 'child_model', None) if cls is not None else None
    meta = getattr(child, '_meta', None)
    if meta is None:
        return None
    child_target = f'{meta.app_label}.{meta.model_name}'
    child_area = areas.area_for(meta.app_label, meta.model_name, package=meta.app_label)
    if child_area is None and tab and not tab[2]:
        request._userpin_children = child_target  # restrict() lets this type through for this request
        return None
    if child_area is not None:
        if areas.can(user, child_area, 'view', child_target):
            return None
        _throttled_log(user, child_area, 'view', request)
        return denied_response(request, child_area, 'view', child_target)
    if areas.default_deny_blocks(user, meta.app_label, meta.model_name, meta.app_label):
        return denied_response(request, None, right='view', target=child_target)
    return None


def _is_token_request(request):
    """A script calling the API or GraphQL with a token: whoever holds the key is not a person at a screen."""
    if request is None or not request.path_info.startswith(('/api/', '/graphql/')):
        return False
    return request.headers.get('Authorization', '').split(' ', 1)[0].lower() in ('token', 'bearer')


def _token_request():
    try:
        from netbox.context import current_request
        return _is_token_request(current_request.get())
    except Exception:  # noqa: BLE001
        return False


def _child_of_allowed_tab(meta):
    """Is this type the list of a tab of an object that the current request was allowed to open (Device › Interfaces)?"""
    try:
        from netbox.context import current_request
        request = current_request.get()
    except Exception:  # noqa: BLE001
        return False
    return getattr(request, '_userpin_children', None) == f'{meta.app_label}.{meta.model_name}'


def install():
    """
    Two small hooks into NetBox, installed once at start:

    * ``RestrictedQuerySet.restrict`` (lists, details, bulk actions, REST API, drop-down lists): in a protected area
      the rows the PIN profiles allow, instead of NetBox's own permission constraints, superusers included.
    * the REST API authentication classes hand over a user that is armed like the one of a page request.
    """
    try:
        from netbox.api.authentication import TokenAuthentication
        from rest_framework.authentication import SessionAuthentication
        from utilities.querysets import RestrictedQuerySet
    except ImportError:
        logger.warning('NetBox internals not found: the row filter of the protected areas is not installed.')
        return

    if not getattr(RestrictedQuerySet.restrict, '_userpin', False):
        original = RestrictedQuerySet.restrict

        def restrict(self, user, action='view'):
            if _token_request():
                return original(self, user, action)
            meta = self.model._meta
            area = areas.area_for(meta.app_label, meta.model_name, package=meta.app_label)
            if area is None:
                if areas.default_deny_blocks(user, meta.app_label, meta.model_name, meta.app_label):
                    # the rows of an allowed tab (Device › Interfaces) are shown whatever NetBox permissions say; the
                    # page narrows them to the object
                    return self if _child_of_allowed_tab(meta) else self.none()  # GraphQL, search, widgets, selectors ... also obey "deny everything not allowed"
                result = original(self, user, action)
                hidden = areas.unseen_objects(user, meta.app_label, meta.model_name)
                if hidden is not None:
                    result = result.exclude(hidden)
                return result
            if action not in areas.rights_available(area):  # sync, render_config, run ... need the right to change
                action = 'change'
            query = areas.row_filter(user, area, meta.app_label, meta.model_name, action)
            if query is None:
                return self.none()
            return self.filter(query) if query else self

        restrict._userpin = True
        RestrictedQuerySet.restrict = restrict

    for cls in (TokenAuthentication, SessionAuthentication):
        if getattr(cls.authenticate, '_userpin', False):
            continue

        def wrap(method):
            def authenticate(self, request):
                result = method(self, request)
                if result and areas.active_areas() and not isinstance(self, TokenAuthentication):
                    arm_user(result[0])  # a token (a script) is NetBox's own business; a browser session is not
                return result
            authenticate._userpin = True
            return authenticate

        cls.authenticate = wrap(cls.authenticate)
