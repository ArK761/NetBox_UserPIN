"""
Enforcement of the protected areas.

* ``has_perm`` of the logged-in user is replaced for the objects of protected areas (menu items, tabs and every
  permission check of NetBox use it), so that a superuser has no access without a PIN grant either.
* ``process_view`` refuses requests (pages and the REST API) to the objects of a protected area.

Not covered: GraphQL and places that list objects of other types together (global search, dashboard widgets,
the change log). Keep that in mind when an area contains sensitive data.
"""
import logging
import re
import time

from django.apps import apps
from django.conf import settings as django_settings
from django.core.cache import cache
from django.db.models import Q
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.utils.functional import SimpleLazyObject
from django.utils import translation
from django.utils.translation import gettext as _
from django.utils.http import urlencode

from . import areas, guests, roles, service
from .models import AreaRequest, AreaRequestStatus, PinEventAction

logger = logging.getLogger('netbox_user_pin')

# Pages and API paths of NetBox without any object type behind them (background tasks, system information, the
# plugin catalogue): NetBox lets every superuser in, so "deny everything not allowed" refuses them here.
SYSTEM_PATHS = ('/core/background-', '/core/system', '/core/plugins', '/api/core/background-', '/api/core/system',
                '/api/plugins/installed-plugins', '/api/plugins/catalog',
                # the own profile and preferences: the only thing left open is changing the password
                '/user/profile', '/user/preferences', '/user/notifications', '/user/bookmarks', '/user/subscriptions', '/user/api-tokens')


def _plugin_perm(user, perm):
    """
    The administration of the plugin follows the roles in the PIN, not the NetBox permissions of the user: CORE and the
    heads / delegates of departments see Users, Departments, Approvals and the Audit log; CORE the Settings and Mail.
    ``None``: not a permission of this kind (NetBox decides).
    """
    app_label, _dot, codename = perm.partition('.')
    if app_label != 'netbox_user_pin':
        return None
    if guests.is_guest(user):
        return False  # a person with a PIN only has no administration, no PIN pages - only their own guest pages
    if areas.outside(user):
        return None  # the PIN does not rule him: NetBox's permissions decide what he sees of this plugin too
    if codename == 'view_mypin':
        return True
    action, _underscore, model = codename.partition('_')
    if model == 'guestspage':
        return action == 'view' and (areas.is_keeper(user) or areas.administers_any(user))
    if action != 'view':
        return None
    # the items of the "My PIN" part of the menu: B takes from the user who is in no group what is not the PIN itself
    if model in ('myroles', 'myaccess', 'pintest', 'areaspage'):
        nothing = areas.sees_nothing(user)
        if model == 'myroles':
            return not nothing or roles.is_manager(user)
        if model == 'myaccess':
            return areas.requests_allowed() if nothing else True
        if model == 'pintest':
            return not nothing
        return areas.administers_any(user)
    # with protection keepers and CORE deputies a superuser is no PIN authority by being a superuser; while there is
    # no CORE deputy, the master still manages the PINs (otherwise nobody could)
    if areas.keepers() and roles.core_roles().exists():
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
        if perm.startswith('userpin.import:'):  # the menu button "Import" of an object type
            try:
                return _may_use(user, apps.get_model(perm.partition(':')[2]), 'import')
            except LookupError:
                return False
        decided = _plugin_perm(user, perm)
        if decided is not None:
            return decided
        if perm.partition('.')[2].startswith('view_') and _select_perm(perm):
            return True  # the one request that serves the drop-down of a relation field
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


def denied_response(request, area, right='view', target=None, tab_label=None, only_password=False):
    """``area=None``: refused by "deny everything not allowed"."""
    user = request.user
    wants_json = request.path_info.startswith('/api/') or 'application/json' in request.headers.get('Accept', '')
    if area is None:
        if wants_json:
            response = JsonResponse({'detail': 'Denied: nothing allows this and everything else is denied.'}, status=403)
            response['X-UserPIN'] = 'denied'
            return response
        with translation.override(service.get_settings().language or 'en'):
            response = render(request, 'netbox_user_pin/area_denied.html', {
                'area': None, 'deny': True, 'keepers': areas.keepers(), 'next': request.get_full_path(),
                **_request_context(request, None, right, target), 'tab_label': tab_label,
                'only_password': only_password, 'can_request': areas.requests_allowed(),
                'own_tokens': areas.own_tokens_allowed(),
                'pending': AreaRequest.objects.filter(user=user, target=target or '', status=AreaRequestStatus.PENDING
                                                      ).first() if getattr(user, 'is_authenticated', False) else None,
                'overview': (overview := _overview(user, target)), 'scope_hint': _scope_hint(overview, target),
            }, status=403)
            response.render() if hasattr(response, 'render') else None
        response['X-UserPIN'] = 'denied'
        return response
    if wants_json:
        response = JsonResponse({'detail': f'Access to the protected area "{area.name}" requires a PIN grant.'},
                                status=403)
        response['X-UserPIN'] = 'denied'
        return response
    pending = (AreaRequest.objects.filter(area=area, user=user, target=target or '',
                                          status=AreaRequestStatus.PENDING).first()
               if getattr(user, 'is_authenticated', False) else None)
    # the page is shown on an ordinary NetBox URL, so the language of the plugin is switched on by hand
    with translation.override(service.get_settings().language or 'en'):
        response = render(request, 'netbox_user_pin/area_denied.html', {
            'area': area, 'right': right, 'pending': pending, 'owners': areas.owners(area),
            'has_owners': True,
            'next': request.get_full_path(), **_request_context(request, area, right, target),
            'can_request': areas.requests_allowed(),
            'tab_label': tab_label, 'overview': (overview := _overview(user, target)),
            'scope_hint': _scope_hint(overview, target),
        }, status=403)
        response.render() if hasattr(response, 'render') else None
    response['X-UserPIN'] = 'denied'
    return response


class AreaGuardMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path_info
        chosen = guests.login_path()
        if path.rstrip('/').lower() == chosen.rstrip('/').lower():
            # the address chosen for the PIN-only sign-in serves the page itself (no redirect into the plugin)
            if not path.endswith('/'):
                return redirect(chosen)
            from django.views.decorators.csrf import csrf_protect
            from .guest_views import GuestPinLoginView
            return csrf_protect(GuestPinLoginView.as_view())(request)
        if not getattr(getattr(request, 'user', None), 'is_authenticated', False) and not path.startswith(OPEN_ANONYMOUS):
            # nobody signed in sees nothing of NetBox (no menu, no plugin, no 'page not found'): only a sign-in
            if path.startswith(('/api/', '/graphql')):
                if not _is_token_request(request):
                    return JsonResponse({'detail': 'Authentication credentials were not provided.'}, status=403)
            elif request.headers.get('HX-Request'):
                from django.http import HttpResponse
                return HttpResponse(status=401)
            else:
                return redirect(f"{django_settings.LOGIN_URL}?{urlencode({'next': request.get_full_path()})}")
        arm(request)
        response = self.get_response(request)
        user = getattr(request, 'user', None)
        if (_hides_menu_for(user) and not getattr(response, 'streaming', False)
                and 'text/html' in response.get('Content-Type', '') and hasattr(response, 'content')):
            try:
                response.content = _shape_html(request, response.content.decode(response.charset)).encode(response.charset)
                if response.has_header('Content-Length'):
                    response['Content-Length'] = str(len(response.content))
            except Exception:  # noqa: BLE001 - the page is more important than its shaping
                logger.exception('Cannot shape the page for the PIN visibility B')
        return response

    def process_view(self, request, view_func, view_args, view_kwargs):
        guest = guests.guest_of(request.user)
        if guest is not None and (response := guests.guard(request, guest)) is not None:
            return response
        if guest is not None and guest.ui_language and not request.path_info.startswith('/plugins/user-pin/'):
            # the NetBox interface in the language chosen for this person (not the browser's)
            translation.activate(guest.ui_language)
            request.LANGUAGE_CODE = guest.ui_language
            request._language_cookie = guest.ui_language  # NetBox's middleware renews the cookie with it
        if _hides_menu_for(request.user) and request.path_info.startswith(HIDDEN_DOCS) \
                and not _is_token_request(request):
            return denied_response(request, None, right='view', target=None)
        if not getattr(request.user, 'is_authenticated', False) and getattr(view_func, '__module__', '').startswith(
                'netbox_user_pin.'):
            return None  # the pages of this plugin ask for the sign-in themselves (the public link of a PIN-only access)
        if request.path_info == guests.OWN_CONFIG and request.method in ('GET', 'PATCH') and getattr(
                request.user, 'is_authenticated', False):
            return None  # own table columns and preferences: NetBox touches only the config of the signed-in user
        if not areas.protection_on() or _is_token_request(request) or areas.is_exempt(request.user):
            return None  # (an exception: NetBox's own permissions rule the user)
        if request.path_info.startswith('/graphql') and _graphql_would_leak(request):
            return denied_response(request, None, right='view', target=None)
        if request.path_info == '/' and request.method == 'GET' and areas.sees_nothing(request.user):
            return redirect('plugins:netbox_user_pin:my_pin')  # nothing to see: what he may do is the PIN
        if areas.sees_nothing(request.user) and not _open_to_the_unlisted(request):
            return denied_response(request, None, right='view', target=None, only_password=True)
        cls = getattr(view_func, 'view_class', None) or getattr(view_func, 'cls', None)
        if cls is not None and request.method in ('GET', 'POST') and not request.path_info.startswith('/api/') and \
                any(word in cls.__name__ for word in ('Edit', 'Create', 'Import')):
            request._userpin_edit = True  # the form fields may offer what the user may pick (see _form_pick)
        model = _model_of(cls) if cls is not None else None
        if model is None:  # the views of the changelog, journal, contacts ... get the model from the URL
            candidate = (view_kwargs or {}).get('model')
            model = candidate if hasattr(candidate, '_meta') else None
        package = (cls.__module__ if cls is not None else getattr(view_func, '__module__', '') or '').split('.')[0]
        if model is None and package not in getattr(django_settings, 'PLUGINS', ()):
            if areas.default_deny_active() and request.path_info.startswith(SYSTEM_PATHS) and not (
                    areas.own_tokens_allowed() and request.path_info.startswith('/user/api-tokens')):
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
            if _select_exception(request, user, api, target, view_kwargs):
                return None
            return denied_response(request, None, right=right, target=ask, tab_label=tab[1] if tab else None)
        if areas.can(user, area, right, rights_target) and (
                right != 'import' or request.method != 'POST' or areas.can(user, area, 'add', rights_target)):
            if tab and not tab[2] and not areas.tab_allowed(user, area, target, tab[0]):
                _throttled_log(user, area, right, request)
                return denied_response(request, area, right, ask, tab_label=tab[1])
            if (response := _child_denied(request, user, cls, tab)) is not None:
                return response
            # whoever holds access unlocks the PIN to enter (not before the owners exist, and the REST API has no
            # unlock step)
            if not api and areas.owners(area) and not guests.is_guest(user):  # (a PIN-only person signed in with it)
                from .mixins import pin_gate
                if service.is_allowed(user) and not service.has_pin(user):
                    from django.contrib import messages
                    with translation.override(service.get_settings().language or 'en'):
                        messages.info(request, _('You have access to "%(area)s". To enter you need a PIN: set it '
                                                 'here and you will continue.') % {'area': area.name})
                if (response := pin_gate(request, scope=f'area-{area.key}')) is not None:
                    return response
            return None
        if _select_exception(request, user, api, target, view_kwargs):
            return None
        _throttled_log(user, area, right, request)
        return denied_response(request, area, right, ask, tab_label=tab[1] if tab else None)


def _graphql_would_leak(request):
    """GraphQL draws every field of what it returns: not for a person at a screen while any field is hidden."""
    user = request.user
    if not getattr(user, 'is_authenticated', False) or areas.is_keeper(user) or areas.is_exempt(user):
        return False
    from .models import AreaFieldMode, AreaFieldRule
    return AreaFieldRule.objects.filter(mode=AreaFieldMode.HIDDEN).exists()


def _select_exception(request, user, api, target, view_kwargs):
    """
    The drop-down of a relation field the user may write asks the API for the objects to pick from (``brief``): that
    one request is served, narrowed by the text of the field rule - the pages of the type stay closed.
    """
    if not (api and request.method == 'GET' and target):
        return False
    from . import fieldrules
    pk = (view_kwargs or {}).get('pk')
    if target == 'extras.customfieldchoiceset':  # the values of a select custom field he may write
        if pk is None or not request.path_info.rstrip('/').endswith('/choices') or int(pk) not in \
                fieldrules.choice_set_ids(user):
            return False
        request._userpin_select = (target, ('pk', [int(pk)]))
        return True
    if pk is not None or not request.GET.get('brief') or request.GET.get('fields') or request.GET.get('include'):
        return False
    scope = fieldrules.select_scope(user)
    if target not in scope:
        return False
    request._userpin_select = (target, scope[target])
    return True


def _form_pick(user, meta):
    """
    While a form is built or validated, the objects the user may pick in its relation fields are served (narrowed by the
    text of the rule): otherwise a chosen group or device type would be "not one of the available choices".
    """
    from . import fieldrules
    try:
        from netbox.context import current_request
        request = current_request.get()
    except Exception:  # noqa: BLE001
        request = None
    # NetBox narrows the querysets of the form fields (restrict_form_fields) after the form is built and before it is
    # validated, so the edit views themselves are the window as well
    if not (fieldrules.in_form() or getattr(request, '_userpin_edit', False)):
        return None
    cache = request.__dict__.setdefault('_userpin_scope', {}) if request is not None else {}
    if user.pk not in cache:
        cache[user.pk] = fieldrules.select_scope(user)
    label = f'{meta.app_label}.{meta.model_name}'
    if label not in cache[user.pk]:
        return None
    return (label, cache[user.pk][label])


def _select_perm(perm):
    app_label, _dot, codename = perm.partition('.')
    try:
        from netbox.context import current_request
        flag = getattr(current_request.get(), '_userpin_select', None)
    except Exception:  # noqa: BLE001
        return False
    if not flag:
        return False
    model_name = flag[0].partition('.')[2]
    return flag[0].partition('.')[0] == app_label and codename == f'view_{model_name}'


def _select_flag(meta):
    try:
        from netbox.context import current_request
        flag = getattr(current_request.get(), '_userpin_select', None)
    except Exception:  # noqa: BLE001
        return None
    return flag if flag and flag[0] == f'{meta.app_label}.{meta.model_name}' else None


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


#
# B: what is not allowed is not shown. "Not allowed" is the default, so what a later NetBox or a new plugin adds stays
# hidden until it is allowed: nothing here lists plugins or pages by name.
#

def _hides_menu_for(user):
    """B is on and the user is no keeper: the menus and the account pages show only what is allowed."""
    if guests.is_guest(user):
        return True  # whatever the settings say: a person with a PIN only sees what the groups allow
    return bool(getattr(user, 'is_authenticated', False) and areas.protection_on() and areas.default_deny_active()
                and areas.hides_denied() and not areas.is_keeper(user) and not areas.is_exempt(user))


def _menu_item_allowed(item):
    """
    An item of the navigation menu in B. One with a permission stays (the permission is judged afterwards: for
    protected types by the PIN); one without any permission, or only for superusers, is shown only when it belongs to
    this plugin (its own pages decide by the roles).
    """
    if getattr(item, 'staff_only', False):
        return False
    if getattr(item, 'permissions', None):
        return True
    return str(getattr(item, 'link', '') or '').startswith('plugins:netbox_user_pin:')


def _filtered_menus(menus):
    from netbox.navigation import Menu, MenuGroup
    result = []
    for menu in menus:
        groups = []
        for group in menu.groups:
            items = [item for item in group.items if _menu_item_allowed(item)]
            if items:
                groups.append(MenuGroup(label=group.label, items=items))
        if groups:
            result.append(Menu(label=menu.label, icon_class=menu.icon_class, groups=groups))
    return result


ACCOUNT_OPEN = ('/user/password',)  # what the account pages keep in B (and the API keys, when they are allowed)


def _account_href_allowed(href):
    if href.startswith('/plugins/user-pin/guest/'):
        return True
    return href.startswith(ACCOUNT_OPEN) or href.startswith('/plugins/user-pin/') or (
        areas.own_tokens_allowed() and href.startswith('/user/api-tokens'))


_USER_MENU = re.compile(
    r'(<div class="dropdown-menu dropdown-menu-end dropdown-menu-arrow">)((?:(?!</div>).)*?href="[^"]*/logout/[^"]*".*?)'
    r'(</div>)', re.S)
_ANCHOR = re.compile(r'<a\b[^>]*href="([^"]*)"[^>]*>.*?</a>', re.S)
_ACCOUNT_TAB = re.compile(r'<li class="nav-item">\s*<a class="nav-link[^"]*" href="(/user/[^"]*)">.*?</a>\s*</li>', re.S)
_BELL = re.compile(r'<div class="dropdown">\s*<button class="nav-link fs-2 p-0".*?'
                   r'<div class="dropdown-menu[^"]*notifications"></div>\s*</div>', re.S)
_SEARCH = re.compile(r'<form action="[^"]*/search/"[^>]*>.*?</form>', re.S)


def _shape_html(request, text):
    """The user menu, the tabs of the account pages (and the bell and the search of one who has no role) in B."""
    from django.urls import reverse
    from django.utils.translation import gettext
    user = request.user

    def user_menu(match):
        anchors = list(_ANCHOR.finditer(match.group(2)))
        kept = [a.group(0) for a in anchors if _account_href_allowed(a.group(1))]
        logout = next((a.group(0) for a in anchors if '/logout/' in a.group(1)), '')
        kept = [a for a in kept if '/logout/' not in a]
        with translation.override(service.get_settings().language or 'en'):
            if guests.is_guest(user):
                extra = [(reverse('plugins:netbox_user_pin:guest_home'), 'mdi-home', gettext('My access')),
                         (reverse('plugins:netbox_user_pin:guest_change'), 'mdi-dialpad', gettext('Change my PIN'))]
                logout = f'<a href="{reverse("plugins:netbox_user_pin:guest_logout")}" class="dropdown-item">' \
                         f'<i class="dropdown-item-icon mdi mdi-logout" aria-hidden="true"></i> {gettext("Sign out")}</a>'
                made = [f'<a href="{href}" class="dropdown-item"><i class="dropdown-item-icon mdi {icon}" '
                        f'aria-hidden="true"></i> {label}</a>' for href, icon, label in extra]
                return match.group(1) + ''.join(made) + '<hr class="dropdown-divider" />' + logout + match.group(3)
            extra = [('/user/password/', 'mdi-lock-reset', gettext('Change the password')),
                     (reverse('plugins:netbox_user_pin:my_pin'), 'mdi-dialpad', gettext('My PIN'))]
            if areas.own_tokens_allowed():
                extra.append(('/user/api-tokens/', 'mdi-key', gettext('My API keys')))
        shown = {a.group(1) for a in anchors if _account_href_allowed(a.group(1))}
        made = [f'<a href="{href}" class="dropdown-item"><i class="dropdown-item-icon mdi {icon}" aria-hidden="true">'
                f'</i> {label}</a>' for href, icon, label in extra if href not in shown]
        return (match.group(1) + ''.join(made + kept) + '<hr class="dropdown-divider" />' + logout + match.group(3))

    text = _USER_MENU.sub(user_menu, text)  # the layout has the menu twice (small and large screens)
    # the footer links (docs, REST API, API docs, GraphQL, GitHub, Slack) are not for them
    text = text.replace('</head>', '<style>footer.footer{display:none!important}</style></head>', 1)
    guest = guests.guest_of(user)
    if guest is not None:  # a PIN-only person always sees until when the PIN and the account are valid
        badges = _guest_badges(guest)
        text = text.replace('<div class="navbar-nav flex-row align-items-center order-md-last">',
                            '<div class="navbar-nav flex-row align-items-center order-md-last">' + badges)
        text = text.replace('<div class="navbar-nav flex-row align-items-center d-lg-none">',
                            '<div class="navbar-nav flex-row align-items-center d-lg-none">' + badges)
    text = _ACCOUNT_TAB.sub(lambda m: m.group(0) if _account_href_allowed(m.group(1)) else '', text)
    if not (roles.is_manager(user) or areas.administers_any(user)):  # no role: nothing to be told, nothing to search
        text = _BELL.sub('', text)
        text = _SEARCH.sub('', text)
    return text


def _guest_badges(guest):
    """'PIN: 54 d 14 h' and 'Account until …' for the top bar of a PIN-only person (in the language of the page)."""
    from django.urls import reverse
    from django.utils import timezone
    from django.utils.html import escape
    settings = service.get_settings()
    now = timezone.now()
    parts = []
    until = guests.pin_valid_until(guest)
    if guests.must_change(guest):
        parts.append(('red', 'mdi-dialpad', _('PIN: change it'), _('Your PIN must be changed now.')))
    elif until:
        left = until - now
        color = 'yellow' if left.days <= settings.warn_days else 'green'
        parts.append((color, 'mdi-dialpad', _('PIN: %(d)d d %(h)d h') % {'d': left.days, 'h': left.seconds // 3600},
                      _('Your PIN expires on %(time)s – change it under My access > Change my PIN.') % {
                          'time': timezone.localtime(until).strftime('%d.%m.%Y %H:%M')}))
    if guest.expires:
        color = 'yellow' if guest.expires - now <= timezone.timedelta(days=7) else 'secondary'
        when = timezone.localtime(guest.expires).strftime('%d.%m.%Y %H:%M')
        parts.append((color, 'mdi-timer-sand', _('Account until %(time)s') % {'time': when},
                      _('Your account is switched off on %(time)s.') % {'time': when}))
    link = reverse('plugins:netbox_user_pin:guest_home')
    return ''.join(f'<a href="{link}" class="badge text-bg-{c} me-2 text-decoration-none" title="{escape(t)}">'
                   f'<i class="mdi {i}"></i> {escape(label)}</a>' for c, i, label, t in parts)


# What somebody who is not signed in may reach: the sign-in pages (classic and PIN-only) and the files they need.
OPEN_ANONYMOUS = ('/login', '/logout', '/static/', '/media-failure/', '/oauth/', '/social-auth/',
                  '/plugins/user-pin/pin/', '/plugins/user-pin/guest/')


# Documentation of NetBox and of its API: closed for those who see only what is allowed (B) and PIN-only people.
HIDDEN_DOCS = ('/api/schema', '/api/docs', '/api/redoc', '/static/docs', '/graphql')


# What a user who is in no group still has (B): the pages of this plugin (PIN, 2FA, unlock), the password, the login,
# the files of the pages - and the own API keys, when the settings allow them.
OPEN_TO_THE_UNLISTED = ('/plugins/user-pin/', '/login/', '/logout/', '/user/password', '/static/', '/media/',
                        '/oauth/', '/social-auth/', '/htmx/')


def _open_to_the_unlisted(request):
    path = request.path_info
    if path.startswith(OPEN_TO_THE_UNLISTED):
        return True
    return areas.own_tokens_allowed() and path.startswith('/user/api-tokens')


def _tab_hidden(tab, instance):
    """Is this tab of the page of ``instance`` hidden from the current user (an area that hides what is not allowed)?"""
    try:
        from netbox.context import current_request
        request = current_request.get()
    except Exception:  # noqa: BLE001
        return False
    user = getattr(request, 'user', None)
    meta = getattr(instance, '_meta', None)
    if meta is None or not getattr(user, 'is_authenticated', False) or not areas.active_areas() \
            or areas.is_exempt(user):
        return False
    area = areas.area_for(meta.app_label, meta.model_name, package=meta.app_label)
    if area is None or not areas.hides_denied(area):
        return False
    target = f'{meta.app_label}.{meta.model_name}'
    for config, view in areas._tab_configs(meta.app_label, meta.model_name):
        if getattr(view, 'tab', None) is not tab or not config['name']:
            continue
        if view.__module__.split('.')[0] in getattr(django_settings, 'PLUGINS', ()):
            plugin_area = areas.area_for(None, None, package=view.__module__.split('.')[0])
            return plugin_area is not None and not areas.can(user, plugin_area, 'view', None)
        return not areas.tab_allowed(user, area, target, config['name'])
    return False


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


def _may_use(user, model, right):
    """May the user use ``right`` (import / export) on this object type? Outside of the protection NetBox decides."""
    meta = getattr(model, '_meta', None) or getattr(type(model), '_meta', None)
    if meta is None or not getattr(user, 'is_authenticated', False) or _token_request() or areas.is_exempt(user):
        return True
    area = areas.area_for(meta.app_label, meta.model_name, package=meta.app_label)
    if area is None:
        return not areas.default_deny_blocks(user, meta.app_label, meta.model_name, meta.app_label)
    return areas.can(user, area, right, f'{meta.app_label}.{meta.model_name}')


def _import_buttons_need_the_right(menus):
    """The "Import" buttons of the menu ask for the right to import (not only for adding): once per button."""
    for menu in menus:
        for group in menu.groups:
            for item in group.items:
                for button in getattr(item, 'buttons', None) or ():
                    perms = list(button.permissions or ())
                    if str(button.link).endswith('_bulk_import') and len(perms) == 1 and '.add_' in perms[0]:
                        app_label, _dot, codename = perms[0].partition('.add_')
                        button.permissions = [perms[0], f'userpin.import:{app_label}.{codename}']


def _hide_buttons():
    """The Import and Export buttons of the lists appear only for who has these rights."""
    try:
        from netbox.object_actions import BulkExport, BulkImport
    except ImportError:
        return
    for action, right in ((BulkImport, 'import'), (BulkExport, 'export')):
        if getattr(action.render.__func__, '_userpin', False):
            continue

        def make(original, right):
            def render(cls, context, obj, **kwargs):
                request = context.get('request') if hasattr(context, 'get') else None
                if request is not None and not _may_use(request.user, obj, right):
                    return ''
                return original(context, obj, **kwargs)
            render._userpin = True
            return render

        action.render = classmethod(make(action.render, right))


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

    _hide_buttons()
    if not getattr(RestrictedQuerySet.restrict, '_userpin', False):
        original = RestrictedQuerySet.restrict

        def restrict(self, user, action='view'):
            if _token_request() or areas.is_exempt(user):
                return original(self, user, action)
            meta = self.model._meta
            if (flag := _select_flag(meta) or _form_pick(user, meta)) is not None:  # a drop-down / a form field
                if flag[1] and flag[1][0] == 'pk':
                    return self.filter(pk__in=flag[1][1])
                if not flag[1]:
                    return self
                field = areas._name_field(self.model)
                if field is None:
                    return self.none()
                from . import fieldrules
                return self.filter(fieldrules.name_query(field, flag[1]))
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
                own = areas.own_rows_only(user, meta.app_label, meta.model_name)
                if own and getattr(user, 'is_authenticated', False):
                    result = result.filter(**{own: user})
                return result
            if action not in areas.rights_available(area):  # sync, render_config, run ... need the right to change
                action = 'change'
            query = areas.row_filter(user, area, meta.app_label, meta.model_name, action)
            if query is None:
                return self.none()
            return self.filter(query) if query else self

        restrict._userpin = True
        RestrictedQuerySet.restrict = restrict

    from utilities.templatetags import navigation as navigation_tags
    if not getattr(navigation_tags.get_menus, '_userpin', False):
        original_menus = navigation_tags.get_menus

        def get_menus():
            menus = original_menus()
            _import_buttons_need_the_right(menus)
            try:
                from netbox.context import current_request
                user = getattr(current_request.get(), 'user', None)
            except Exception:  # noqa: BLE001
                user = None
            return _filtered_menus(menus) if _hides_menu_for(user) else menus

        get_menus._userpin = True
        navigation_tags.get_menus = get_menus

    from utilities.views import ViewTab
    if not getattr(ViewTab.render, '_userpin', False):
        original_render = ViewTab.render

        def render(self, instance):
            result = original_render(self, instance)
            return None if result is not None and _tab_hidden(self, instance) else result

        render._userpin = True
        ViewTab.render = render

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
