"""
Protected areas: part of NetBox (or of a plugin) whose objects are shown only to people holding a PIN grant given
by the area's owners – whatever their NetBox role is, superusers included.

An area is *active* (protects) when

* it is a custom area (defined on the Protected areas page) and the setting "Protect areas and objects" is on, or
* it was registered by a plugin with :func:`register` and the plugin's own PIN integration switch is on (the
  plugin passes it as ``enabled``). This works even when the global setting is off.

Rights: ``view``, ``add``, ``change``, ``delete`` for NetBox objects, plus any rights a plugin defines
(e.g. ``config``). Owners hold every right. Without owners (before they are appointed) only the master
(a superuser) has access, so that an area can never lock everybody out.

Use from a plugin::

    from netbox_user_pin import areas
    areas.register('netbox_libreoxi', 'LibreOXI', targets=['netbox_libreoxi'],
                   rights={'config': 'View configurations'},
                   profiles=[('Logs only', ['view']), ('Configurations', ['view', 'config'])],
                   enabled=lambda: my_settings().pin_integration)
    ...
    if not areas.can(request.user, 'netbox_libreoxi', 'config'):
        return areas.denied_response(request, 'netbox_libreoxi')
"""
import logging
import time
import uuid
from datetime import timedelta

from django.apps import apps
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import DatabaseError, transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import gettext as _

from . import roles, service
from .models import (
    AreaFieldMode, AreaFieldRule, AreaGrant, AreaOwner, AreaProfile, AreaRequest, AreaRequestStatus, PinEventAction, PolicyKeeper, ProtectedArea,
)

logger = logging.getLogger('netbox_user_pin')

API_VERSION = 1  # for plugins: register / can / require / get_area / is_owner / denied_response
GENERIC_RIGHTS = ('view', 'add', 'change', 'delete')
DEFAULT_PROFILES = (
    ('Read', ('view',)),
    ('Edit', ('view', 'add', 'change')),
    ('Full', GENERIC_RIGHTS),
)
# Never protectable: the plugin itself (it holds the means to get access).
NEVER = frozenset({'netbox_user_pin'})
CACHE_SECONDS = 5
EVENT_TYPE = 'netbox_user_pin_area_request'

_registry = {}
_cache = {'at': 0.0, 'areas': None, 'deny': False, 'keepers': frozenset()}
# Never refused by the default deny: what every logged-in user needs to work with their own account in NetBox.
DEFAULT_DENY_EXEMPT = frozenset({
    'extras.bookmark', 'extras.notification', 'extras.notificationgroup', 'extras.subscription', 'extras.dashboard',
    'users.userconfig', 'users.token',
})


#
# Registry (plugins)
#

def register(key, name, targets=None, rights=None, profiles=None, enabled=None, description=''):
    """
    Announce an area of a plugin. ``enabled`` is a callable returning True while the plugin's PIN integration
    is switched on. ``rights`` maps plugin specific rights to a label, ``profiles`` is a list of
    ``(name, [rights])`` (default: Read / Edit / Full).
    """
    _registry[key] = {
        'name': name, 'targets': list(targets or [key]), 'rights': dict(rights or {}),
        'profiles': [(profile, list(items)) for profile, items in (profiles or [])],
        'enabled': enabled or (lambda: False), 'description': description,
    }
    clear_cache()


def registered():
    return dict(_registry)


def clear_cache():
    _cache['at'] = 0.0
    _cache['areas'] = None


def sync_plugin_areas():
    """Create the database rows (and profiles) of the registered plugin areas."""
    for key, info in _registry.items():
        area, created = ProtectedArea.objects.get_or_create(
            key=key, defaults={'name': info['name'], 'description': info['description'], 'plugin': True,
                               'targets': info['targets']})
        profiles = info['profiles'] or [(name, list(rights)) for name, rights in DEFAULT_PROFILES]
        for name, rights in profiles:
            AreaProfile.objects.get_or_create(area=area, name=name, defaults={'rights': list(rights)})
        if not created and (area.targets != info['targets'] or not area.plugin):
            ProtectedArea.objects.filter(pk=area.pk).update(targets=info['targets'], plugin=True)


def _load_active():
    settings = service.get_settings()
    try:
        sync_plugin_areas()
        rows = list(ProtectedArea.objects.all())
    except DatabaseError:  # before the migrations
        return []
    active = []
    for area in rows:
        if area.plugin:
            info = _registry.get(area.key)
            try:
                on = bool(info and info['enabled']())
            except Exception:  # a broken plugin switch must not take NetBox down
                logger.exception('PIN integration switch of %s failed', area.key)
                on = False
            if on:
                active.append(area)
        elif settings.areas_enabled and area.enabled:
            active.append(area)
    return active


def _refresh():
    _cache['areas'] = _load_active()
    try:
        keepers = frozenset(PolicyKeeper.objects.filter(user__is_active=True).values_list('user_id', flat=True))
        _cache['deny'] = bool(service.get_settings().default_deny and keepers)
        _cache['keepers'] = keepers
    except DatabaseError:
        _cache['deny'], _cache['keepers'] = False, frozenset()
    _cache['at'] = time.monotonic()


def active_areas():
    if _cache['areas'] is None or time.monotonic() - _cache['at'] > CACHE_SECONDS:
        _refresh()
    return _cache['areas']


def default_deny_active():
    active_areas()
    return _cache['deny']


def protection_on():
    """Does anything protect (an active area or the default deny)?"""
    return bool(active_areas()) or _cache['deny']


def is_keeper(user):
    active_areas()
    return bool(getattr(user, 'is_authenticated', False) and user.pk in _cache['keepers'])


def default_deny_blocks(user, app_label, model, package=None):
    """Is this object type refused by "deny everything not allowed" (it is in no active area)?"""
    if not default_deny_active() or app_label in NEVER or package in NEVER:
        return False
    if f'{app_label}.{model}' in DEFAULT_DENY_EXEMPT:
        return False
    return not is_keeper(user)


def targets_of(area):
    info = _registry.get(area.key) if area.plugin else None
    return list(info['targets']) if info else list(area.targets or [])


def rights_available(area):
    """Every right the area knows: the generic ones and the plugin's own."""
    info = _registry.get(area.key) if area.plugin else None
    return list(GENERIC_RIGHTS) + (list(info['rights']) if info else [])


def right_label(area, right):
    info = _registry.get(area.key) if area.plugin else None
    if info and right in info['rights']:
        return info['rights'][right]
    return {'view': _('View'), 'add': _('Add'), 'change': _('Change'), 'delete': _('Delete')}.get(right, right)


def get_area(key_or_area):
    if isinstance(key_or_area, ProtectedArea):
        return key_or_area
    return ProtectedArea.objects.filter(key=key_or_area).first()


def area_for(app_label=None, model=None, package=None):
    """The active area protecting this app / object type / plugin package, or None."""
    if app_label in NEVER or package in NEVER:
        return None
    for area in active_areas():
        for target in targets_of(area):
            if '.' in target:
                target_app, target_model = target.split('.', 1)
                if app_label == target_app and model == target_model:
                    return area
            elif target in (app_label, package):
                return area
    return None


#
# Rights
#

def owners(area):
    return [owner.user for owner in area.owners.select_related('user') if owner.user.is_active]


def is_owner(user, area):
    return bool(getattr(user, 'is_authenticated', False) and user.is_active
                and AreaOwner.objects.filter(area=area, user=user).exists())


def active_grants(user, area, target=None):
    """Live grants of the user; with ``target`` ('dcim.device') only those valid for that object type."""
    now = timezone.now()
    return [g for g in AreaGrant.objects.filter(area=area, user=user, revoked__isnull=True).select_related('profile')
            if (g.expires is None or g.expires > now) and (not target or not g.target or g.target == target)]


def rights_of(user, area, target=None):
    """Rights the user holds in the area now (owners: all of them)."""
    if not getattr(user, 'is_authenticated', False) or not user.is_active:
        return set()
    if is_owner(user, area):
        return set(rights_available(area))
    if not AreaOwner.objects.filter(area=area).exists() and user.is_superuser:
        return set(rights_available(area))  # bootstrap: no owners yet, the master keeps access
    rights = set()
    for grant in active_grants(user, area, target):
        rights.update(grant.profile.rights)
    return rights


def can(user, area, right='view', target=None):
    """May the user use ``right`` in the area? Areas that do not protect (inactive / unknown key) allow."""
    area = get_area(area)
    if area is None or area not in active_areas():
        return True
    return right in _memo_rights(user, area, target)


def _memo_rights(user, area, target=None):
    memo = user.__dict__.setdefault('_userpin_rights', {}) if hasattr(user, '__dict__') else {}
    stamp = int(time.monotonic() // CACHE_SECONDS)
    key = (area.pk, target or '')
    entry = memo.get(key)
    if entry is None or entry[0] != stamp:
        entry = (stamp, rights_of(user, area, target))
        memo[key] = entry
    return entry[1]


def _unrestricted(user, area):
    """Owners (and, before owners exist, superusers) see every row."""
    if is_owner(user, area):
        return True
    return user.is_superuser and not AreaOwner.objects.filter(area=area).exists()


def row_filter(user, area, app_label, model, action='view'):
    """
    ``None``: no access. ``Q()``: every row. Otherwise a ``Q`` with the rows the user's profiles show.
    NetBox permissions and their constraints are not consulted inside a protected area.
    """
    target = f'{app_label}.{model}'
    if not getattr(user, 'is_authenticated', False) or action not in _memo_rights(user, area, target):
        return None
    if _unrestricted(user, area):
        return Q()
    combined = None
    for grant in active_grants(user, area, target):
        if action not in grant.profile.rights:
            continue
        lookups = (grant.profile.filters or {}).get(f'{app_label}.{model}')
        if not lookups:
            return Q()  # one profile without a filter for this type shows everything of it
        combined = Q(**lookups) if combined is None else combined | Q(**lookups)
    return combined


def parse_filters(text, area):
    """
    Lines ``app.model: lookup=value`` (several lookups: separate them with ``&``) -> {"app.model": {lookup: value}}.
    Example: ``dcim.device: name__istartswith=PRINTER``. The lookups are checked against the model.
    """
    from django.core.exceptions import FieldError
    result = {}
    allowed = set(targets_of(area))
    for raw in (text or '').splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        target, sep, rest = line.partition(':')
        target = target.strip().lower()
        if not sep or '.' not in target:
            raise ValidationError(_('Use "app.model: lookup=value", e.g. dcim.device: name__istartswith=PRINTER.'))
        app_label, model_name = target.split('.', 1)
        if target not in allowed and app_label not in allowed:
            raise ValidationError(_('"%(target)s" is not protected by this area.') % {'target': target})
        lookups = {}
        for part in rest.split('&'):
            key, equals, value = part.strip().partition('=')
            if not equals or not key.strip():
                raise ValidationError(_('Use lookup=value, e.g. name__istartswith=PRINTER.'))
            lookups[key.strip()] = value.strip()
        try:
            apps.get_model(app_label, model_name)._default_manager.filter(**lookups).query  # noqa: B018
        except (LookupError, FieldError, ValueError, TypeError) as exc:
            raise ValidationError(_('The filter for "%(target)s" is not valid: %(error)s') % {
                'target': target, 'error': exc})
        result[target] = lookups
    return result


def format_filters(filters):
    return '\n'.join(f'{target}: ' + ' & '.join(f'{k}={v}' for k, v in lookups.items())
                     for target, lookups in (filters or {}).items())


def _ensure_pin_allowed(user, actor, request=None):
    """Owners and grantees unlock a PIN to enter: allow them to use one (unless an administrator denied it)."""
    from .models import PinAccess
    if service.is_allowed(user):
        return
    user_pin = getattr(user, 'user_pin', None)
    if user_pin is not None and user_pin.access == PinAccess.DENIED:
        raise ValidationError(_('%(user)s is not permitted to use a PIN (denied by an administrator).') % {
            'user': user.username})
    service.set_access(user, PinAccess.ALLOWED, actor, request=request)


def check_perm(user, perm):
    """
    For ``User.has_perm``: ``None`` when no area covers the permission, otherwise ``(allowed, area)``.

    In a protected area the PIN grants decide alone; the NetBox permissions of the user are not asked. A user who
    holds no key at all still sees the door (menu item, tab): ``True`` here, and the guard refuses the entry.
    """
    app_label, _dot, codename = perm.partition('.')
    if not codename or not active_areas():
        return None
    action, _underscore, model = codename.partition('_')
    area = area_for(app_label, model or None, package=app_label)
    if area is None:
        return None
    rights = _memo_rights(user, area, f'{app_label}.{model}' if model else None)
    if not rights:
        return True, area
    # a permission named after a right of the area (e.g. app.config_model) asks for exactly that right
    return (action if action in rights_available(area) else 'change') in rights, area


def right_for_request(request, view_class=None, view_kwargs=None):
    """The right a request needs: reading needs ``view``; changes depend on the kind of view."""
    method = request.method
    if method in ('GET', 'HEAD', 'OPTIONS'):
        return 'view'
    name = getattr(view_class, '__name__', '') if view_class is not None else ''
    if method == 'DELETE' or 'Delete' in name:
        return 'delete'
    if 'Import' in name:
        return 'add'
    if method == 'POST' and view_class is not None and ('Edit' in name or 'Create' in name):
        return 'change' if (view_kwargs or {}).get('pk') else 'add'
    if method == 'POST' and view_class is not None and hasattr(view_class, 'serializer_class'):
        return 'add'  # REST API: POST creates
    return 'change'


#
# Administration
#

def _core_or_owner(actor, area):
    """Who may change an area: its owners; as long as there are none, CORE / the master."""
    if AreaOwner.objects.filter(area=area).exists():
        return is_owner(actor, area)
    return roles.is_core(actor)


def can_manage(actor, area):
    return _core_or_owner(actor, area)


def can_see(actor, area):
    return roles.is_core(actor) or is_owner(actor, area)


def _log(action, area, actor, user=None, request=None, detail=''):
    service.log_event(action, user=user, actor=actor, request=request, scope=area.key, detail=detail)


def parse_targets(text):
    """Validate lines of ``app`` or ``app.model``; returns the list or raises ValidationError."""
    result = []
    for raw in (text or '').replace(',', '\n').splitlines():
        target = raw.strip().lower()
        if not target or target in result:
            continue
        app_label, _dot, model = target.partition('.')
        if app_label in NEVER:
            raise ValidationError(_('"%(target)s" cannot be protected.') % {'target': target})
        try:
            apps.get_app_config(app_label)
            if model:
                apps.get_model(app_label, model)
        except LookupError:
            raise ValidationError(_('"%(target)s" is not an installed app or object type (use app or app.model, '
                                    'e.g. dcim or users.user).') % {'target': target})
        result.append(target)
    if not result:
        raise ValidationError(_('Enter at least one app or object type.'))
    return result


@transaction.atomic
def create_area(name, targets, owners_, actor, description='', max_hours=24, request=None):
    if not roles.is_core(actor):
        raise PermissionDenied
    key = _unique_key(name)
    area = ProtectedArea.objects.create(key=key, name=name, description=description, targets=targets,
                                        max_hours=max_hours)
    for name_, rights in DEFAULT_PROFILES:
        AreaProfile.objects.create(area=area, name=name_, rights=list(rights))
    _log(PinEventAction.AREA_CREATED, area, actor, request=request, detail=f'targets: {", ".join(targets)}')
    for user in owners_:
        _ensure_pin_allowed(user, actor, request)
        _add_owner(area, user, actor, request)
    clear_cache()
    return area


def _unique_key(name):
    from django.utils.text import slugify
    base = slugify(name)[:90] or 'area'
    key, n = base, 2
    while ProtectedArea.objects.filter(key=key).exists():
        key, n = f'{base}-{n}', n + 1
    return key


def _add_owner(area, user, actor, request):
    owner, created = AreaOwner.objects.get_or_create(area=area, user=user)
    if created:
        _log(PinEventAction.AREA_OWNER_ADDED, area, actor, user=user, request=request)
        service.send_user_mail(user, _('You are an owner of the area "%(area)s"') % {'area': area.name}, _(
            'You were appointed an owner of the protected area "%(area)s". You decide who gets access to it: '
            'requests arrive here (bell and e-mail) and are confirmed with your PIN and 2FA.') % {'area': area.name},
            request=request)
    return owner


def add_owner(area, user, actor, request=None):
    if not _core_or_owner(actor, area):
        raise PermissionDenied
    if not user.is_active:
        raise ValidationError(_('The account is not active.'))
    _ensure_pin_allowed(user, actor, request)
    owner = _add_owner(area, user, actor, request)
    clear_cache()
    return owner


def remove_owner(area, user, actor, request=None):
    """Only an owner removes an owner (never the master alone), and never the last one."""
    if not is_owner(actor, area):
        raise PermissionDenied
    owner = AreaOwner.objects.filter(area=area, user=user).first()
    if owner is None:
        return
    if area.owners.count() <= 1:
        raise ValidationError(_('The last owner cannot be removed. Appoint another owner first.'))
    owner.delete()
    _log(PinEventAction.AREA_OWNER_REMOVED, area, actor, user=user, request=request)
    clear_cache()


def update_area(area, actor, name=None, description=None, targets=None, enabled=None, max_hours=None, request=None):
    if not _core_or_owner(actor, area):
        raise PermissionDenied
    changes = []
    for field, value in (('name', name), ('description', description), ('targets', targets), ('enabled', enabled),
                         ('max_hours', max_hours)):
        if value is None or area.plugin and field in ('targets', 'enabled'):
            continue
        if getattr(area, field) != value:
            changes.append(f'{field}: {getattr(area, field)!r} -> {value!r}')
            setattr(area, field, value)
    if changes:
        area.save()
        _log(PinEventAction.AREA_CHANGED, area, actor, request=request, detail='\n'.join(changes))
        clear_cache()
    return bool(changes)


def delete_area(area, actor, request=None):
    if area.plugin:
        raise ValidationError(_('The area of a plugin cannot be deleted; switch the plugin integration off.'))
    if not _core_or_owner(actor, area):
        raise PermissionDenied
    _log(PinEventAction.AREA_DELETED, area, actor, request=request, detail=area.name)
    area.delete()
    clear_cache()


def save_profile(area, name, rights, actor, profile=None, request=None, filters=None):
    if not _core_or_owner(actor, area):
        raise PermissionDenied
    known = set(rights_available(area))
    rights = [r for r in rights if r in known]
    if not rights:
        raise ValidationError(_('Choose at least one right.'))
    if profile is None:
        if AreaProfile.objects.filter(area=area, name=name).exists():
            raise ValidationError(_('A profile with this name exists.'))
        profile = AreaProfile.objects.create(area=area, name=name, rights=rights, filters=filters or {})
    else:
        profile.name, profile.rights, profile.filters = name, rights, filters or {}
        profile.save()
    _log(PinEventAction.AREA_CHANGED, area, actor, request=request,
         detail=f'profile {name}: {", ".join(rights)}' + (f' | rows: {format_filters(filters)}' if filters else ''))
    return profile


def delete_profile(profile, actor, request=None):
    area = profile.area
    if not _core_or_owner(actor, area):
        raise PermissionDenied
    if AreaGrant.objects.filter(profile=profile, revoked__isnull=True).exists():
        raise ValidationError(_('The profile is in use. Revoke those grants first.'))
    _log(PinEventAction.AREA_CHANGED, area, actor, request=request, detail=f'profile {profile.name} deleted')
    profile.delete()


def _notify(req, users, text, subject):
    """NetBox notification (bell) + e-mail."""
    from core.models import ObjectType
    from extras.models import Notification
    for user in users:
        try:
            Notification.objects.update_or_create(
                user=user, object_type=ObjectType.objects.get_for_model(AreaRequest), object_id=req.pk,
                defaults={'event_type': EVENT_TYPE, 'read': None, 'object_repr': str(req)[:200]},
            )
        except Exception as exc:  # a convenience only
            logger.warning('Cannot create NetBox notification for %s: %s', user, exc)
        service.send_user_mail(user, subject, text)


def request_access(area, user, note='', request=None, scope=''):
    """A user asks the owners for access. One waiting request per user and area."""
    area = get_area(area)
    if area is None or not user.is_authenticated or not user.is_active:
        raise PermissionDenied
    existing = AreaRequest.objects.filter(area=area, user=user, status=AreaRequestStatus.PENDING).first()
    if existing:
        return existing
    if len((note or '').strip()) < 5:
        raise ValidationError(_('Write why you need the access (at least a few words).'))
    recipients = owners(area)
    if not recipients:
        raise ValidationError(_('The area has no owners yet. Ask the administrator to appoint them.'))
    req = AreaRequest.objects.create(area=area, user=user, note=note.strip()[:200], scope=(scope or '').strip()[:200])
    _log(PinEventAction.AREA_REQUESTED, area, user, user=user, request=request,
         detail=f'{req.note}' + (f' | {req.scope}' if req.scope else ''))
    label = service.user_label(user)
    _notify(req, recipients, _(
        '%(user)s asks for access to the area "%(area)s".\n\nWhy: %(reason)s\nWhat exactly: %(scope)s\n\n'
        'Open User PIN > Protected areas to grant or deny it (confirm with your PIN and 2FA).') % {
        'user': label, 'area': area.name, 'reason': req.note, 'scope': req.scope or '-'},
        _('Access request: %(area)s') % {'area': area.name})
    return req


def decide_request(req, actor, approve, profile=None, hours=None, request=None, rights=None, target=''):
    area = req.area
    if req.status != AreaRequestStatus.PENDING:
        raise ValidationError(_('The request has been dealt with already.'))
    if not is_owner(actor, area):
        raise PermissionDenied
    if req.user_id == actor.pk:
        raise PermissionDenied  # nobody decides about their own request
    if not approve:
        req.status = AreaRequestStatus.DENIED
        req.decided, req.decided_by_name = timezone.now(), actor.username
        req.save()
        _log(PinEventAction.AREA_DENIED, area, actor, user=req.user, request=request)
        service.send_user_mail(req.user, _('Access denied: %(area)s') % {'area': area.name},
                               _('Your request for access to "%(area)s" was denied.') % {'area': area.name},
                               request=request)
        return None
    if rights:
        grant = grant_custom(area, req.user, target, rights, hours, actor, request=request, notify=False)
    else:
        grant = grant_access(area, req.user, profile, hours, actor, request=request, notify=False)
    req.status, req.grant = AreaRequestStatus.GRANTED, grant
    req.decided, req.decided_by_name = timezone.now(), actor.username
    req.save()
    service.send_user_mail(req.user, _('Access granted: %(area)s') % {'area': area.name}, _(
        'You were given access to "%(area)s" (%(profile)s) %(until)s.') % {
        'area': area.name, 'profile': _profile_label(grant.profile), 'until': _until_text(grant)}, request=request)
    return grant


def _until_text(grant):
    if grant.expires is None:
        return _('without time limit')
    return _('until %(time)s') % {'time': timezone.localtime(grant.expires).strftime('%Y-%m-%d %H:%M')}


def _profile_label(profile):
    return ', '.join(str(right_label(profile.area, r)) for r in profile.rights) if profile.private else profile.name


def grant_custom(area, user, target, rights, hours, actor, filters=None, request=None, notify=True):
    """
    Give ``user`` exactly ``rights`` on one object type (``target`` 'dcim.device'; '' = the whole area), optionally
    only the rows of ``filters``. The rights live in a private profile that belongs to this entry alone.
    """
    if not is_owner(actor, area):
        raise PermissionDenied
    known = set(rights_available(area))
    rights = [r for r in rights if r in known]
    if not rights:
        raise ValidationError(_('Choose at least one right.'))
    if target and target not in area_models(area):
        raise ValidationError(_('"%(target)s" is not protected by this area.') % {'target': target})
    profile = AreaProfile.objects.create(area=area, name=f'{user.username} · {target or "*"} · {uuid.uuid4().hex[:6]}',
                                         rights=rights, filters=filters or {}, private=True)
    try:
        return grant_access(area, user, profile, hours, actor, request=request, notify=notify, target=target)
    except Exception:
        profile.delete()
        raise


def update_grant(grant, rights, actor, filters=None, request=None):
    """Change the rights / rows of an access entry (its private profile)."""
    area = grant.area
    if not is_owner(actor, area):
        raise PermissionDenied
    known = set(rights_available(area))
    rights = [r for r in rights if r in known]
    if not rights:
        raise ValidationError(_('Choose at least one right.'))
    profile = grant.profile
    if not profile.private:
        raise ValidationError(_('Revoke this access and grant it again.'))
    profile.rights, profile.filters = rights, filters or {}
    profile.save()
    _log(PinEventAction.AREA_CHANGED, area, actor, user=grant.user, request=request,
         detail=f'{grant.target or "*"}: {", ".join(rights)}' + (f' | rows: {format_filters(filters)}' if filters else ''))
    clear_cache()


def grant_access(area, user, profile, hours, actor, request=None, notify=True, target=''):
    """Give ``user`` access. ``hours=None`` is permanent; otherwise 1..area.max_hours. Only owners grant."""
    if not is_owner(actor, area):
        raise PermissionDenied
    if user.pk == actor.pk:
        raise ValidationError(_('Owners already hold every right in their area.'))
    if profile is None or profile.area_id != area.pk:
        raise ValidationError(_('Choose a profile of this area.'))
    _ensure_pin_allowed(user, actor, request)
    expires = None
    if hours is not None:
        if not 1 <= int(hours) <= area.max_hours:
            raise ValidationError(_('Temporary access is 1 to %(max)s hours.') % {'max': area.max_hours})
        expires = timezone.now() + timedelta(hours=int(hours))
    grant = AreaGrant.objects.create(area=area, user=user, profile=profile, expires=expires, granted_by=actor,
                                     granted_by_name=actor.username, target=target or '')
    _log(PinEventAction.AREA_GRANTED, area, actor, user=user, request=request,
         detail=f'{target or "*"} ({", ".join(profile.rights)}) {_until_text(grant)}')
    if notify:
        service.send_user_mail(user, _('Access granted: %(area)s') % {'area': area.name}, _(
            'You were given access to "%(area)s" (%(profile)s) %(until)s.') % {
            'area': area.name, 'profile': _profile_label(profile), 'until': _until_text(grant)}, request=request)
    clear_cache()
    return grant


def revoke_grant(grant, actor, request=None):
    """Owners revoke; the user may end their own access."""
    if grant.revoked is not None:
        return
    if not (is_owner(actor, grant.area) or actor.pk == grant.user_id):
        raise PermissionDenied
    grant.revoked, grant.revoked_by_name = timezone.now(), actor.username
    grant.save()
    _log(PinEventAction.AREA_REVOKED, grant.area, actor, user=grant.user, request=request)
    clear_cache()


def cancel_request(req, actor, request=None):
    if req.user_id != actor.pk:
        raise PermissionDenied
    if req.status == AreaRequestStatus.PENDING:
        req.status, req.decided, req.decided_by_name = AreaRequestStatus.CANCELLED, timezone.now(), actor.username
        req.save()
        _log(PinEventAction.AREA_CANCELLED, req.area, actor, user=actor, request=request)


def pending_requests_for(user):
    """Waiting requests in the areas the user owns."""
    return AreaRequest.objects.filter(area__owners__user=user, status=AreaRequestStatus.PENDING).exclude(
        user=user).select_related('area', 'user')


def reset_owners(area, new_owners, actor_label='server command'):
    """Emergency (server shell, see ``manage.py userpin_area_owners``): replace the owners. Audited."""
    area.owners.all().delete()
    for user in new_owners:
        AreaOwner.objects.create(area=area, user=user)
    service.log_event(PinEventAction.AREA_CHANGED, scope=area.key,
                      detail=f'OWNERS RESET by {actor_label}: {", ".join(u.username for u in new_owners)}')
    clear_cache()


def keepers():
    return [k.user for k in PolicyKeeper.objects.select_related('user').filter(user__is_active=True)]


def can_manage_keepers(actor):
    """Keepers; as long as there are none, CORE / the master appoint the first one."""
    if PolicyKeeper.objects.exists():
        return is_keeper(actor)
    return roles.is_core(actor)


def add_keeper(user, actor, request=None):
    if not can_manage_keepers(actor):
        raise PermissionDenied
    if not user.is_active:
        raise ValidationError(_('The account is not active.'))
    if not (service.has_pin(user) and service.has_2fa(user)):
        raise ValidationError(_('%(user)s must have a PIN and 2FA set up first (My PIN).') % {'user': user.username})
    _ensure_pin_allowed(user, actor, request)
    keeper, created = PolicyKeeper.objects.get_or_create(user=user, defaults={'added_by_name': actor.username})
    if created:
        service.log_event(PinEventAction.KEEPER_ADDED, user=user, actor=actor, request=request)
        service.send_user_mail(user, _('You are a protection keeper'), _(
            'You were appointed a protection keeper: you can switch "deny everything not allowed" on and off and '
            'hand the duty over. You cannot remove your 2FA or resign alone; another keeper has to take over.'),
            request=request)
        clear_cache()
    return keeper


def remove_keeper(user, actor, request=None):
    """Only a keeper removes a keeper; the last one stays, and nobody leaves alone (another keeper must remain)."""
    if not is_keeper(actor):
        raise PermissionDenied
    keeper = PolicyKeeper.objects.filter(user=user).first()
    if keeper is None:
        return
    if PolicyKeeper.objects.count() <= 1:
        raise ValidationError(_('The last keeper cannot be removed. Appoint another keeper first.'))
    keeper.delete()
    service.log_event(PinEventAction.KEEPER_REMOVED, user=user, actor=actor, request=request)
    clear_cache()


def set_default_deny(on, actor, request=None):
    settings = service.get_settings()
    if bool(on) == settings.default_deny:
        return
    if not PolicyKeeper.objects.exists():
        raise ValidationError(_('Appoint a protection keeper first (with PIN and 2FA).'))
    if not is_keeper(actor):
        raise PermissionDenied
    settings.default_deny = bool(on)
    settings.save()
    service.log_event(PinEventAction.DENY_ENABLED if on else PinEventAction.DENY_DISABLED, actor=actor,
                      request=request)
    clear_cache()


def add_target(area, target, actor, request=None):
    """Add one app / object type to the area (chosen from the list)."""
    if area.plugin:
        raise ValidationError(_('The objects of a plugin area are set by the plugin.'))
    if not _core_or_owner(actor, area):
        raise PermissionDenied
    (target,) = parse_targets(target)
    if target in (area.targets or []):
        return False
    area.targets = list(area.targets or []) + [target]
    area.save()
    _log(PinEventAction.AREA_CHANGED, area, actor, request=request, detail=f'object added: {target}')
    clear_cache()
    return True


def remove_target(area, target, actor, request=None):
    if area.plugin:
        raise ValidationError(_('The objects of a plugin area are set by the plugin.'))
    if not _core_or_owner(actor, area):
        raise PermissionDenied
    targets = list(area.targets or [])
    if target not in targets:
        return False
    if len(targets) <= 1:
        raise ValidationError(_('An area needs at least one protected object type.'))
    targets.remove(target)
    area.targets = targets
    area.save()
    _log(PinEventAction.AREA_CHANGED, area, actor, request=request, detail=f'object removed: {target}')
    clear_cache()
    return True


def area_models(area):
    """['app.model']: the object types of the area, an app expanded into its models."""
    result = []
    for target in targets_of(area):
        if '.' in target:
            result.append(target)
            continue
        try:
            config = apps.get_app_config(target)
        except LookupError:
            continue
        result += [f'{config.label}.{m._meta.model_name}' for m in config.get_models()
                   if not m._meta.auto_created and not m._meta.proxy]
    return sorted(set(result))


def save_field_rules(area, profile, target, rules, actor, request=None):
    """
    ``rules``: {field: (mode or 'default', contains)}. 'default' removes the rule. ``profile=None`` is the rule
    "nobody sees it" (only 'hidden' / 'default').
    """
    if not _core_or_owner(actor, area):
        raise PermissionDenied
    if target not in area_models(area):
        raise ValidationError(_('"%(target)s" is not protected by this area.') % {'target': target})
    if profile is not None and profile.area_id != area.pk:
        raise ValidationError(_('Choose a profile of this area.'))
    changed = []
    for field, (mode, contains) in rules.items():
        existing = AreaFieldRule.objects.filter(area=area, profile=profile, target=target, field=field)
        if mode in ('', 'default', None) or (profile is None and mode != AreaFieldMode.HIDDEN):
            if existing.delete()[0]:
                changed.append(f'{field}: default')
            continue
        if mode not in AreaFieldMode.values:
            raise ValidationError(_('Unknown mode.'))
        rule = existing.first()
        contains = (contains or '').strip()[:200]
        if rule is None:
            AreaFieldRule.objects.create(area=area, profile=profile, target=target, field=field, mode=mode,
                                         contains=contains)
            changed.append(f'{field}: {mode}' + (f' contains "{contains}"' if contains else ''))
        elif (rule.mode, rule.contains) != (mode, contains):
            rule.mode, rule.contains = mode, contains
            rule.save()
            changed.append(f'{field}: {mode}' + (f' contains "{contains}"' if contains else ''))
    if changed:
        who = profile.name if profile else 'NOBODY'
        _log(PinEventAction.AREA_CHANGED, area, actor, request=request,
             detail=f'field rules {target} / {who}: ' + '; '.join(changed))
    return len(changed)


def denied_response(request, area, right='view'):
    """The "no access - request it" page (for plugins that check ``can`` themselves)."""
    from .area_guard import denied_response as render_denied
    return render_denied(request, get_area(area), right)


def require(request, area, right='view'):
    """None when the request's user holds ``right`` in ``area``, otherwise the response to return."""
    if can(request.user, area, right):
        return None
    return denied_response(request, area, right)


def connect_signals():
    """The list of active areas is cached for a few seconds; changes take effect at once."""
    from django.db.models.signals import post_delete, post_save

    from .models import PinSettings

    def _clear(sender, **kwargs):
        clear_cache()

    for model in (ProtectedArea, PinSettings):
        post_save.connect(_clear, sender=model, dispatch_uid=f'userpin-area-cache-save-{model.__name__}')
        post_delete.connect(_clear, sender=model, dispatch_uid=f'userpin-area-cache-delete-{model.__name__}')
