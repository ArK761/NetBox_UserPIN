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
from datetime import timedelta

from django.apps import apps
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import DatabaseError, transaction
from django.utils import timezone
from django.utils.translation import gettext as _

from . import roles, service
from .models import (
    AreaGrant, AreaOwner, AreaProfile, AreaRequest, AreaRequestStatus, PinEventAction, ProtectedArea,
)

logger = logging.getLogger('netbox_user_pin')

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
_cache = {'at': 0.0, 'areas': None}


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


def active_areas():
    now = time.monotonic()
    if _cache['areas'] is None or now - _cache['at'] > CACHE_SECONDS:
        _cache['areas'] = _load_active()
        _cache['at'] = now
    return _cache['areas']


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


def active_grants(user, area):
    now = timezone.now()
    return [g for g in AreaGrant.objects.filter(area=area, user=user, revoked__isnull=True).select_related('profile')
            if g.expires is None or g.expires > now]


def rights_of(user, area):
    """Rights the user holds in the area now (owners: all of them)."""
    if not getattr(user, 'is_authenticated', False) or not user.is_active:
        return set()
    if is_owner(user, area):
        return set(rights_available(area))
    if not AreaOwner.objects.filter(area=area).exists() and user.is_superuser:
        return set(rights_available(area))  # bootstrap: no owners yet, the master keeps access
    rights = set()
    for grant in active_grants(user, area):
        rights.update(grant.profile.rights)
    return rights


def can(user, area, right='view'):
    """May the user use ``right`` in the area? Areas that do not protect (inactive / unknown key) allow."""
    area = get_area(area)
    if area is None or area not in active_areas():
        return True
    return right in _memo_rights(user, area)


def _memo_rights(user, area):
    memo = user.__dict__.setdefault('_userpin_rights', {}) if hasattr(user, '__dict__') else {}
    stamp = int(time.monotonic() // CACHE_SECONDS)
    entry = memo.get(area.pk)
    if entry is None or entry[0] != stamp:
        entry = (stamp, rights_of(user, area))
        memo[area.pk] = entry
    return entry[1]


def check_perm(user, perm):
    """For ``User.has_perm``: ``None`` when no area covers the permission, otherwise ``(allowed, area)``."""
    app_label, _dot, codename = perm.partition('.')
    if not codename or not active_areas():
        return None
    action, _underscore, model = codename.partition('_')
    area = area_for(app_label, model or None, package=app_label)
    if area is None:
        return None
    return can(user, area, action if action in GENERIC_RIGHTS else 'change'), area


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


def save_profile(area, name, rights, actor, profile=None, request=None):
    if not _core_or_owner(actor, area):
        raise PermissionDenied
    known = set(rights_available(area))
    rights = [r for r in rights if r in known]
    if not rights:
        raise ValidationError(_('Choose at least one right.'))
    if profile is None:
        if AreaProfile.objects.filter(area=area, name=name).exists():
            raise ValidationError(_('A profile with this name exists.'))
        profile = AreaProfile.objects.create(area=area, name=name, rights=rights)
    else:
        profile.name, profile.rights = name, rights
        profile.save()
    _log(PinEventAction.AREA_CHANGED, area, actor, request=request, detail=f'profile {name}: {", ".join(rights)}')
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


def request_access(area, user, note='', request=None):
    """A user asks the owners for access. One waiting request per user and area."""
    area = get_area(area)
    if area is None or not user.is_authenticated or not user.is_active:
        raise PermissionDenied
    existing = AreaRequest.objects.filter(area=area, user=user, status=AreaRequestStatus.PENDING).first()
    if existing:
        return existing
    recipients = owners(area)
    if not recipients:
        raise ValidationError(_('The area has no owners yet. Ask the administrator to appoint them.'))
    req = AreaRequest.objects.create(area=area, user=user, note=note[:200])
    _log(PinEventAction.AREA_REQUESTED, area, user, user=user, request=request, detail=note[:200])
    label = service.user_label(user)
    _notify(req, recipients, _(
        '%(user)s asks for access to the area "%(area)s".\n\nOpen User PIN > Protected areas to grant or deny it '
        '(confirm with your PIN and 2FA).') % {'user': label, 'area': area.name},
        _('Access request: %(area)s') % {'area': area.name})
    return req


def decide_request(req, actor, approve, profile=None, hours=None, request=None):
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
    grant = grant_access(area, req.user, profile, hours, actor, request=request, notify=False)
    req.status, req.grant = AreaRequestStatus.GRANTED, grant
    req.decided, req.decided_by_name = timezone.now(), actor.username
    req.save()
    service.send_user_mail(req.user, _('Access granted: %(area)s') % {'area': area.name}, _(
        'You were given access to "%(area)s" (%(profile)s) %(until)s.') % {
        'area': area.name, 'profile': grant.profile.name, 'until': _until_text(grant)}, request=request)
    return grant


def _until_text(grant):
    if grant.expires is None:
        return _('without time limit')
    return _('until %(time)s') % {'time': timezone.localtime(grant.expires).strftime('%Y-%m-%d %H:%M')}


def grant_access(area, user, profile, hours, actor, request=None, notify=True):
    """Give ``user`` access. ``hours=None`` is permanent; otherwise 1..area.max_hours. Only owners grant."""
    if not is_owner(actor, area):
        raise PermissionDenied
    if user.pk == actor.pk:
        raise ValidationError(_('Owners already hold every right in their area.'))
    if profile is None or profile.area_id != area.pk:
        raise ValidationError(_('Choose a profile of this area.'))
    expires = None
    if hours is not None:
        if not 1 <= int(hours) <= area.max_hours:
            raise ValidationError(_('Temporary access is 1 to %(max)s hours.') % {'max': area.max_hours})
        expires = timezone.now() + timedelta(hours=int(hours))
    grant = AreaGrant.objects.create(area=area, user=user, profile=profile, expires=expires, granted_by=actor,
                                     granted_by_name=actor.username)
    _log(PinEventAction.AREA_GRANTED, area, actor, user=user, request=request,
         detail=f'{profile.name} ({", ".join(profile.rights)}) {_until_text(grant)}')
    if notify:
        service.send_user_mail(user, _('Access granted: %(area)s') % {'area': area.name}, _(
            'You were given access to "%(area)s" (%(profile)s) %(until)s.') % {
            'area': area.name, 'profile': profile.name, 'until': _until_text(grant)}, request=request)
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
