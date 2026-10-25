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
# Never refused by the default deny: technical data NetBox needs to draw its forms. Nothing else - the user may do what
# a group allows him, and change his password (a view without objects, never refused).
DEFAULT_DENY_EXEMPT = frozenset({'core.objecttype'})


# The types that point at an object of another type: what is in a protected area is not told by them either.
POINTING_AT_OBJECTS = {'core.objectchange': 'changed_object_type', 'extras.journalentry': 'assigned_object_type',
                       'extras.imageattachment': 'object_type'}


def unseen_objects(user, app_label, model):
    """A ``Q`` of the rows (change log, journal, attachments) that belong to objects the user may not view, or None."""
    field = POINTING_AT_OBJECTS.get(f'{app_label}.{model}')
    if not field or not active_areas():
        return None
    hidden = Q()
    from . import fieldrules
    for target in fieldrules.hidden_by_type(user):  # the old and new values would show the hidden fields
        app, _dot, name = target.partition('.')
        hidden |= Q(**{f'{field}__app_label': app, f'{field}__model': name})
    for area in active_areas():
        for target in targets_of(area):
            if can(user, area, 'view', target if '.' in target else None):
                continue
            app, _dot, name = target.partition('.')
            hidden |= Q(**{f'{field}__app_label': app, **({f'{field}__model': name} if name else {})})
    return hidden if hidden else None


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
    except DatabaseError:  # before the migrations - or a hiccup of the database: the caller keeps what it knew
        return None
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
    loaded = _load_active()
    _cache['areas'] = loaded if loaded is not None else (_cache['areas'] or [])
    try:
        keepers = frozenset(PolicyKeeper.objects.filter(user__is_active=True).values_list('user_id', flat=True))
        _cache['deny'] = bool(service.get_settings().default_deny and keepers)
        _cache['keepers'] = keepers
    except DatabaseError:
        logger.exception('PIN: the keepers cannot be read, the last known state stays')
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
    info = _registry.get(area.key) if area is not None and area.plugin else None
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
    broad = None
    for area in active_areas():
        for target in targets_of(area):
            if '.' in target:
                target_app, target_model = target.split('.', 1)
                if app_label == target_app and model == target_model:
                    return area  # an area of the very object type wins over one of its whole app
            elif target in (app_label, package) and broad is None:
                broad = area
    return broad


#
# Rights
#

def owners(area):
    return [owner.user for owner in area.owners.select_related('user') if owner.user.is_active]


def is_owner(user, area):
    """An owner is still an owner only while he holds the role (head, delegate, CORE deputy) and is no superuser."""
    if not (getattr(user, 'is_authenticated', False) and user.is_active and not user.is_superuser
            and AreaOwner.objects.filter(area=area, user=user).exists()):
        return False
    return not is_keeper(user) and roles.manager_users(include_superusers=False).filter(pk=user.pk).exists()


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
    if _bootstrap(user, area):
        return set(rights_available(area))  # bootstrap: no owners yet, the master keeps access
    rights, denied = set(), set()
    for grant in active_grants(user, area, target):
        rights.update(grant.profile.rights)
        denied.update(grant.profile.denied or [])
    if 'view' in denied:
        return set()  # who may not read may not do anything with it
    return rights - denied


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


def _bootstrap(user, area):
    """
    Until an area has owners its data is seen by the protection keepers only - so that somebody can set it up and
    nobody else (superusers included) sees what nobody was given. Without any keeper yet: the superusers.
    """
    if not getattr(user, 'is_authenticated', False) or AreaOwner.objects.filter(area=area).exists():
        return False
    active_areas()
    if _cache['keepers']:
        return is_keeper(user)
    return bool(user.is_superuser)


def _unrestricted(user, area):
    """Owners (and, before owners exist, superusers) see every row."""
    return is_owner(user, area) or _bootstrap(user, area)


#
# Tabs of the detail pages
#

def _tab_configs(app_label, model_name):
    from django.utils.module_loading import import_string
    from netbox.registry import registry
    result = []
    for config in registry['views'].get(app_label, {}).get(model_name, []):
        view = import_string(config['view']) if isinstance(config['view'], str) else config['view']
        result.append((config, view))
    return result


def tab_info(view_class, app_label, model_name):
    """
    (name, label, is_plugin) when ``view_class`` is a tab of the detail page of ``app_label.model_name``, else None.
    The main page of the object is no tab.
    """
    from django.conf import settings
    if view_class is None or not app_label or not model_name:
        return None
    for config, view in _tab_configs(app_label, model_name):
        tab = getattr(view, 'tab', None)
        if view is view_class and tab is not None and config['name'] and config.get('detail', True):
            package = view.__module__.split('.')[0]
            return config['name'], str(tab.label), package in getattr(settings, 'PLUGINS', ())
    return None


def tabs_of(target):
    """[{name, label, plugin}] of the tabs the detail page of an object type ('dcim.device') has."""
    app_label, _dot, model_name = (target or '').partition('.')
    result, seen = [], set()
    for config, view in _tab_configs(app_label, model_name):
        tab = getattr(view, 'tab', None)
        if tab is None or not config['name'] or config['name'] in seen or not config.get('detail', True):
            continue
        seen.add(config['name'])
        from django.conf import settings
        result.append({'name': config['name'], 'label': str(tab.label),
                       'plugin': view.__module__.split('.')[0] in getattr(settings, 'PLUGINS', ())})
    return sorted(result, key=lambda t: t['label'].lower())


def set_group_tabs(group, tabs, actor, request=None):
    """Choose the system tabs the members of a group may open."""
    area = group.area
    if not _may_grant(actor, area) or group.private:
        raise PermissionDenied
    known = {t['name'] for t in tabs_of(group.target) if not t['plugin']}
    group.tabs = sorted(t for t in tabs if t in known)
    group.save()
    _log(PinEventAction.AREA_CHANGED, area, actor, request=request,
         detail=f'group {group.name} tabs: {", ".join(group.tabs) or "main page only"}')
    clear_cache()


def tab_allowed(user, area, target, tab_name):
    """May the user open this (system) tab? Owners always; others as their grants for the object type allow."""
    if _unrestricted(user, area):
        return True
    for grant in active_grants(user, area, target):
        if 'view' in grant.profile.rights and (grant.profile.tabs is None or tab_name in grant.profile.tabs):
            return True
    return False


def set_grant_tabs(grant, tabs, actor, request=None):
    """Choose the system tabs an access entry may open."""
    area = grant.area
    if not _may_grant(actor, area):
        raise PermissionDenied
    profile = grant.profile
    if not profile.private:
        raise ValidationError(_('Revoke this access and grant it again.'))
    known = {t['name'] for t in tabs_of(grant.target) if not t['plugin']}
    profile.tabs = sorted(t for t in tabs if t in known)
    profile.save()
    _log(PinEventAction.AREA_CHANGED, area, actor, user=grant.user, request=request,
         detail=f'tabs {grant.target or "*"}: {", ".join(profile.tabs) or "main page only"}')
    clear_cache()


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
    allowed, everything, denied = [], False, []
    for grant in active_grants(user, area, target):
        profile = grant.profile
        deny_spec = (profile.deny_filters or {}).get(target)
        if isinstance(deny_spec, list):  # a Deny of any source applies whatever the other sources allow
            denied += [_spec_q([c]) for c in deny_spec]
        if action not in profile.rights:
            continue
        spec = (profile.filters or {}).get(target)
        if profile.records == 'unset':
            continue  # not configured: no records, never "all of them by accident"
        if profile.records == 'filtered':
            if not spec:
                continue  # a filter without a condition is "nothing"
            allowed.append(_spec_q(spec))
        else:
            everything = True
    if not (everything or allowed):
        return None
    query = Q() if everything else _any_q(allowed)
    if denied:
        query = query & ~_any_q(denied)
    return query


def _any_q(queries):
    """One of the conditions (``Q() | Q(x)`` would drop the empty one, so the first one starts it)."""
    result = queries[0]
    for query in queries[1:]:
        result = result | query
    return result


#
# Row conditions of a group: [{"field": "role", "op": "eq", "value": "3"}, ...] - all of them hold
# (the older form of a private entry is a dict of Django lookups)
#

ROW_OPS = {  # op: (lookup, negated)
    'eq': ('exact', False), 'ne': ('exact', True),
    'contains': ('icontains', False), 'ncontains': ('icontains', True),
    'startswith': ('istartswith', False),
    'in': ('in', False), 'nin': ('in', True),
}


def row_op_labels():
    return {'eq': _('is'), 'ne': _('is not'), 'contains': _('contains'), 'ncontains': _('does not contain'),
            'startswith': _('starts with'), 'in': _('is one of'), 'nin': _('is not one of')}


def _spec_q(spec):
    if isinstance(spec, dict):
        return Q(**spec)
    query = Q()
    for condition in spec:
        lookup, negated = ROW_OPS[condition['op']]
        lookup = condition.get('lookup') or lookup
        path = condition.get('path') or condition['field']
        if condition.get('ci') and condition['op'] in ('in', 'nin'):  # a text: capital letters do not matter
            part = Q()
            for value in condition['value']:
                part |= Q(**{f'{path}__iexact': value})
        elif condition.get('ci') and condition['op'] in ('eq', 'ne'):
            part = Q(**{f'{path}__iexact': condition['value']})
        elif lookup in ('icontains', 'istartswith') and isinstance(condition['value'], list):
            part = Q()  # "agg" or "core": the record qualifies when any of the values fits
            for value in condition['value']:
                part |= Q(**{f'{path}__{lookup}': value})
        else:
            part = Q(**{f"{path}__{lookup}": condition['value']})
        query &= ~part if negated else part
    return query


def _name_field(model):
    """The field by which people call the objects of a model: name, label, slug ..."""
    for candidate in ('name', 'label', 'slug', 'model', 'title'):
        try:
            model._meta.get_field(candidate)
            return candidate
        except Exception:  # noqa: BLE001 - no such field
            continue
    return None


def filter_fields(target):
    """[{key, label, kind, choices}]: the fields a row condition may use (choices for relations and choice fields)."""
    from django.db import models as dj
    app_label, _dot, model_name = target.partition('.')
    model = apps.get_model(app_label, model_name)
    result = []
    for field in model._meta.concrete_fields:
        if field.primary_key or field.name in ('custom_field_data', 'created', 'last_updated'):
            continue
        choices = None
        if field.is_relation and field.many_to_one:
            kind = 'relation'
            choices = [(str(o.pk), str(o)) for o in field.related_model._default_manager.all()[:500]]
        elif getattr(field, 'choices', None):
            kind = 'choice'
            choices = [(str(v), str(label)) for v, label in field.flatchoices]
        elif isinstance(field, (dj.IntegerField, dj.FloatField, dj.DecimalField)):
            kind = 'number'
        elif isinstance(field, dj.BooleanField):
            kind, choices = 'bool', [('True', str(_('yes'))), ('False', str(_('no')))]
        else:
            kind = 'text'
        result.append({'key': field.name, 'label': str(getattr(field, 'verbose_name', field.name)).capitalize(),
                       'kind': kind, 'choices': choices})
    return sorted(result, key=lambda f: f['label'].lower())


def _clean_condition(target, field, op, values):
    """The condition as it is stored, or a ValidationError."""
    from django.core.exceptions import FieldError
    meta = next((f for f in filter_fields(target) if f['key'] == field), None)
    if meta is None or op not in ROW_OPS:
        raise ValidationError(_('Choose the field and the condition.'))
    values = [v.strip() for v in values if v and v.strip()]
    if not values:
        raise ValidationError(_('Write or choose the value.'))
    multi = op in ('in', 'nin', 'contains', 'ncontains', 'startswith')
    if not multi:
        values = values[:1]
    app_label, _dot, model_name = target.partition('.')
    model = apps.get_model(app_label, model_name)
    model_field = model._meta.get_field(field)
    lookup, _negated = ROW_OPS[op]

    def convert(text):
        if model_field.is_relation:
            return model_field.target_field.to_python(text)
        if lookup in ('icontains', 'istartswith'):
            return text
        return model_field.to_python(text)

    try:
        extra = {}
        if model_field.is_relation:
            # a relation is chosen by its number from a list, or written as text: then the name of the related object
            by_name = lookup in ('icontains', 'istartswith') or not all(v.lstrip('-').isdigit() for v in values)
            if by_name:
                name = _name_field(model_field.related_model)
                if name is None:
                    raise ValidationError(_('This field cannot be compared by a text.'))
                extra = {'path': f'{field}__{name}', 'lookup': 'iexact' if lookup == 'exact' else lookup}
                converted = list(values)
            else:
                converted = [convert(v) for v in values]
        else:
            converted = [convert(v) for v in values]
        value = converted if multi else converted[0]
        condition = {'field': field, 'op': op, 'value': [str(v) for v in value] if multi else str(value), **extra}
        if not model_field.is_relation and model_field.get_internal_type() in ('CharField', 'TextField', 'SlugField'):
            condition['ci'] = True  # texts are compared without regard to the case
        probe = value[0] if isinstance(value, list) and (extra.get('lookup') or lookup) != 'in' else value
        model._default_manager.filter(**{f"{extra.get('path') or field}__{extra.get('lookup') or lookup}": probe}
                                      ).query  # noqa: B018
    except (ValidationError, FieldError, ValueError, TypeError) as exc:
        raise ValidationError(_('The condition is not valid: %(error)s') % {'error': exc})
    return condition


def condition_text(target, condition):
    """'Role is Switch' for the page."""
    meta = next((f for f in filter_fields(target) if f['key'] == condition['field']), None)
    label = meta['label'] if meta else condition['field']
    names = dict(meta['choices']) if meta and meta['choices'] else {}
    value = condition['value']
    glue = ', ' if condition['op'] in ('in', 'nin') else ' / '
    shown = glue.join(names.get(str(v), str(v)) for v in value) if isinstance(value, list) else names.get(
        str(value), str(value))
    return f"{label} {row_op_labels().get(condition['op'], condition['op'])} {shown}"


def group_deny_conditions(group):
    """[(index, text, field)] of the conditions of the records a group never shows."""
    spec = (group.deny_filters or {}).get(group.target) or []
    return [(i, condition_text(group.target, c), c['field']) for i, c in enumerate(spec) if isinstance(c, dict)]


def set_group_records(group, actor, state, request=None):
    """Which records the group sees: ``unset`` (none yet), ``all`` (chosen by the owner) or ``filtered``."""
    if not _may_grant(actor, group.area) or group.private:
        raise PermissionDenied
    if state not in ('unset', 'all', 'filtered'):
        raise ValidationError(_('Unknown choice.'))
    group.records = state
    group.save()
    _log(PinEventAction.AREA_CHANGED, group.area, actor, request=request, detail=f'group {group.name} records: {state}')
    clear_cache()


def _condition_values(condition):
    """The values by which a condition lets (or hides) records, lower-cased, for the test of a conflict."""
    if condition['op'] not in ('eq', 'in', 'contains', 'startswith'):
        return set()
    value = condition['value']
    return {str(v).lower() for v in (value if isinstance(value, list) else [value])}


def _conflict(new, others):
    """A value cannot be both allowed and denied: the same value of the same field in the other list."""
    mine = _condition_values(new)
    for other in others:
        if isinstance(other, dict) and other.get('field') == new['field'] and other.get('path') == new.get('path') \
                and (mine & _condition_values(other)):
            return sorted(mine & _condition_values(other))[0]
    return None


def group_conditions(group):
    """[(index, text, field)] of the row conditions of a group (for its object type)."""
    spec = (group.filters or {}).get(group.target) or []
    if isinstance(spec, dict):
        return [(i, f'{k} = {v}', '') for i, (k, v) in enumerate(spec.items())]
    return [(i, condition_text(group.target, c), c['field']) for i, c in enumerate(spec)]


def add_group_condition(group, actor, field, op, values, request=None, deny=False):
    area = group.area
    if not _may_grant(actor, area) or group.private or not group.target:
        raise PermissionDenied
    condition = _clean_condition(group.target, field, op, values)
    opposite = (group.filters if deny else group.deny_filters) or {}
    clash = _conflict(condition, opposite.get(group.target) if isinstance(opposite.get(group.target), list) else [])
    if clash is not None:
        raise ValidationError(_('"%(value)s" is already in the list of %(list)s: a value cannot be both allowed and '
                                'denied.') % {'value': clash, 'list': _('allowed') if deny else _('denied')})
    filters = dict((group.deny_filters if deny else group.filters) or {})
    current = filters.get(group.target) or []
    if isinstance(current, dict):
        current = []
    current = list(current)
    # a second "is X" on the same field means "is X or Y", and "is not X" then "is not Y" means neither of them
    merge = {'eq': 'in', 'ne': 'nin'}

    def as_many(cond):
        cond = {**cond, 'op': merge[cond['op']], 'value': [cond['value']]}
        if cond.get('lookup') == 'iexact':  # a name compared as text: "any of these names, whatever the case"
            cond.pop('lookup')
            cond['ci'] = True
        return cond

    def same_field(other):
        return other['field'] == condition['field'] and other.get('path') == condition.get('path')

    same = None
    if condition['op'] in merge:
        for index, existing in enumerate(current):
            if same_field(existing) and existing['op'] == condition['op'] and \
                    not isinstance(existing['value'], list):
                current[index] = same = as_many(existing)  # "is X" and now "is Y": one condition for both
                condition = as_many(condition)
                break
            if same_field(existing) and existing['op'] == merge[condition['op']] and \
                    isinstance(existing['value'], list):
                same, condition = existing, as_many(condition)
                break
    if same is None and condition['op'] in ('contains', 'ncontains', 'startswith', 'in', 'nin'):
        same = next((c for c in current if same_field(c) and c['op'] == condition['op']
                     and isinstance(c['value'], list) and isinstance(condition['value'], list)), None)
    if same is not None:  # one more value of the same condition: agg, and now core as well
        same['value'] = list(dict.fromkeys(same['value'] + condition['value']))
        condition = same
    else:
        current.append(condition)
    filters[group.target] = current
    if deny:
        group.deny_filters = filters
    else:
        group.filters = filters
        group.records = 'filtered'  # a condition that is added is meant to narrow the records
    group.save()
    _log(PinEventAction.AREA_CHANGED, area, actor, request=request,
         detail=f'group {group.name} rows {"DENIED" if deny else "allowed"}: {condition_text(group.target, condition)}')
    clear_cache()
    return condition


def remove_group_condition(group, actor, index, request=None, deny=False):
    area = group.area
    if not _may_grant(actor, area) or group.private:
        raise PermissionDenied
    filters = dict((group.deny_filters if deny else group.filters) or {})
    current = filters.get(group.target) or []
    if isinstance(current, list) and 0 <= index < len(current):
        removed = current.pop(index)
        if current:
            filters[group.target] = current
        else:
            filters.pop(group.target, None)
        if deny:
            group.deny_filters = filters
        else:
            group.filters = filters
        group.save()
        _log(PinEventAction.AREA_CHANGED, area, actor, request=request,
             detail=f'group {group.name} rows {"denied" if deny else "allowed"} removed: '
                    f'{condition_text(group.target, removed)}')
        clear_cache()


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
    lines = []
    for target, spec in (filters or {}).items():
        if isinstance(spec, dict):
            lines.append(f'{target}: ' + ' & '.join(f'{k}={v}' for k, v in spec.items()))
        else:
            lines.append(f'{target}: ' + ' & '.join(condition_text(target, c) for c in spec))
    return '\n'.join(lines)


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
    if not codename:
        return None
    active_areas()
    action, _underscore, model = codename.partition('_')
    area = area_for(app_label, model or None, package=app_label) if _cache['areas'] else None
    if area is None:
        if model and default_deny_blocks(user, app_label, model, app_label):
            # nothing allows it. The door (menu item) stays, so that the "request access" page can be reached;
            # buttons do not, and the system apps (users, permissions, jobs ...) have no door at all
            if action == 'view' and app_label not in SENSITIVE_APPS:
                return None
            return False, None
        return None
    rights = _memo_rights(user, area, f'{app_label}.{model}' if model else None)
    if not rights:
        # the door (menu item) stays so that a request can be made (unless the area hides what is not allowed)
        return action == 'view' and not area.hide_denied, area
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
    if 'BulkEdit' in name or 'BulkRename' in name:
        return 'change'
    if method == 'POST' and view_class is not None and ('Edit' in name or 'Create' in name):
        return 'change' if (view_kwargs or {}).get('pk') else 'add'
    if method == 'POST' and view_class is not None and hasattr(view_class, 'serializer_class'):
        return 'add'  # REST API: POST creates
    return 'change'


#
# Administration
#

def _core_or_owner(actor, area):
    """Who may change an area: its owners; as long as there are none, the keepers (CORE / the master without any)."""
    if AreaOwner.objects.filter(area=area).exists():
        return is_owner(actor, area)
    return _stand_in(actor)


def _stand_in(actor):
    """Who sets up what has no owner yet: a protection keeper; while there is none, CORE / the master."""
    active_areas()
    if _cache['keepers']:
        return is_keeper(actor)
    return roles.is_core(actor)


# Apps whose data decides about accounts and the system: only a keeper (CORE / the master while there is none)
# may protect them, never an owner of an area - or he would rule over every account.
SENSITIVE_APPS = frozenset({'users', 'auth', 'core', 'social_django', 'django_rq', 'contenttypes', 'sessions',
                            'account'})


def _may_take(actor, area, target):
    """May the actor put this app / object type in the area? Not an owner, when it is sensitive or protected already."""
    if _stand_in(actor):
        return True
    app_label = target.partition('.')[0]
    if app_label in SENSITIVE_APPS:
        return False
    for other in active_areas():
        if other.pk != area.pk and any(t == target or t == app_label or t.startswith(f'{target}.')
                                       for t in targets_of(other)):
            return False
    return True


def can_manage(actor, area):
    return _core_or_owner(actor, area)


def administers_any(user):
    """Does the user have anything to do on the pages of the protected areas (a keeper, a stand-in, an owner)?"""
    if not getattr(user, 'is_authenticated', False):
        return False
    if is_keeper(user) or _stand_in(user):
        return True
    return any(is_owner(user, owner.area) for owner in AreaOwner.objects.filter(user=user).select_related('area'))


def can_see(actor, area):
    return is_owner(actor, area) or is_keeper(actor) or (
        roles.is_core(actor) and not AreaOwner.objects.filter(area=area).exists())


def _log(action, area, actor, user=None, request=None, detail=''):
    service.log_event(action, user=user, actor=actor, request=request, scope=area.key if area else 'default-deny',
                      detail=detail)


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
    if not _stand_in(actor):
        raise PermissionDenied
    key = _unique_key(name)
    area = ProtectedArea.objects.create(key=key, name=name, description=description, targets=targets,
                                        max_hours=max_hours)
    _log(PinEventAction.AREA_CREATED, area, actor, request=request, detail=f'targets: {", ".join(targets)}')
    for user in owners_:
        _check_owner_role(user)
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


def owner_requirements(user):
    """[(text, ok)]: what an account needs to own an area; every line is met or it is what blocks him."""
    plain = not (user.is_superuser or is_keeper(user))
    role = roles.manager_users(include_superusers=False).filter(pk=user.pk).exists()
    return [
        (_('Is not a superuser or a protection keeper') if plain else
         _('Is a superuser or a protection keeper (they are decided about)'), plain),
        (_('Is a department head, a delegate or a CORE deputy') if role else
         _('Is no department head, delegate or CORE deputy'), role),
        (_('Has a PIN') if service.has_pin(user) else _('Has no PIN yet'), service.has_pin(user)),
        (_('Has 2FA') if service.has_2fa(user) else _('Has no 2FA yet'), service.has_2fa(user)),
    ]


def _check_owner_role(user):
    """
    The owner decides about the superusers, so he is none of them (nor a protection keeper): a department head, a
    delegate or a CORE deputy, with a PIN and 2FA.
    """
    problems = [text for text, ok in owner_requirements(user) if not ok]
    if problems:
        raise ValidationError(_('%(user)s cannot own an area: %(why)s.') % {
            'user': user.username, 'why': '; '.join(str(p).lower() for p in problems)})


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
    _check_owner_role(user)
    _ensure_pin_allowed(user, actor, request)
    owner = _add_owner(area, user, actor, request)
    clear_cache()
    return owner


def add_owners(area, users, actor, request=None):
    """Several owners at once (the right to do so is checked once, before the first one makes it the owners' own)."""
    if not _core_or_owner(actor, area):
        raise PermissionDenied
    added, errors = [], []
    for user in users:
        try:
            if not user.is_active:
                raise ValidationError(_('The account is not active.'))
            _check_owner_role(user)
            _ensure_pin_allowed(user, actor, request)
            _add_owner(area, user, actor, request)
            added.append(user)
        except ValidationError as exc:
            errors.append(exc)
    clear_cache()
    return added, errors


def remove_owner(area, user, actor, request=None):
    """
    Only an owner removes an owner (never the master alone), and never the last one. A superuser or a protection
    keeper cannot be an owner: the protection keepers remove such an owner, even the last one.
    """
    owner = AreaOwner.objects.filter(area=area, user=user).first()
    ineligible = owner is not None and (owner.user.is_superuser or is_keeper(owner.user))
    keeper = is_keeper(actor)  # the protection keepers run the whole protection: they may remove any owner
    if not (is_owner(actor, area) or keeper):
        raise PermissionDenied
    if owner is None:
        return
    if area.owners.count() <= 1 and not (ineligible or keeper):
        raise ValidationError(_('The last owner cannot be removed. Appoint another owner first.'))
    owner.delete()
    _log(PinEventAction.AREA_OWNER_REMOVED, area, actor, user=user, request=request)
    clear_cache()


def update_area(area, actor, name=None, description=None, targets=None, enabled=None, max_hours=None, request=None,
                hide_denied=None):
    if not _core_or_owner(actor, area):
        raise PermissionDenied
    changes = []
    for field, value in (('name', name), ('description', description), ('targets', targets), ('enabled', enabled),
                         ('max_hours', max_hours), ('hide_denied', hide_denied)):
        if value is None or area.plugin and field in ('targets', 'enabled'):
            continue
        if field == 'targets' and not all(_may_take(actor, area, t) for t in value if t not in (area.targets or [])):
            raise ValidationError(_('Some object type is sensitive or protected by another area: only a protection '
                                    'keeper can put it in this one.'))
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
    if not (_core_or_owner(actor, area) or is_keeper(actor)):
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
    rights = _with_view(rights)
    if profile is None:
        if AreaProfile.objects.filter(area=area, name=name).exists():
            raise ValidationError(_('A profile with this name exists.'))
        profile = AreaProfile.objects.create(area=area, name=name, rights=rights, filters=filters or {},
                                             records='filtered' if filters else 'all')
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


def request_access(area, user, note='', request=None, scope='', target='', rights=None):
    """A user asks the owners for access. One waiting request per user, area and object type."""
    area = get_area(area)
    if area is None or not user.is_authenticated or not user.is_active:
        raise PermissionDenied
    existing = AreaRequest.objects.filter(area=area, user=user, target=target or '',
                                          status=AreaRequestStatus.PENDING).first()
    if existing:
        return existing
    recipients = owners(area)
    if not recipients:
        recipients = keepers()  # no owners yet: the keepers decide
    return _create_request(area, user, note, request, scope, target, rights, recipients)


def request_target_access(user, target, rights, note, request=None, scope=''):
    """
    A user whose way is blocked asks for ``rights`` on an object type / app. The owners of the area that protects it
    decide; when no area protects it yet, the protection keepers do (and approving creates the area).
    """
    if not user.is_authenticated or not user.is_active:
        raise PermissionDenied
    target = (target or '').strip().lower()
    app_label, _dot, model = target.partition('.')
    try:
        apps.get_app_config(app_label)
        if model:
            apps.get_model(app_label, model)
    except LookupError:
        raise ValidationError(_('Unknown object type.'))
    if app_label in NEVER:
        raise PermissionDenied
    area = area_for(app_label, model or None, package=app_label)
    existing = AreaRequest.objects.filter(user=user, target=target, status=AreaRequestStatus.PENDING).first()
    if existing:
        return existing
    recipients = (owners(area) if area else []) or keepers()
    return _create_request(area, user, note, request, scope, target, rights, recipients)


def _create_request(area, user, note, request, scope, target, rights, recipients):
    if len((note or '').strip()) < 5:
        raise ValidationError(_('Write why you need the access (at least a few words).'))
    known = set(rights_available(area)) if area else set(GENERIC_RIGHTS)
    rights = [r for r in (rights or []) if r in known]
    if not recipients:
        raise ValidationError(_('Nobody can decide about it yet. Ask the administrator to appoint the owners or '
                                'a protection keeper.'))
    req = AreaRequest.objects.create(area=area, user=user, target=target or '', rights=rights, note=note.strip()[:200],
                                     scope=(scope or '').strip()[:200])
    _log(PinEventAction.AREA_REQUESTED, area, user, user=user, request=request,
         detail=f'{target_label(target) or "-"}: {", ".join(rights) or "-"} | {req.note}'
                + (f' | {req.scope}' if req.scope else ''))
    link = ''
    if request is not None:
        from django.urls import reverse
        link = request.build_absolute_uri(reverse('plugins:netbox_user_pin:request_decide', kwargs={'pk': req.pk}))
    what = area.name if area else target_label(req.target)
    _notify(req, recipients, _(
        '%(user)s asks for access: %(what)s\n\nRights: %(rights)s\nWhy: %(reason)s\nWhat exactly: %(scope)s\n\n'
        'Decide here (confirm with your PIN and 2FA):\n%(link)s') % {
        'user': service.user_label(user), 'what': what,
        'rights': ', '.join(str(right_label(area, r)) if area else r for r in rights) or '-',
        'reason': req.note, 'scope': req.scope or '-', 'link': link or _('User PIN > Protected areas')},
        _('Access request: %(area)s') % {'area': what})
    return req


def _may_grant(actor, area):
    """Owners grant; an area without owners yet is handled by the protection keepers."""
    return is_owner(actor, area) or (not AreaOwner.objects.filter(area=area).exists() and is_keeper(actor))


def target_label(target):
    """'dcim.device' -> 'DCIM > Device'; an app -> its name."""
    app_label, _dot, model = (target or '').partition('.')
    try:
        config = apps.get_app_config(app_label)
        if not model:
            return str(config.verbose_name)
        return f'{config.verbose_name} > {str(apps.get_model(app_label, model)._meta.verbose_name).capitalize()}'
    except LookupError:
        return target or ''


def _create_requested_area(req, actor, request):
    """The first approved request for an object type creates its area (without owners: those are appointed by hand)."""
    name = target_label(req.target)
    area = ProtectedArea.objects.create(
        key=_unique_key(name), name=name, targets=[req.target], max_hours=24,
        description=_('Created from the access request of %(user)s.') % {'user': req.user.username})
    _log(PinEventAction.AREA_CREATED, area, actor, request=request,
         detail=f'targets: {req.target} (from the request of {req.user.username})')
    settings = service.get_settings()
    if not settings.areas_enabled:
        settings.areas_enabled = True
        settings.save()
        _log(PinEventAction.AREA_CHANGED, area, actor, request=request, detail='protection of own areas switched on')
    clear_cache()
    return area


def decide_request(req, actor, approve, profile=None, hours=None, request=None, rights=None, target=None,
                   group=None, group_name='', group_rights=None):
    if req.status != AreaRequestStatus.PENDING:
        raise ValidationError(_('The request has been dealt with already.'))
    area = req.area
    if area is None:
        app_label, _dot, model = req.target.partition('.')
        area = area_for(app_label, model or None, package=app_label)
        if area is None and not is_keeper(actor):
            raise PermissionDenied
    if area is not None and not _may_grant(actor, area):
        raise PermissionDenied
    if req.user_id == actor.pk:
        raise PermissionDenied  # nobody decides about their own request
    what = area.name if area else target_label(req.target)
    if not approve:
        req.status = AreaRequestStatus.DENIED
        req.decided, req.decided_by_name = timezone.now(), actor.username
        req.save()
        _log(PinEventAction.AREA_DENIED, area, actor, user=req.user, request=request)
        service.send_user_mail(req.user, _('Access denied: %(area)s') % {'area': what},
                               _('Your request for access to "%(area)s" was denied.') % {'area': what},
                               request=request)
        return None
    if area is None:
        area = _create_requested_area(req, actor, request)
    req.area = area
    if target is None:
        target = req.target if '.' in req.target else ''
    if rights is None and profile is None:
        rights = req.rights  # as asked
    if '.' in req.target and (group is not None or group_name or group_rights is not None):
        if group is None:  # the decider creates the group the request needs
            wanted = _clean_group_rights(area, group_rights or req.rights)
            name = (group_name or '').strip() or (_('Reading') if wanted == ['view'] else _('Writing'))
            group = AreaProfile.objects.filter(area=area, name=name, target=req.target, private=False).first()
            if group is None:
                group = create_group(area, req.target, name, wanted, actor, request=request, records='all')
        elif group.area_id != area.pk or group.target != req.target:
            raise ValidationError(_('Choose a group of this object type.'))
        grant = add_member(group, req.user, hours, actor, request=request, notify=False)
    elif rights:
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
    if not _may_grant(actor, area):
        raise PermissionDenied
    known = set(rights_available(area))
    rights = [r for r in rights if r in known]
    if not rights:
        raise ValidationError(_('Choose at least one right.'))
    rights = _with_view(rights)
    if target and target not in area_models(area):
        raise ValidationError(_('"%(target)s" is not protected by this area.') % {'target': target})
    profile = AreaProfile.objects.create(area=area, name=f'{user.username} · {target or "*"} · {uuid.uuid4().hex[:6]}',
                                         rights=rights, filters=filters or {}, private=True,
                                         tabs=[] if target else None, records='filtered' if filters else 'all')
    try:
        return grant_access(area, user, profile, hours, actor, request=request, notify=notify, target=target)
    except Exception:
        profile.delete()
        raise


def update_grant(grant, rights, actor, filters=None, request=None):
    """Change the rights / rows of an access entry (its private profile)."""
    area = grant.area
    if not _may_grant(actor, area):
        raise PermissionDenied
    known = set(rights_available(area))
    rights = [r for r in rights if r in known]
    if not rights:
        raise ValidationError(_('Choose at least one right.'))
    rights = _with_view(rights)
    profile = grant.profile
    if not profile.private:
        raise ValidationError(_('Revoke this access and grant it again.'))
    profile.rights, profile.filters = rights, filters or {}
    profile.records = 'filtered' if filters else 'all'
    profile.save()
    _log(PinEventAction.AREA_CHANGED, area, actor, user=grant.user, request=request,
         detail=f'{grant.target or "*"}: {", ".join(rights)}' + (f' | rows: {format_filters(filters)}' if filters else ''))
    clear_cache()


def grant_access(area, user, profile, hours, actor, request=None, notify=True, target=''):
    """Give ``user`` access. ``hours=None`` is permanent; otherwise 1..area.max_hours. Only owners grant."""
    if not _may_grant(actor, area):
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


#
# Groups: a named set of rights for one object type; the users granted through it are its members
#

WRITE_RIGHTS = ('add', 'change', 'delete')


def _with_view(rights):
    """Who may write must be able to read: writing rights bring ``view`` along."""
    rights = list(dict.fromkeys(rights))
    if set(rights) & set(WRITE_RIGHTS) and 'view' not in rights:
        rights.insert(0, 'view')
    return rights


def groups_of(area, target=None):
    query = AreaProfile.objects.filter(area=area, private=False).exclude(target='')
    return query.filter(target=target) if target else query


def group_members(group):
    now = timezone.now()
    return [g for g in AreaGrant.objects.filter(profile=group, revoked__isnull=True).select_related('user')
            if g.expires is None or g.expires > now]


def _clean_group_rights(area, rights):
    known = set(rights_available(area))
    rights = _with_view([r for r in rights if r in known])
    if not rights:
        raise ValidationError(_('Choose at least one right.'))
    return rights


def create_group(area, target, name, rights, actor, filters=None, request=None, records='unset'):
    rights = rights or ['view']  # a new group reads; what else it may do is ticked inside the group
    if not _may_grant(actor, area):
        raise PermissionDenied
    name = (name or '').strip()[:100]
    if not name:
        raise ValidationError(_('Write the name of the group.'))
    if target not in area_models(area):
        raise ValidationError(_('"%(target)s" is not protected by this area.') % {'target': target})
    if AreaProfile.objects.filter(area=area, target=target, private=False, name__iexact=name).exists():
        raise ValidationError(_('A group with this name exists.'))
    group = AreaProfile.objects.create(area=area, name=name, rights=_clean_group_rights(area, rights),
                                       filters=filters or {}, private=False, target=target, tabs=[],
                                       records='filtered' if filters else records)
    _log(PinEventAction.AREA_CHANGED, area, actor, request=request,
         detail=f'group {name} ({target}): {", ".join(group.rights)}')
    return group


def update_group(group, actor, name=None, rights=None, filters=None, request=None, allow_empty=False, denied=None):
    area = group.area
    if not _may_grant(actor, area) or group.private:
        raise PermissionDenied
    if name is not None:
        name = name.strip()[:100]
        if not name:
            raise ValidationError(_('Write the name of the group.'))
        if AreaProfile.objects.filter(area=area, target=group.target, private=False, name__iexact=name
                                      ).exclude(pk=group.pk).exists():
            raise ValidationError(_('A group with this name exists.'))
        group.name = name
    if rights is not None:
        group.rights = [] if (allow_empty and not rights) else _clean_group_rights(area, rights)
    if filters is not None:
        group.filters = filters
    if denied is not None:
        known = set(rights_available(area))
        group.denied = [r for r in dict.fromkeys(denied) if r in known]
    group.save()
    _log(PinEventAction.AREA_CHANGED, area, actor, request=request,
         detail=f'group {group.name} ({group.target}): {", ".join(group.rights) or "no access"}'
                + (f' | DENY: {", ".join(group.denied)}' if group.denied else ''))
    clear_cache()


def delete_group(group, actor, request=None):
    area = group.area
    if not _may_grant(actor, area) or group.private:
        raise PermissionDenied
    if group_members(group):
        raise ValidationError(_('The group has members. Remove them first.'))
    _log(PinEventAction.AREA_CHANGED, area, actor, request=request, detail=f'group {group.name} deleted')
    group.delete()
    clear_cache()


def add_member(group, user, hours, actor, request=None, notify=True):
    """
    Put ``user`` into the group. A user is in one group per object type: the others are left, so writing rights given
    later replace the reading ones, and leaving the last group means no access.
    """
    area = group.area
    if not _may_grant(actor, area) or group.private or not group.target:
        raise PermissionDenied
    now = timezone.now()
    for grant in AreaGrant.objects.filter(area=area, user=user, target=group.target, revoked__isnull=True
                                          ).exclude(profile=group):
        grant.revoked, grant.revoked_by_name = now, actor.username
        grant.save()
        _log(PinEventAction.AREA_REVOKED, area, actor, user=user, request=request,
             detail=f'moved to group {group.name}')
    existing = [g for g in group_members(group) if g.user_id == user.pk]
    if existing:
        return existing[0]
    return grant_access(area, user, group, hours, actor, request=request, notify=notify, target=group.target)


def revoke_grant(grant, actor, request=None):
    """Owners revoke; the user may end their own access."""
    if grant.revoked is not None:
        return
    if not (_may_grant(actor, grant.area) or actor.pk == grant.user_id):
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
    query = Q(area__owners__user=user)
    if is_keeper(user):
        query |= Q(area__isnull=True) | Q(area__owners__isnull=True)
    return AreaRequest.objects.filter(query, status=AreaRequestStatus.PENDING).exclude(
        user=user).distinct().select_related('area', 'user')


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
    first = not PolicyKeeper.objects.exists()
    keeper, created = PolicyKeeper.objects.get_or_create(user=user, defaults={'added_by_name': actor.username})
    if created:
        service.log_event(PinEventAction.KEEPER_ADDED, user=user, actor=actor, request=request)
        settings = service.get_settings()
        if first and not settings.default_deny:  # the first keeper switches the global protection on
            settings.default_deny = True
            settings.save()
            service.log_event(PinEventAction.DENY_ENABLED, actor=actor, request=request)
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
    if not _may_take(actor, area, target):
        raise ValidationError(_('"%(target)s" is sensitive or protected by another area: only a protection keeper '
                                'can put it in this one.') % {'target': target})
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
        contains = (contains or '').strip()[:200]
        if profile is None and mode != AreaFieldMode.HIDDEN:
            mode = ''
        if mode in ('', None):
            mode = 'default'
        if mode == 'default' and not contains:  # nothing of its own to remember: no rule at all
            if existing.delete()[0]:
                changed.append(f'{field}: default')
            continue
        if mode not in AreaFieldMode.values:
            raise ValidationError(_('Unknown mode.'))
        rule = existing.first()
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
    area = get_area(area)
    targets = targets_of(area) if area else []
    return render_denied(request, area, right, targets[0] if targets else None)


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
