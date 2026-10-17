"""
Field rules of the protected areas: what a profile sees and may change in an object, field by field.

Per profile, object type and field: ``hidden`` / ``read`` (read only) / ``write``; for a custom field also a text the
values must contain ("must include PRINTER"). A rule without a profile hides the field from everybody in the area,
owners included.

The rules are applied where NetBox shows or takes the data:

* custom fields: detail pages, forms, tables, REST API (values are never deleted: a hidden field keeps its data),
* model fields: forms (hidden = removed, read only = disabled), tables (columns), REST API (hidden / read only),
* the value filter ("must include"): detail pages, the drop-down of the form (and a check on save), REST API.

Not covered: the fixed fields of the detail page of an object (NetBox draws them by hand, model by model),
GraphQL, filters in lists (``?cf_name=…``), exports and the global search.
"""
import logging

from django.utils.translation import gettext

from . import areas
from .models import AreaFieldMode, AreaFieldRule

logger = logging.getLogger('netbox_user_pin')

RANK = {AreaFieldMode.HIDDEN: 0, AreaFieldMode.READ: 1, AreaFieldMode.WRITE: 2}
SKIP_FIELDS = {'id', 'created', 'last_updated', 'custom_field_data'}


class FieldPolicy:
    def __init__(self, default, modes, contains):
        self.default = default
        self.modes = modes
        self.contains = contains

    def mode(self, field):
        return self.modes.get(field, self.default)

    def hidden(self):
        return {name for name, mode in self.modes.items() if mode == AreaFieldMode.HIDDEN}

    def texts(self, field):
        return self.contains.get(field)


def _grant_default(rights):
    return AreaFieldMode.WRITE if {'add', 'change'} & set(rights) else AreaFieldMode.READ


def compute_policy(user, area, app_label, model):
    """The policy of ``user`` for the fields of one object type, or None when there are no rules at all."""
    target = f'{app_label}.{model}'
    rules = list(AreaFieldRule.objects.filter(area=area, target=target))
    if not rules:
        return None
    nobody = {r.field for r in rules if r.profile_id is None}
    modes, contains = {}, {}
    if areas._unrestricted(user, area):
        default = AreaFieldMode.WRITE
    else:
        grants = [g for g in areas.active_grants(user, area) if 'view' in g.profile.rights]
        if not grants:
            return FieldPolicy(AreaFieldMode.HIDDEN, {}, {})
        by_profile = {}
        for rule in rules:
            if rule.profile_id is not None:
                by_profile.setdefault(rule.profile_id, {})[rule.field] = rule
        defaults = {g.pk: _grant_default(g.profile.rights) for g in grants}
        default = max(defaults.values(), key=RANK.get)
        for field in {r.field for r in rules if r.profile_id is not None}:
            best, texts, unlimited = None, [], False
            for grant in grants:
                rule = by_profile.get(grant.profile_id, {}).get(field)
                mode = AreaFieldMode(rule.mode) if rule else defaults[grant.pk]
                if best is None or RANK[mode] > RANK[best]:
                    best = mode
                if mode != AreaFieldMode.HIDDEN:
                    if rule and rule.contains:
                        texts.append(rule.contains)
                    else:
                        unlimited = True
            if best != default:
                modes[field] = best
            if texts and not unlimited:
                contains[field] = texts
    for field in nobody:
        modes[field] = AreaFieldMode.HIDDEN
        contains.pop(field, None)
    return FieldPolicy(default, modes, contains)


def current_policy(app_label, model):
    """The policy for the user of the current request, or None (no area, no rules, not logged in)."""
    try:
        from netbox.context import current_request
        request = current_request.get()
    except Exception:
        return None
    user = getattr(request, 'user', None)
    if request is None or not getattr(user, 'is_authenticated', False) or not areas.active_areas():
        return None
    area = areas.area_for(app_label, model, package=app_label)
    if area is None:
        return None
    cache = request.__dict__.setdefault('_userpin_policies', {})
    key = (area.pk, app_label, model)
    if key not in cache:
        cache[key] = compute_policy(user, area, app_label, model)
    return cache[key]


def policy_of_model(model):
    meta = getattr(model, '_meta', None)
    return current_policy(meta.app_label, meta.model_name) if meta is not None else None


def matches(value, texts):
    """Does the (display of the) value contain one of the texts (case-insensitive)?"""
    shown = str(value).lower()
    return any(text.lower() in shown for text in texts)


def filter_value(value, texts):
    """Keep only what contains a text: one value -> value / None, a list -> the matching items."""
    if value in (None, '', []):
        return value
    if isinstance(value, (list, tuple, set)) or (hasattr(value, 'all') and not isinstance(value, str)):
        items = value.all() if hasattr(value, 'all') else value
        return [item for item in items if matches(item, texts)]
    return value if matches(value, texts) else None


#
# Lists of the fields of an object type (for the rules page)
#

def fields_of(app_label, model_name):
    """[(key, label, kind)]: the model fields, then the custom fields (kind 'field' / 'custom')."""
    from django.apps import apps
    model = apps.get_model(app_label, model_name)
    result = []
    for field in model._meta.get_fields():
        if field.auto_created and not field.concrete:
            continue
        if not (getattr(field, 'concrete', False) or getattr(field, 'many_to_many', False)):
            continue
        if field.name in SKIP_FIELDS or field.name.startswith('_'):
            continue
        result.append((field.name, str(getattr(field, 'verbose_name', field.name)).capitalize(), 'field'))
    if hasattr(model, 'tags') and not any(key == 'tags' for key, _l, _k in result):
        result.append(('tags', 'Tags', 'field'))
    try:
        from extras.models import CustomField
        for cf in CustomField.objects.get_for_model(model):
            result.append((f'cf:{cf.name}', str(cf.label or cf.name), 'custom'))
    except Exception:
        pass
    return result


#
# Hooks into NetBox
#

def install():
    """Install the hooks (once). Each one falls back to NetBox's own behaviour when no rule applies."""
    for installer in (_hook_detail, _hook_forms, _hook_tables, _hook_api):
        try:
            installer()
        except ImportError as exc:
            logger.warning('Field rules: a NetBox part was not found (%s); that layer is not installed.', exc)


def _once(owner, name, make):
    original = getattr(owner, name)
    if getattr(original, '_userpin', False):
        return
    wrapper = make(original)
    wrapper._userpin = True
    setattr(owner, name, wrapper)


def _hook_detail():
    from netbox.models.features import CustomFieldsMixin

    def get_custom_fields(original):
        def wrapper(self, *args, **kwargs):
            data = original(self, *args, **kwargs)
            policy = policy_of_model(type(self))
            if policy is None:
                return data
            result = {}
            for cf, value in data.items():
                key = f'cf:{cf.name}'
                if policy.mode(key) == AreaFieldMode.HIDDEN:
                    continue
                if (texts := policy.texts(key)):
                    value = filter_value(value, texts)
                result[cf] = value
            return result
        return wrapper

    def get_custom_fields_by_group(original):
        def wrapper(self, *args, **kwargs):
            groups = original(self, *args, **kwargs)
            policy = policy_of_model(type(self))
            if policy is None:
                return groups
            result = {}
            for group, fields in groups.items():
                kept = {}
                for cf, value in fields.items():
                    key = f'cf:{cf.name}'
                    if policy.mode(key) == AreaFieldMode.HIDDEN:
                        continue
                    if (texts := policy.texts(key)):
                        value = filter_value(value, texts)
                    kept[cf] = value
                if kept:
                    result[group] = kept
            return result
        return wrapper

    _once(CustomFieldsMixin, 'get_custom_fields', get_custom_fields)
    _once(CustomFieldsMixin, 'get_custom_fields_by_group', get_custom_fields_by_group)


def _hook_forms():
    from django import forms
    from django.core.exceptions import ValidationError
    from netbox.forms.mixins import CustomFieldsMixin

    def get_custom_fields(original):
        def wrapper(self, content_type):
            fields = original(self, content_type)
            policy = policy_of_model(content_type.model_class())
            if policy is None:
                return fields
            return [cf for cf in fields if policy.mode(f'cf:{cf.name}') != AreaFieldMode.HIDDEN]
        return wrapper

    def get_form_field(original):
        def wrapper(self, customfield):
            field = original(self, customfield)
            try:
                model = self._get_content_type().model_class()
            except Exception:
                model = getattr(self, 'model', None)
            policy = policy_of_model(model)
            if policy is None:
                return field
            key = f'cf:{customfield.name}'
            if policy.mode(key) == AreaFieldMode.READ:
                field.disabled, field.required = True, False
            if (texts := policy.texts(key)):
                if hasattr(field.widget, 'add_query_params'):
                    field.widget.add_query_params({'q': texts[0]})  # narrows the drop-down

                def must_include(value, texts=texts):
                    if value in (None, '', []):
                        return
                    items = value if isinstance(value, (list, tuple)) or hasattr(value, '__iter__') and not isinstance(
                        value, str) and not hasattr(value, 'pk') else [value]
                    if any(not matches(item, texts) for item in items):
                        raise ValidationError(gettext('Only values containing "%(text)s" are allowed.'),
                                              params={'text': ' / '.join(texts)})
                field.validators = list(field.validators) + [must_include]
            return field
        return wrapper

    def model_form_init(original):
        def wrapper(self, *args, **kwargs):
            original(self, *args, **kwargs)
            model = getattr(getattr(self, '_meta', None), 'model', None)
            policy = policy_of_model(model)
            if policy is None:
                return
            for name in list(self.fields):
                if name.startswith('cf_'):
                    continue  # custom fields are handled where they are built
                mode = policy.mode(name)
                if mode == AreaFieldMode.HIDDEN:
                    self.fields.pop(name)
                elif mode == AreaFieldMode.READ:
                    self.fields[name].disabled = True
                    self.fields[name].required = False
        return wrapper

    from netbox.forms.bulk_edit import NetBoxModelBulkEditForm
    from netbox.forms.bulk_import import NetBoxModelImportForm
    from netbox.forms.model_forms import NetBoxModelForm

    _once(CustomFieldsMixin, '_get_custom_fields', get_custom_fields)
    # every form class that builds its own custom field widgets (the list / filter forms are left alone)
    for owner in (CustomFieldsMixin, NetBoxModelForm, NetBoxModelBulkEditForm, NetBoxModelImportForm):
        if '_get_form_field' in owner.__dict__:
            _once(owner, '_get_form_field', get_form_field)
    _once(forms.models.BaseModelForm, '__init__', model_form_init)


def _hook_tables():
    from netbox.tables.tables import BaseTable

    def table_init(original):
        def wrapper(self, *args, **kwargs):
            model = getattr(getattr(type(self), 'Meta', None), 'model', None)
            policy = policy_of_model(model)
            if policy is not None:
                names = {f'cf_{name[3:]}' if name.startswith('cf:') else name for name in policy.hidden()}
                kwargs['exclude'] = tuple(kwargs.get('exclude') or ()) + tuple(sorted(names))
            original(self, *args, **kwargs)
        return wrapper

    _once(BaseTable, '__init__', table_init)


def _hook_api():
    from django.utils.functional import cached_property
    from extras.api.customfields import CustomFieldsDataField
    from netbox.api.serializers.base import BaseModelSerializer

    original_fields = BaseModelSerializer.__dict__['fields']
    if not getattr(original_fields, '_userpin', False):
        def fields(self):
            result = original_fields.func(self)
            meta = getattr(self, 'Meta', None)
            policy = policy_of_model(getattr(meta, 'model', None))
            if policy is not None:
                for name in list(result):
                    if name in ('id', 'url', 'display', 'display_url', 'custom_fields'):
                        continue
                    mode = policy.mode(name)
                    if mode == AreaFieldMode.HIDDEN:
                        result.pop(name)
                    elif mode == AreaFieldMode.READ:
                        result[name].read_only = True
                        result[name].required = False
            return result

        wrapped = cached_property(fields)
        wrapped.__set_name__(BaseModelSerializer, 'fields')
        wrapped.func._userpin = True
        wrapped._userpin = True
        BaseModelSerializer.fields = wrapped

    def get_custom_fields(original):
        def wrapper(self):
            fields = original(self)
            model = getattr(getattr(self.parent, 'Meta', None), 'model', None)
            policy = policy_of_model(model)
            if policy is None:
                return fields
            return [cf for cf in fields if policy.mode(f'cf:{cf.name}') != AreaFieldMode.HIDDEN]
        return wrapper

    def to_representation(original):
        def wrapper(self, obj):
            data = original(self, obj)
            model = getattr(getattr(self.parent, 'Meta', None), 'model', None)
            policy = policy_of_model(model)
            if policy is None:
                return data
            for key, texts in policy.contains.items():
                name = key[3:] if key.startswith('cf:') else None
                if name in data and data[name] not in (None, ''):
                    value = data[name]
                    if isinstance(value, list):
                        value = [v for v in value if matches(v.get('display', v) if isinstance(v, dict) else v, texts)] \
                            or None
                    elif isinstance(value, dict):
                        value = value if matches(value.get('display', value), texts) else None
                    else:
                        value = value if matches(value, texts) else None
                    data[name] = value
            return data
        return wrapper

    _once(CustomFieldsDataField, '_get_custom_fields', get_custom_fields)
    _once(CustomFieldsDataField, 'to_representation', to_representation)
