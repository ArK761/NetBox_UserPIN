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
        grants = [g for g in areas.active_grants(user, area, target) if 'view' in g.profile.rights]
        if not grants:
            return FieldPolicy(AreaFieldMode.HIDDEN, {}, {})
        by_profile = {}
        for rule in rules:
            if rule.profile_id is not None:
                by_profile.setdefault(rule.profile_id, {})[rule.field] = rule
        defaults = {g.pk: _grant_default(g.profile.rights) for g in grants}
        default = max(defaults.values(), key=RANK.get)
        for field in {r.field for r in rules if r.profile_id is not None}:
            best, texts, unlimited, explicit = None, [], False, []
            for grant in grants:
                rule = by_profile.get(grant.profile_id, {}).get(field)
                mode = AreaFieldMode(rule.mode) if rule else defaults[grant.pk]
                if rule and mode == AreaFieldMode.DEFAULT:
                    mode = defaults[grant.pk]  # "by rights": the rule only carries its text
                elif rule:
                    explicit.append(mode)
                if best is None or RANK[mode] > RANK[best]:
                    best = mode
                if mode != AreaFieldMode.HIDDEN:
                    if rule and entries(rule.contains):
                        texts.extend(entries(rule.contains))
                    else:
                        unlimited = True
            # a rule of any source that hides the field or makes it read only wins over a write of another source
            if AreaFieldMode.HIDDEN in explicit:
                best = AreaFieldMode.HIDDEN
            elif AreaFieldMode.READ in explicit and best == AreaFieldMode.WRITE:
                best = AreaFieldMode.READ
            if best != default:
                modes[field] = best
            if texts and not unlimited:
                contains[field] = texts
    for field in nobody:
        modes[field] = AreaFieldMode.HIDDEN
        contains.pop(field, None)
    return FieldPolicy(default, modes, contains)


import contextvars

_IN_FORM = contextvars.ContextVar('userpin_in_form', default=0)


def in_form():
    """True while a form is being built or validated."""
    return _IN_FORM.get() > 0


def related_label(model, key):
    """'app.model' of the objects a relation field (a model field or ``cf:<name>``) points at, or None."""
    try:
        if key.startswith('cf:'):
            from extras.models import CustomField
            cf = CustomField.objects.filter(name=key[3:], type__in=('object', 'multiobject')).first()
            ct = cf.related_object_type if cf else None
            return f'{ct.app_label}.{ct.model}' if ct else None
        field = model._meta.get_field(key)
    except Exception:  # noqa: BLE001 - no such field
        return None
    related = getattr(field, 'related_model', None)
    if getattr(field, 'is_relation', False) and related is not None and not field.auto_created:
        return f'{related._meta.app_label}.{related._meta.model_name}'
    return None


def pick_values(model, key, limit=500):
    """The existing values a condition "is one of" may choose from: names of the related objects or select choices."""
    from django.apps import apps
    try:
        if key.startswith('cf:'):
            from extras.models import CustomField
            cf = CustomField.objects.filter(name=key[3:]).select_related('choice_set').first()
            if cf is not None and cf.type in ('select', 'multiselect') and cf.choice_set_id:
                return [str(label) for _value, label in cf.choice_set.choices][:limit]
        label = related_label(model, key)
        if not label:
            return []
        related = apps.get_model(label)
        field = areas._name_field(related)
        if field is None:
            return []
        values = related.objects.order_by(field).values_list(field, flat=True).distinct()[:limit]
        return [str(v) for v in values if v not in (None, '')]
    except Exception:  # noqa: BLE001 - a list to choose from is a help, not a must
        logger.exception('Cannot list the values of %s', key)
        return []


def conditions_of(contains):
    """[(mark, value, label)] of a rule, for the page."""
    names = {'~': gettext('contains'), '^': gettext('starts with'), '=': gettext('is')}
    return [(line[0], line[1:], f'{names[line[0]]} {line[1:]}') for line in entries(contains)]


def _writable_fields(user):
    """(model, key, policy, texts): every field the user may write, in the types he holds a right to change."""
    from django.apps import apps
    from .models import AreaGrant
    if not getattr(user, 'is_authenticated', False):
        return
    entries = []  # (area, target, rights)
    for grant in AreaGrant.objects.filter(user=user, revoked__isnull=True).select_related('area', 'profile'):
        if grant.is_active and grant.target and grant.area in areas.active_areas():
            entries.append((grant.area, grant.target, set(grant.profile.rights)))
    for area in areas.active_areas():
        if areas.is_owner(user, area):
            entries += [(area, t, set(areas.GENERIC_RIGHTS)) for t in areas.area_models(area)]
    for area, target, rights in entries:
        if not {'add', 'change'} & rights:
            continue
        app_label, _dot, name = target.partition('.')
        try:
            model = apps.get_model(app_label, name)
        except LookupError:
            continue
        policy = compute_policy(user, area, app_label, name)
        for key, _label, _kind in fields_of(app_label, name):
            if (policy.mode(key) if policy else AreaFieldMode.WRITE) == AreaFieldMode.WRITE:
                yield model, key, (policy.texts(key) if policy else None)


def select_scope(user):
    """
    {'ipam.vlan': None | [texts]}: the objects the user may PICK in the relation fields he may write - all of the type
    (None) or only those whose name contains one of the texts of the field rule. Picking does not open the type: its
    pages stay closed, only the drop-down of the field is served.
    """
    scope = {}
    for model, key, texts in _writable_fields(user):
        related = related_label(model, key)
        if not related or (related in scope and scope[related] is None):
            continue
        scope[related] = None if not texts else sorted(set(scope.get(related) or []) | set(texts))
    return scope


def choice_set_ids(user):
    """The ids of the choice sets of the select custom fields the user may write: their values fill the drop-down."""
    ids = set()
    try:
        from extras.models import CustomField
        names = {key[3:] for _model, key, _texts in _writable_fields(user) if key.startswith('cf:')}
        if names:
            ids = set(CustomField.objects.filter(name__in=names, type__in=('select', 'multiselect'),
                                                 choice_set__isnull=False).values_list('choice_set_id', flat=True))
    except Exception:  # noqa: BLE001
        logger.exception('Cannot list the choice sets of the writable fields')
    return ids


def hidden_by_type(user):
    """{'app.model': {field names}}: the fields hidden from the user, for every protected object type."""
    result = {}
    if not getattr(user, 'is_authenticated', False) or areas.is_exempt(user):
        return result
    for area in areas.active_areas():
        for target in areas.targets_of(area):
            if '.' not in target:
                continue
            app_label, _dot, name = target.partition('.')
            policy = compute_policy(user, area, app_label, name)
            if policy is not None and policy.hidden():
                result[target] = {n[3:] if n.startswith('cf:') else n for n in policy.hidden()}
    return result


def current_policy(app_label, model):
    """The policy for the user of the current request, or None (no area, no rules, not logged in)."""
    try:
        from netbox.context import current_request
        request = current_request.get()
    except Exception:
        return None
    user = getattr(request, 'user', None)
    if request is None or not getattr(user, 'is_authenticated', False) or not areas.active_areas() \
            or areas.is_exempt(user):
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


# A field rule holds conditions on what may be picked, one per line: ``~text`` contains, ``^text`` starts with,
# ``=text`` is exactly (one of the existing values); a line without a mark (rules before 2.0.5) means "contains".
OPERATORS = (('~', 'contains'), ('^', 'starts with'), ('=', 'is one of'))


def entries(contains):
    """The conditions of a rule as marked lines (``['~PRINTER', '=Office']``)."""
    result = []
    for line in str(contains or '').splitlines():
        line = line.strip()
        if not line:
            continue
        result.append(line if line[0] in '~^=' and len(line) > 1 else f'~{line}')
    return result


def join_entries(lines):
    """Marked lines -> the stored text (duplicates and empty values dropped, order kept)."""
    seen, result = set(), []
    for line in lines:
        line = str(line or '').strip()
        if not line:
            continue
        line = line if line[0] in '~^=' and len(line) > 1 else f'~{line}'
        if line.lower() not in seen:
            seen.add(line.lower())
            result.append(line)
    return '\n'.join(result)


def describe(texts):
    """'contains PRINTER / is Office' for messages."""
    names = {'~': gettext('contains'), '^': gettext('starts with'), '=': gettext('is')}
    return ' / '.join(f'{names[t[0]]} "{t[1:]}"' for t in entries('\n'.join(texts)))


def _one(shown, line):
    mark, text = line[0], line[1:].lower()
    if mark == '^':
        return shown.startswith(text)
    if mark == '=':
        return shown == text
    return text in shown


def matches(value, texts):
    """Does the (display of the) value fit one of the conditions (case-insensitive)?"""
    shown = str(value).strip().lower()
    return any(_one(shown, line) for line in entries('\n'.join(texts)))


def name_query(field, texts):
    """A Q that keeps the objects whose ``field`` fits one of the conditions."""
    from django.db.models import Q
    lookup = {'~': 'icontains', '^': 'istartswith', '=': 'iexact'}
    query = Q()
    for line in entries('\n'.join(texts)):
        query |= Q(**{f'{field}__{lookup[line[0]]}': line[1:]})
    return query


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
    for installer in (_hook_detail, _hook_forms, _hook_tables, _hook_api, _hook_paths):
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

    # The fixed fields of a detail page are drawn by the template of each model: a hidden one is emptied on the
    # object shown (a read-only page: edit and delete views are no ObjectView and never save such an object).
    from netbox.views.generic import ObjectView

    def get_object(original):
        def wrapper(self, **kwargs):
            instance = original(self, **kwargs)
            request = getattr(self, 'request', None)
            if request is None or request.method != 'GET' or instance is None:
                return instance
            policy = policy_of_model(type(instance))
            if policy is None:
                return instance
            for field in type(instance)._meta.concrete_fields:
                if field.primary_key or field.name in SKIP_FIELDS or field.name.startswith('_'):
                    continue
                if policy.mode(field.name) == AreaFieldMode.HIDDEN:
                    try:
                        setattr(instance, field.name, None)
                    except Exception:  # a field that cannot be emptied stays as it is
                        logger.debug('Cannot hide %s on the detail page', field.name)
            return instance
        return wrapper

    _once(ObjectView, 'get_object', get_object)


def _must_include(texts):
    from django.core.exceptions import ValidationError

    def validator(value, texts=texts):
        if value in (None, '', []):
            return
        items = value if isinstance(value, (list, tuple)) or (hasattr(value, '__iter__') and not isinstance(
            value, str) and not hasattr(value, 'pk')) else [value]
        if any(not matches(item, texts) for item in items):
            raise ValidationError(gettext('Only these values are allowed: %(text)s.'),
                                  params={'text': describe(texts)})
    return validator


class _GoneWidget:
    """A widget that draws nothing (built on first use, so that Django's forms are imported lazily)."""
    _cls = None

    def __new__(cls):
        if cls._cls is None:
            from django import forms

            class Gone(forms.Widget):
                is_hidden = True
                input_type = 'hidden'

                def render(self, name, value, attrs=None, renderer=None):
                    return ''

                def value_from_datadict(self, data, files, name):
                    return None

            cls._cls = Gone
        return cls._cls()


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
                if hasattr(field.widget, 'add_query_params') and len(texts) == 1 and texts[0][0] == '~':
                    field.widget.add_query_params({'q': texts[0][1:]})  # narrows the drop-down (the server does too)

                def must_include(value, texts=texts):
                    if value in (None, '', []):
                        return
                    items = value if isinstance(value, (list, tuple)) or hasattr(value, '__iter__') and not isinstance(
                        value, str) and not hasattr(value, 'pk') else [value]
                    if any(not matches(item, texts) for item in items):
                        raise ValidationError(gettext('Only these values are allowed: %(text)s.'),
                                              params={'text': describe(texts)})
                field.validators = list(field.validators) + [must_include]
            return field
        return wrapper

    def apply_form_policy(form):
        """Hide the hidden fields and disable the read-only ones - when the form is complete, not inside its constructors
        (NetBox's own mixins reach for fields such as ``tags`` after the base class has been initialised)."""
        model = getattr(getattr(form, '_meta', None), 'model', None)
        policy = policy_of_model(model)
        if policy is None:
            return
        for name in list(form.fields):
            if name.startswith('cf_'):
                continue  # custom fields are handled where they are built
            mode = policy.mode(name)
            if mode == AreaFieldMode.HIDDEN:
                # not removed: the templates of NetBox draw some fields by name (render_field form.description) and
                # a missing one breaks the page. The field stays, switched off and drawn as nothing - its value is
                # neither shown nor taken from the request (a disabled field keeps what the object has).
                field = form.fields[name]
                field.disabled, field.required, field.label, field.help_text = True, False, '', ''
                field.widget = _GoneWidget()
            elif mode == AreaFieldMode.READ:
                form.fields[name].disabled = True
                form.fields[name].required = False
            elif (texts := policy.texts(name)) and hasattr(form.fields[name], 'queryset'):
                form.fields[name].validators = list(form.fields[name].validators) + [_must_include(texts)]

    from django.forms.forms import DeclarativeFieldsMetaclass
    if not getattr(DeclarativeFieldsMetaclass, '_userpin', False):
        def call(cls, *args, **kwargs):
            token = _IN_FORM.set(_IN_FORM.get() + 1)
            try:
                form = type.__call__(cls, *args, **kwargs)
            finally:
                _IN_FORM.reset(token)
            try:
                apply_form_policy(form)
            except Exception:  # noqa: BLE001 - a rule that cannot be applied must not break the page
                logger.exception('Cannot apply the field rules to %s', cls.__name__)
                raise
            return form

        DeclarativeFieldsMetaclass.__call__ = call
        DeclarativeFieldsMetaclass._userpin = True

        from django.forms.forms import BaseForm

        def full_clean(original):
            def wrapper(self):
                token = _IN_FORM.set(_IN_FORM.get() + 1)
                try:
                    return original(self)
                finally:
                    _IN_FORM.reset(token)
            return wrapper

        _once(BaseForm, 'full_clean', full_clean)

    from netbox.forms.bulk_edit import NetBoxModelBulkEditForm
    from netbox.forms.bulk_import import NetBoxModelImportForm
    from netbox.forms.model_forms import NetBoxModelForm

    _once(CustomFieldsMixin, '_get_custom_fields', get_custom_fields)
    # every form class that builds its own custom field widgets (the list / filter forms are left alone)
    for owner in (CustomFieldsMixin, NetBoxModelForm, NetBoxModelBulkEditForm, NetBoxModelImportForm):
        if '_get_form_field' in owner.__dict__:
            _once(owner, '_get_form_field', get_form_field)


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


def _hook_paths():
    """The other ways to the values: bulk edit, exports, list filters, search, writing through the REST API."""
    from django.core.exceptions import PermissionDenied
    from django.db.models import Q
    from django_filters import FilterSet
    from netbox.forms.bulk_edit import NetBoxModelBulkEditForm
    from netbox.views.generic import ObjectListView

    # bulk edit: a field the group does not see or only reads is not in the form, so it cannot be set for many objects
    def bulk_edit_init(original):
        def wrapper(self, *args, **kwargs):
            original(self, *args, **kwargs)
            policy = policy_of_model(getattr(self, 'model', None))
            if policy is None:
                return
            for name in list(self.fields):
                if name in ('pk', 'changelog_message', 'background_job'):
                    continue
                key = 'tags' if name in ('add_tags', 'remove_tags') else (f'cf:{name[3:]}' if name.startswith('cf_')
                                                                         else name)
                if policy.mode(key) in (AreaFieldMode.HIDDEN, AreaFieldMode.READ):
                    self.fields.pop(name)
                    getattr(self, 'custom_fields', {}).pop(name, None)
        return wrapper

    _once(NetBoxModelBulkEditForm, '__init__', bulk_edit_init)

    # exports: the table export has no hidden columns; the YAML and the export templates show every field
    def list_get(original):
        def wrapper(self, request, *args, **kwargs):
            if 'export' in request.GET and request.GET['export'] != 'table':
                policy = policy_of_model(self.queryset.model)
                if policy is not None and policy.hidden():
                    raise PermissionDenied('This export would show fields hidden from you.')
            return original(self, request, *args, **kwargs)
        return wrapper

    _once(ObjectListView, 'get', list_get)

    # list filters: a hidden field cannot be asked about (?description=secret) and the fulltext "q" reads them all
    def filterset_init(original):
        def wrapper(self, *args, **kwargs):
            original(self, *args, **kwargs)
            policy = policy_of_model(getattr(getattr(self, '_meta', None), 'model', None))
            if policy is None or not policy.hidden():
                return
            hidden = policy.hidden()
            bare = {n[3:] for n in hidden if n.startswith('cf:')}
            for name in list(self.filters):
                field = (getattr(self.filters[name], 'field_name', None) or name).split('__')[0]
                if name == 'q' or field in hidden or (name.startswith('cf_') and name[3:].split('__')[0] in bare):
                    self.filters.pop(name)
        return wrapper

    _once(FilterSet, '__init__', filterset_init)

    # search: no hit on a hidden field
    try:
        from netbox.search.backends import CachedValueSearchBackend
    except ImportError:
        CachedValueSearchBackend = None
    if CachedValueSearchBackend is not None:
        def search(original):
            def wrapper(self, value, user=None, *args, **kwargs):
                result = original(self, value, user, *args, **kwargs)
                hidden = hidden_by_type(user) if user is not None else {}
                if not hidden:
                    return result
                if not hasattr(result, 'exclude'):  # the backend hands over a list of hits
                    return [hit for hit in result if hit.field not in hidden.get(
                        f'{hit.object_type.app_label}.{hit.object_type.model}', ())]
                unwanted = Q()
                for target, names in hidden.items():
                    app_label, _dot, model = target.partition('.')
                    unwanted |= Q(object_type__app_label=app_label, object_type__model=model, field__in=names)
                return result.exclude(unwanted)
            return wrapper

        _once(CachedValueSearchBackend, 'search', search)

    # REST API: a read-only custom field is not written, a field with a text rule takes only values with the text
    from extras.api.customfields import CustomFieldsDataField
    from rest_framework.exceptions import ValidationError as ApiValidationError

    def to_internal_value(original):
        def wrapper(self, data):
            model = getattr(getattr(self.parent, 'Meta', None), 'model', None)
            policy = policy_of_model(model)
            if policy is not None and isinstance(data, dict):
                instance = getattr(self.parent, 'instance', None)
                current = getattr(instance, 'custom_field_data', None) or {}
                errors = {}
                for name, value in data.items():
                    key = f'cf:{name}'
                    mode = policy.mode(key)
                    if mode in (AreaFieldMode.READ, AreaFieldMode.HIDDEN) and current.get(name) != value:
                        errors[name] = gettext('This field is read only for you.')
                    elif (texts := policy.texts(key)) and value not in (None, '', []) and not (
                            matches(value, texts) if not isinstance(value, (list, tuple)) else
                            all(matches(v, texts) for v in value)):
                        errors[name] = gettext('Only these values are allowed: %(text)s.') % {
                            'text': describe(texts)}
                if errors:
                    raise ApiValidationError(errors)
            return original(self, data)
        return wrapper

    _once(CustomFieldsDataField, 'to_internal_value', to_internal_value)
