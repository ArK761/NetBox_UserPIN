"""Pages of the protected areas (administration by the owners, requests, my access)."""
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied, ValidationError
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext as _
from django.views import View

from . import areas, fieldrules, roles, service
from .forms import ACCESS_HOURS
from .forms import (
    AccessRequestForm, GroupForm, GroupMemberForm, AreaDecideForm, AreaForm, AreaGrantForm, AreaOwnerForm, AreaProfileForm, AreaRequestForm, AreaTargetForm,
    KeeperForm,
)
from .mixins import PinRequiredMixin, area_gate
from .models import (
    AreaFieldRule, AreaGrant, AreaProfile, AreaRequest, AreaRequestStatus, PinEventAction, ProtectedArea,
)
from .views import ADMIN_SCOPE, _errors, _next_url, _step_up_context

__all__ = ('GroupView', 'AccessRequestView', 'RequestDecideView', 'AreaFieldsView', 'AreaListView', 'AreaRequestView', 'AreaView', 'MyAccessView')


class AreaViewMixin(LoginRequiredMixin, PinRequiredMixin):
    """Logged in, allowed to use a PIN and unlocked; 2FA (if the user has it) is asked once in a while only."""
    pin_scope = ADMIN_SCOPE
    idle_to_access = False  # the overview page: whoever has nothing to administer is sent to what he may do

    def dispatch(self, request, *args, **kwargs):
        if self.idle_to_access and request.user.is_authenticated and not areas.administers_any(request.user):
            # nothing to administer: no PIN to set up, a pointer to what the user is allowed instead
            messages.info(request, _('You do not administer any protected area. Here is what you are allowed.'))
            return redirect('plugins:netbox_user_pin:my_access')
        if request.user.is_authenticated and (response := area_gate(request)) is not None:
            return response
        return super().dispatch(request, *args, **kwargs)


def _target_label(target):
    """'dcim.device' -> 'DCIM › Device'; 'dcim' -> 'DCIM (everything)'."""
    from django.apps import apps
    app_label, _dot, model = target.partition('.')
    try:
        config = apps.get_app_config(app_label)
        if not model:
            return _('%(app)s (everything)') % {'app': config.verbose_name}
        return f'{config.verbose_name} › {str(apps.get_model(app_label, model)._meta.verbose_name).capitalize()}'
    except LookupError:
        return target


def _grant_rows(area, grant):
    """What an access entry allows, for the table."""
    profile = grant.profile
    return {
        'target': _target_label(grant.target) if grant.target else _('Everything in this area'),
        'rights': [areas.right_label(area, r) for r in profile.rights],
        'rows': areas.format_filters(profile.filters).split(': ', 1)[-1] if profile.filters else '',
        'name': '' if profile.private else profile.name,
    }


def _tree(user):
    """[{name, label, rows}]: the apps and object types that are protected, with their groups and members."""
    from django.apps import apps
    mapping, app_map = {}, {}
    info = {}
    for area in ProtectedArea.objects.all():
        if not areas.can_see(user, area):
            continue  # who owns what and who is a member is for the owners and the keepers only
        groups = []
        for group in areas.groups_of(area):
            groups.append({'name': group.name, 'target': group.target,
                           'members': [g.user.username for g in areas.group_members(group)]})
        info[area.pk] = {
            'owners': [o.username for o in areas.owners(area)],
            'users': sum(1 for g in area.grants.all() if g.is_active),
            'groups': groups,
            'individual': [g.user.username for g in area.grants.all() if g.is_active and g.profile.private],
        }
        for target in areas.targets_of(area):
            (mapping if '.' in target else app_map)[target] = area
    tree = []
    for config in sorted(apps.get_app_configs(), key=lambda c: str(c.verbose_name).lower()):
        if config.label in areas.NEVER:
            continue
        rows = []
        for model in sorted((m for m in config.get_models() if not m._meta.auto_created and not m._meta.proxy),
                            key=lambda m: str(m._meta.verbose_name).lower()):
            target = f'{config.label}.{model._meta.model_name}'
            area = mapping.get(target) or app_map.get(config.label)
            if area is None:
                continue
            data = info[area.pk]
            rows.append({
                'target': target, 'label': str(model._meta.verbose_name).capitalize(), 'area': area,
                'owners': data['owners'], 'users': data['users'],
                'groups': [g for g in data['groups'] if g['target'] == target],
                'individual': data['individual'],
            })
        if rows:
            tree.append({'label': config.label, 'name': str(config.verbose_name), 'rows': rows})
    return tree


def _chosen_users(request, queryset=None):
    """The users picked in a multi-select (field ``users``; ``user`` still works): active accounts only."""
    from django.contrib.auth import get_user_model
    ids = [i for i in request.POST.getlist('users') + request.POST.getlist('user') if str(i).isdigit()]
    users = get_user_model().objects.filter(pk__in=ids, is_active=True)
    return list(users if queryset is None else users.filter(pk__in=queryset.values('pk')))


def _user_choices(queryset):
    return [(u.pk, service.user_label(u)) for u in queryset.order_by('username')]


def _all_user_choices():
    from django.contrib.auth import get_user_model
    return _user_choices(get_user_model().objects.filter(is_active=True))


def _owner_choices():
    """Every active account with what he meets for owning an area (the eligible ones first)."""
    from django.contrib.auth import get_user_model
    rows = []
    for user in get_user_model().objects.filter(is_active=True).order_by('username'):
        checks = areas.owner_requirements(user)
        rows.append({'pk': user.pk, 'label': service.user_label(user), 'checks': checks,
                     'ok': all(ok for _text, ok in checks)})
    return sorted(rows, key=lambda r: (not r['ok'], r['label'].lower()))


def _status(area):
    """(code, label) of what the area does now."""
    if area in areas.active_areas():
        return 'ok', _('Protecting')
    if area.plugin:
        return 'off', _('Off (the plugin integration is not switched on)')
    if not area.enabled:
        return 'off', _('Off (deactivated by the owners)')
    return 'off', _('Off ("Protect areas and objects" is not switched on in the settings)')


class AreaListView(AreaViewMixin, View):
    idle_to_access = True
    template_name = 'netbox_user_pin/areas.html'

    def _render(self, request, form=None):
        areas.sync_plugin_areas()
        core = areas._stand_in(request.user)
        queryset = ProtectedArea.objects.filter(pk__in=[a.pk for a in ProtectedArea.objects.all()
                                                        if areas.can_see(request.user, a)])
        waiting_list = list(areas.pending_requests_for(request.user))
        rows = []
        for area in queryset.distinct().order_by('name'):
            code, label = _status(area)
            rows.append({
                'area': area, 'status': code, 'status_label': label,
                'owners': list(areas.owners(area)), 'grants': sum(1 for g in area.grants.all() if g.is_active),
                'pending': area.requests.filter(status=AreaRequestStatus.PENDING).count(),
                'mine': areas.is_owner(request.user, area), 'targets': areas.targets_of(area),
            })
        return render(request, self.template_name, {
            'rows': rows, 'is_core': core, 'form': form or AreaForm(create=True), 'tree': _tree(request.user),
            'add_form': AreaTargetForm(exclude=[t for a in ProtectedArea.objects.all() for t in areas.targets_of(a)]),
            'waiting': len(waiting_list), 'waiting_list': waiting_list,
            'deny_on': service.get_settings().default_deny, 'keepers': areas.keepers(),
            'is_keeper': areas.is_keeper(request.user), 'can_keepers': areas.can_manage_keepers(request.user),
            'exceptions': areas.exceptions() if areas.is_keeper(request.user) else [],
            'exception_users': [(pk, label) for pk, label in _all_user_choices()
                                if pk not in {k.pk for k in areas.keepers()}] if areas.is_keeper(request.user) else [],
            'denied_view': service.get_settings().denied_view, 'allow_requests': service.get_settings().allow_requests,
            'allow_own_tokens': service.get_settings().allow_own_tokens,
            'keeper_form': KeeperForm(),
            'settings': service.get_settings(), **_step_up_context(request),
        })

    def get(self, request):
        return self._render(request)

    def post(self, request):
        action = request.POST.get('action')
        from django.contrib.auth import get_user_model
        try:
            if action == 'exception-add':
                from django.contrib.auth import get_user_model
                from django.utils.dateparse import parse_datetime
                end = None
                if request.POST.get('expires'):
                    end = parse_datetime(request.POST['expires'])
                    if end is None:
                        raise ValidationError(_('Write the end as a date and a time.'))
                    if timezone.is_naive(end):
                        end = timezone.make_aware(end)
                user = get_object_or_404(get_user_model(), pk=request.POST.get('user') or 0)
                areas.add_exception(user, request.user, end, request.POST.get('note', ''), request=request)
                messages.success(request, _('The exception is set: %(user)s works with the permissions of NetBox.')
                                 % {'user': user.username})
                return redirect('plugins:netbox_user_pin:areas')
            if action == 'exception-remove':
                from django.contrib.auth import get_user_model
                areas.remove_exception(get_object_or_404(get_user_model(), pk=request.POST.get('pk') or 0),
                                       request.user, request=request)
                messages.success(request, _('The exception was taken away: the protection applies to him again.'))
                return redirect('plugins:netbox_user_pin:areas')
            if action == 'visibility':
                areas.set_visibility(request.user, request.POST.get('denied_view', 'doors'),
                                     request.POST.get('allow_requests') == 'on',
                                     request.POST.get('allow_own_tokens') == 'on', request=request)
                messages.success(request, _('Saved.'))
                return redirect('plugins:netbox_user_pin:areas')
            if action == 'create':
                if not areas._stand_in(request.user):
                    raise PermissionDenied
                form = AreaForm(request.POST, create=True)
                if not form.is_valid():
                    return self._render(request, form=form)
                data = form.cleaned_data
                area = areas.create_area(data['name'], areas.parse_targets(data['target']), [], request.user,
                                         data['description'], data['max_hours'], request=request)
                messages.success(request, _('Area "{name}" created. Appoint its owners now - until then only the '
                                            'master has access to it.').format(name=area.name))
                return redirect('plugins:netbox_user_pin:area', pk=area.pk)
            if action == 'unprotect':
                area = get_object_or_404(ProtectedArea, pk=request.POST.get('pk'))
                areas.delete_area(area, request.user, request=request)
                messages.success(request, _('The protection was removed.'))
                return redirect('plugins:netbox_user_pin:areas')
            if action == 'protect':
                if not areas._stand_in(request.user):
                    raise PermissionDenied
                target = request.POST.get('target', '')
                if not target:
                    raise ValidationError(_('Choose an app or an object type.'))
                app_label, _dot, model = target.partition('.')
                from django.apps import apps as django_apps
                try:
                    django_apps.get_app_config(app_label)
                    if model:
                        django_apps.get_model(app_label, model)
                except LookupError:
                    raise ValidationError(_('Unknown object type.'))
                area = areas.area_for(app_label, model or None, package=app_label)
                if area is None:
                    area = areas.create_area(areas.target_label(target), [target], [], request.user,
                                             request=request)
                    messages.success(request, _('"{name}" is protected now. Appoint its owners; until then only the '
                                                'protection keepers see it.').format(name=area.name))
                return redirect('plugins:netbox_user_pin:area', pk=area.pk)
            if action == 'keeper-add':
                form = KeeperForm(request.POST)
                if form.is_valid():
                    areas.add_keeper(form.cleaned_data['user'], request.user, request=request)
                    messages.success(request, _('Protection keeper appointed.'))
            elif action == 'keeper-remove':
                areas.remove_keeper(get_object_or_404(get_user_model(), pk=request.POST.get('pk')), request.user,
                                    request=request)
                messages.success(request, _('Protection keeper removed.'))
            elif action in ('deny-on', 'deny-off'):
                areas.set_default_deny(action == 'deny-on', request.user, request=request)
                messages.success(request, _('Everything not allowed is now denied.') if action == 'deny-on'
                                 else _('"Deny everything not allowed" is switched off.'))
            else:
                raise PermissionDenied
        except ValidationError as exc:
            _errors(request, exc)
        return redirect('plugins:netbox_user_pin:areas')


class AreaView(AreaViewMixin, View):
    template_name = 'netbox_user_pin/area.html'

    def _area(self, request, pk):
        area = get_object_or_404(ProtectedArea, pk=pk)
        if not areas.can_see(request.user, area):
            raise PermissionDenied
        return area

    def _render(self, request, area, **forms):
        code, label = _status(area)
        mine = areas.is_owner(request.user, area)
        grants = list(area.grants.select_related('user', 'profile'))
        pending = list(area.requests.filter(status=AreaRequestStatus.PENDING).select_related('user'))
        targets = areas.targets_of(area)
        single = targets[0] if len(targets) == 1 and '.' in targets[0] else ''
        return render(request, self.template_name, {
            'heading': _target_label(single) if single else area.name, 'single_target': single,
            'area': area, 'status': code, 'status_label': label, 'targets': targets,
            'owners': list(areas.owners(area)), 'is_owner': mine,
            'owner_rows': [(u, (mine and area.owners.count() > 1) or areas.is_keeper(request.user))
                           for u in areas.owners(area)], 'can_manage': areas.can_manage(request.user, area),
            'bootstrap': not area.owners.exists(),
            'active_grants': [(g, _grant_rows(area, g)) for g in grants if g.is_active],
            'old_grants': [g for g in grants if not g.is_active][:15],
            'pending': [(r, AreaDecideForm(area=area)) for r in pending],
            'area_form': forms.get('area_form') or AreaForm(plugin=area.plugin, initial={
                'name': area.name, 'description': area.description, 'max_hours': area.max_hours,
                'enabled': area.enabled,
                'denied_view': {None: 'follow', True: 'hide', False: 'show'}[area.hide_denied]}),
            'target_form': AreaTargetForm(exclude=areas.targets_of(area)),
            'target_labels': [(t, _target_label(t)) for t in areas.targets_of(area)],
            'owner_form': AreaOwnerForm(), 'group_blocks': self._group_blocks(area),
            'owner_choices': _owner_choices(),
            'group_form': forms.get('group_form') or GroupForm(area=area), 'member_form': GroupMemberForm(),
            'grant_form': forms.get('grant_form') or AreaGrantForm(area=area),
            'rights': [(r, areas.right_label(area, r)) for r in areas.rights_available(area)],
            'settings': service.get_settings(), **_step_up_context(request),
        })

    @staticmethod
    def _group_blocks(area):
        blocks = {}
        for group in areas.groups_of(area):
            blocks.setdefault(group.target, []).append({
                'group': group, 'rights': [areas.right_label(area, r) for r in group.rights],
                'rights_set': set(group.rights), 'members': areas.group_members(group),
                'tabs': [dict(t, allowed=group.tabs is None or t['name'] in group.tabs)
                         for t in areas.tabs_of(group.target) if not t['plugin']]})
        return [{'target': t, 'label': _target_label(t), 'groups': gs} for t, gs in sorted(blocks.items())]

    def get(self, request, pk):
        return self._render(request, self._area(request, pk))

    def post(self, request, pk):
        area = self._area(request, pk)
        action = request.POST.get('action')
        from django.contrib.auth import get_user_model
        User = get_user_model()
        try:
            if action == 'update':
                form = AreaForm(request.POST, plugin=area.plugin)
                if not form.is_valid():
                    return self._render(request, area, area_form=form)
                data = form.cleaned_data
                areas.update_area(area, request.user, name=data['name'], description=data['description'],
                                  enabled=data.get('enabled'), max_hours=data['max_hours'], request=request,
                                  hide_denied={'follow': None, 'show': False, 'hide': True}.get(
                                      data.get('denied_view') or 'follow'))
                messages.success(request, _('Saved.'))
            elif action == 'delete':
                areas.delete_area(area, request.user, request=request)
                messages.success(request, _('Area deleted.'))
                return redirect('plugins:netbox_user_pin:areas')
            elif action == 'target-add':
                form = AreaTargetForm(request.POST, exclude=areas.targets_of(area))
                if form.is_valid():
                    areas.add_target(area, form.cleaned_data['target'], request.user, request=request)
                    messages.success(request, _('Object type added.'))
                else:
                    messages.error(request, _('Choose an object type.'))
            elif action == 'target-remove':
                areas.remove_target(area, request.POST.get('target', ''), request.user, request=request)
                messages.success(request, _('Object type removed.'))
            elif action == 'owner-add':
                chosen = _chosen_users(request)
                if not chosen:
                    messages.error(request, _('Choose a user.'))
                if chosen:
                    added, problems = areas.add_owners(area, chosen, request.user, request=request)
                    for user in added:
                        messages.success(request, _('Owner added: {name}').format(name=user.username))
                    for exc in problems:
                        _errors(request, exc)
            elif action == 'owner-remove':
                areas.remove_owner(area, get_object_or_404(User, pk=request.POST.get('pk')), request.user,
                                   request=request)
                messages.success(request, _('Owner removed.'))
            elif action == 'profile-save':
                form = AreaProfileForm(request.POST, area=area)
                if not form.is_valid():
                    return self._render(request, area, profile_form=form)
                profile = AreaProfile.objects.filter(area=area, pk=request.POST.get('pk') or 0).first()
                areas.save_profile(area, form.cleaned_data['name'], form.cleaned_data['rights'], request.user,
                                   profile=profile, request=request, filters=form.cleaned_data['filters'])
                messages.success(request, _('Profile saved.'))
            elif action == 'profile-delete':
                areas.delete_profile(get_object_or_404(AreaProfile, pk=request.POST.get('pk'), area=area),
                                     request.user, request=request)
                messages.success(request, _('Profile deleted.'))
            elif action == 'group-create':
                form = GroupForm(request.POST, area=area)
                if not form.is_valid():
                    return self._render(request, area, group_form=form)
                group = areas.create_group(area, form.cleaned_data['target'], form.cleaned_data['name'], None,
                                           request.user, request=request)
                messages.success(request, _('Group created. Set what it may do and add its users.'))
                return redirect('plugins:netbox_user_pin:group', pk=area.pk, gid=group.pk)
            elif action == 'group-update':
                group = get_object_or_404(AreaProfile, pk=request.POST.get('pk'), area=area, private=False)
                areas.update_group(group, request.user, name=request.POST.get('name', group.name),
                                   rights=request.POST.getlist('rights'), request=request)
                if request.POST.get('tabs_form'):
                    areas.set_group_tabs(group, [k[5:] for k in request.POST if k.startswith('tab__')],
                                         request.user, request=request)
                messages.success(request, _('Saved.'))
            elif action == 'group-delete':
                areas.delete_group(get_object_or_404(AreaProfile, pk=request.POST.get('pk'), area=area,
                                                     private=False), request.user, request=request)
                messages.success(request, _('Group deleted.'))
            elif action == 'member-add':
                group = get_object_or_404(AreaProfile, pk=request.POST.get('pk'), area=area, private=False)
                chosen = _chosen_users(request)
                if not chosen:
                    messages.error(request, _('Choose a user.'))
                for user in chosen:
                    areas.add_member(group, user, None, request.user, request=request)
                if chosen:
                    messages.success(request, _('Added to the group.'))
            elif action == 'grant':
                form = AreaGrantForm(request.POST, area=area)
                if not form.is_valid():
                    return self._render(request, area, grant_form=form)
                data = form.cleaned_data
                areas.grant_custom(area, data['user'], data['target'], data['rights'], data['hours'] or None,
                                   request.user, filters=data['filters'], request=request)
                messages.success(request, _('Access granted.'))
            elif action == 'grant-edit':
                grant = get_object_or_404(AreaGrant, pk=request.POST.get('pk'), area=area)
                form = AreaDecideForm(request.POST, area=area)
                if not form.is_valid():
                    messages.error(request, _('The rights or the rows are not valid.'))
                else:
                    areas.update_grant(grant, form.cleaned_data['rights'], request.user,
                                       filters=form.cleaned_data['filters'], request=request)
                    messages.success(request, _('Saved.'))
            elif action == 'revoke':
                areas.revoke_grant(get_object_or_404(AreaGrant, pk=request.POST.get('pk'), area=area),
                                   request.user, request=request)
                messages.success(request, _('Access revoked.'))
            elif action in ('approve', 'deny'):
                req = get_object_or_404(AreaRequest, pk=request.POST.get('pk'), area=area)
                if action == 'deny':
                    areas.decide_request(req, request.user, False, request=request)
                    messages.success(request, _('Request denied.'))
                else:
                    form = AreaDecideForm(request.POST, area=area)
                    if not form.is_valid():
                        messages.error(request, _('Choose the rights and the duration.'))
                    else:
                        data = form.cleaned_data
                        areas.decide_request(req, request.user, True, hours=data['hours'] or None, request=request,
                                             rights=data['rights'], target=data['target'])
                        messages.success(request, _('Access granted.'))
            else:
                raise PermissionDenied
        except ValidationError as exc:
            _errors(request, exc)
        return redirect('plugins:netbox_user_pin:area', pk=area.pk)


class AreaFieldsView(AreaViewMixin, View):
    """Field rules of one profile (or of nobody) for one object type of the area."""
    template_name = 'netbox_user_pin/area_fields.html'

    def _area(self, request, pk):
        area = get_object_or_404(ProtectedArea, pk=pk)
        if not areas.can_see(request.user, area):
            raise PermissionDenied
        return area

    def _choice(self, request, area):
        """(profile of the chosen access entry or None, 'nobody' flag, target)."""
        raw = request.POST.get('grant') or request.GET.get('grant') or ''
        nobody = raw == 'nobody'
        targets = areas.area_models(area)
        if raw.startswith('g') and raw[1:].isdigit():  # a group
            group = areas.groups_of(area).filter(pk=raw[1:]).first()
            if group is not None:
                return group, False, (group.target if group.target in targets else (targets[0] if targets else ''))
        grant = None if nobody else (self._grants(area).filter(pk=raw).first() if raw.isdigit() else None)
        profile = grant.profile if grant else None
        if grant is not None and grant.target in targets and not (request.POST.get('target') or request.GET.get('target')):
            return profile, nobody, grant.target
        target = request.POST.get('target') or request.GET.get('target') or (targets[0] if targets else '')
        return profile, nobody, (target if target in targets else (targets[0] if targets else ''))

    @staticmethod
    def _grants(area):
        return area.grants.filter(revoked__isnull=True).select_related('user', 'profile')

    def _render(self, request, area):
        profile, nobody, target = self._choice(request, area)
        rows = []
        if target and (profile is not None or nobody):
            app_label, _dot, model = target.partition('.')
            rules = {r.field: r for r in AreaFieldRule.objects.filter(area=area, profile=profile, target=target)}
            for key, label, kind in fieldrules.fields_of(app_label, model):
                rule = rules.get(key)
                rows.append({'key': key, 'label': label, 'kind': kind, 'mode': rule.mode if rule else 'default',
                             'contains': rule.contains if rule else ''})
        tab_rows = []
        if profile is not None and (profile.private or profile.target) and target:
            tab_rows = [dict(t, allowed=profile.tabs is None or t['name'] in profile.tabs)
                        for t in areas.tabs_of(target)]
        return render(request, self.template_name, {
            'tab_rows': tab_rows,
            'area': area, 'profile': profile, 'nobody': nobody, 'target': target, 'rows': rows,
            'grant_choices': [(f'g{p.pk}', f'{_("Group")}: {p.name} · {_target_label(p.target)}')
                              for p in areas.groups_of(area)] +
                             [(str(g.pk), f'{g.user.username} · {g.target or "*"}') for g in self._grants(area)
                              if g.is_active and g.profile.private],
            'grant_pk': (request.POST.get('grant') or request.GET.get('grant') or ''), 'targets': [(t, _target_label(t)) for t in areas.area_models(area)],
            'can_manage': areas.can_manage(request.user, area),
            'settings': service.get_settings(), **_step_up_context(request),
        })

    def get(self, request, pk):
        return self._render(request, self._area(request, pk))

    def post(self, request, pk):
        area = self._area(request, pk)
        profile, nobody, target = self._choice(request, area)
        if request.POST.get('action') == 'tabs':
            try:
                chosen = [k[5:] for k in request.POST if k.startswith('tab__')]
                if profile is not None and profile.target and not profile.private:
                    areas.set_group_tabs(profile, chosen, request.user, request=request)
                else:
                    grant = self._grants(area).filter(pk=request.POST.get('grant') or 0).first()
                    if grant is None:
                        raise PermissionDenied
                    areas.set_grant_tabs(grant, chosen, request.user, request=request)
                messages.success(request, _('Saved.'))
            except ValidationError as exc:
                _errors(request, exc)
            return redirect(f"{reverse('plugins:netbox_user_pin:area_fields', kwargs={'pk': area.pk})}"
                            f"?grant={request.POST.get('grant', '')}&target={target}")
        try:
            app_label, _dot, model = target.partition('.')
            rules = {key: (request.POST.get(f'mode__{key}', 'default'), request.POST.get(f'contains__{key}', ''))
                     for key, _label, _kind in fieldrules.fields_of(app_label, model)}
            count = areas.save_field_rules(area, None if nobody else profile, target, rules, request.user,
                                           request=request)
            messages.success(request, _('Saved ({n} changes).').format(n=count))
        except ValidationError as exc:
            _errors(request, exc)
        return redirect(f"{reverse('plugins:netbox_user_pin:area_fields', kwargs={'pk': area.pk})}"
                        f"?grant={request.POST.get('grant', '')}&target={target}")


class AreaRequestView(LoginRequiredMixin, View):
    """Any logged-in user may ask the owners for access (no PIN needed for the request itself)."""

    def post(self, request, key):
        area = get_object_or_404(ProtectedArea, key=key)
        form = AreaRequestForm(request.POST)
        if not form.is_valid():
            messages.error(request, _('Write why you need the access (at least a few words).'))
            return redirect(_next_url(request, 'plugins:netbox_user_pin:my_access'))
        try:
            areas.request_access(area, request.user, note=form.cleaned_data['note'], request=request,
                                 scope=form.cleaned_data['scope'])
            messages.success(request, _('The owners of "{area}" were asked for access. You will get an e-mail '
                                        'when they decide.').format(area=area.name))
        except ValidationError as exc:
            _errors(request, exc)
        return redirect(_next_url(request, 'plugins:netbox_user_pin:my_access'))


class AccessRequestView(LoginRequiredMixin, View):
    """The form of the "no access" page: ask for chosen rights on the blocked object type."""

    def post(self, request):
        form = AccessRequestForm(request.POST)
        if not form.is_valid():
            messages.error(request, _('Choose the rights and write why you need the access (at least a few words).'))
            return redirect(_next_url(request, 'plugins:netbox_user_pin:my_access'))
        data = form.cleaned_data
        try:
            if not data['rights']:
                raise ValidationError(_('Choose at least one right.'))
            areas.request_target_access(request.user, data['target'], data['rights'], data['note'], request=request,
                                        scope=data['scope'])
            messages.success(request, _('The request was sent. You will get an e-mail when it is decided.'))
        except ValidationError as exc:
            _errors(request, exc)
        return redirect(_next_url(request, 'plugins:netbox_user_pin:my_access'))


class RequestDecideView(AreaViewMixin, View):
    """The page the e-mail links to: who asks for what and why; the decider may change the rights, then OK."""
    template_name = 'netbox_user_pin/request_decide.html'

    def _request(self, request, pk):
        req = get_object_or_404(AreaRequest.objects.select_related('area', 'user'), pk=pk)
        area = req.area
        if area is None:
            app_label, _dot, model = req.target.partition('.')
            area = areas.area_for(app_label, model or None, package=app_label)
        allowed = areas.is_keeper(request.user) if area is None or not area.owners.exists() \
            else areas.is_owner(request.user, area)
        if not allowed or req.user_id == request.user.pk:
            raise PermissionDenied
        return req, area

    def _render(self, request, req, area, form=None):
        if form is None:
            rights = req.rights or ['view']
            form = AreaDecideForm(area=area, initial={'rights': rights, 'hours': 0}) if area else None
        available = areas.rights_available(area) if area else list(areas.GENERIC_RIGHTS)
        return render(request, self.template_name, {
            'req': req, 'area': area, 'target_label': areas.target_label(req.target), 'form': form,
            'by_group': '.' in req.target,
            'groups': list(areas.groups_of(area, req.target)) if area and '.' in req.target else [],
            'asked': [(r, areas.right_label(area, r) if area else r.capitalize()) for r in req.rights],
            'available': [(r, areas.right_label(area, r) if area else r.capitalize()) for r in available],
            'chosen': req.rights or ['view'],
            'creates_area': area is None,
            'hours': [(h, label) for h, label in ACCESS_HOURS if not area or h == 0 or h <= area.max_hours],
        })

    def get(self, request, pk):
        req, area = self._request(request, pk)
        return self._render(request, req, area)

    def post(self, request, pk):
        req, area = self._request(request, pk)
        action = request.POST.get('action')
        try:
            if action == 'deny':
                areas.decide_request(req, request.user, False, request=request)
                messages.success(request, _('Request denied.'))
            elif action == 'approve':
                known = set(areas.rights_available(area) if area else areas.GENERIC_RIGHTS)
                rights = [r for r in request.POST.getlist('rights') if r in known]
                try:
                    hours = int(request.POST.get('hours') or 0)
                except ValueError:
                    hours = 0
                group, group_name, group_rights = None, '', None
                if '.' in req.target:  # a type: the user goes into a group (an existing one, or a new one)
                    gid = request.POST.get('group', '')
                    if gid.isdigit() and area is not None:
                        group = get_object_or_404(AreaProfile, pk=gid, area=area, private=False, target=req.target)
                    else:
                        group_name, group_rights = request.POST.get('group_name', ''), rights
                if not rights and group is None:  # an existing group has its rights; otherwise something must be chosen
                    raise ValidationError(_('Choose at least one right.'))
                areas.decide_request(req, request.user, True, hours=hours or None, request=request,
                                     rights=None if '.' in req.target else rights, group=group,
                                     group_name=group_name, group_rights=group_rights)
                messages.success(request, _('Access granted.'))
            else:
                raise PermissionDenied
        except ValidationError as exc:
            _errors(request, exc)
            return redirect('plugins:netbox_user_pin:request_decide', pk=req.pk)
        req.refresh_from_db()
        if req.area_id:
            return redirect('plugins:netbox_user_pin:area', pk=req.area_id)
        return redirect('plugins:netbox_user_pin:areas')


class MyAccessView(LoginRequiredMixin, View):
    template_name = 'netbox_user_pin/my_access.html'

    def get(self, request):
        grants = list(AreaGrant.objects.filter(user=request.user).select_related('area', 'profile')[:60])
        return render(request, self.template_name, {
            'grants': [g for g in grants if g.is_active], 'old': [g for g in grants if not g.is_active][:10],
            'requests': AreaRequest.objects.filter(user=request.user).select_related('area')[:20],
            'owned': ProtectedArea.objects.filter(owners__user=request.user),
            'waiting': areas.pending_requests_for(request.user).count(),
        })

    def post(self, request):
        action = request.POST.get('action')
        try:
            if action == 'cancel':
                areas.cancel_request(get_object_or_404(AreaRequest, pk=request.POST.get('pk')), request.user,
                                     request=request)
            elif action == 'end':
                areas.revoke_grant(get_object_or_404(AreaGrant, pk=request.POST.get('pk'), user=request.user),
                                   request.user, request=request)
            else:
                raise PermissionDenied
        except ValidationError as exc:
            _errors(request, exc)
        return redirect('plugins:netbox_user_pin:my_access')


class GroupView(AreaViewMixin, View):
    """One group: its members, what it may do (rights, tabs) and the rule of every field."""
    template_name = 'netbox_user_pin/group.html'

    def _objects(self, request, pk, gid):
        area = get_object_or_404(ProtectedArea, pk=pk)
        if not areas.can_see(request.user, area):
            raise PermissionDenied
        group = get_object_or_404(AreaProfile, pk=gid, area=area, private=False)
        if not group.target:
            raise PermissionDenied
        return area, group

    def _render(self, request, area, group):
        target = group.target
        app_label, _dot, model = target.partition('.')
        rules = {r.field: r for r in AreaFieldRule.objects.filter(area=area, profile=group, target=target)}
        from django.apps import apps as django_apps
        model_class = django_apps.get_model(app_label, model)
        rows = []
        for key, label, kind in fieldrules.fields_of(app_label, model):
            rule = rules.get(key)
            related = fieldrules.related_label(model_class, key)
            rows.append({'key': key, 'label': label, 'kind': kind, 'mode': rule.mode if rule else 'default',
                         'contains': rule.contains if rule else '',
                         'related': _target_label(related) if related else ''})
        tabs = areas.tabs_of(target)
        conditions = areas.group_conditions(group)
        filter_fields = areas.filter_fields(target)
        filterable = {f['key'] for f in filter_fields}
        for row in rows:  # the conditions of a field are shown (and added) with the field
            row['filterable'] = row['key'] in filterable
            row['conds'] = [(i, text) for i, text, field in conditions if field == row['key']]
        return render(request, self.template_name, {
            'area': area, 'group': group, 'target': target, 'target_label': _target_label(target),
            'members': areas.group_members(group), 'user_choices': _all_user_choices(),
            'wide_members': self._wide_members(area, group),
            'rights': [(r, areas.right_label(area, r)) for r in areas.rights_available(area)],
            'rights_set': set(group.rights),
            'level': 'none' if not group.rights else ('write' if {'add', 'change'} & set(group.rights) else 'read'),
            'can_delete': 'delete' in group.rights, 'can_import': 'import' in group.rights,
            'can_export': 'export' in group.rights,
            'extra_rights': [(r, areas.right_label(area, r)) for r in areas.rights_available(area)
                             if r not in areas.GENERIC_RIGHTS],
            'tabs': [dict(t, allowed=group.tabs is None or t['name'] in group.tabs) for t in tabs if not t['plugin']],
            'plugin_tabs': [t for t in tabs if t['plugin']], 'rows': rows,
            'conditions': [(i, text) for i, text, _field in conditions], 'filter_fields': filter_fields,
            'deny_conditions': [(i, text) for i, text, _field in areas.group_deny_conditions(group)],
            'records': group.records, 'denied': set(group.denied or []),
            'ops': list(areas.row_op_labels().items()),
            'can_manage': areas.can_manage(request.user, area) or areas._may_grant(request.user, area),
            'settings': service.get_settings(),
        })

    @staticmethod
    def _wide_members(area, group):
        """Members who see all the records anyway: another access of theirs has no row condition."""
        result = set()
        for grant in areas.group_members(group):
            for other in areas.active_grants(grant.user, area, group.target):
                if other.profile_id != group.pk and 'view' in other.profile.rights and \
                        not (other.profile.filters or {}).get(group.target):
                    result.add(grant.user_id)
        return result

    def get(self, request, pk, gid):
        area, group = self._objects(request, pk, gid)
        return self._render(request, area, group)

    def post(self, request, pk, gid):
        area, group = self._objects(request, pk, gid)
        action = request.POST.get('action')
        try:
            if action == 'rights':
                rights = request.POST.getlist('rights')
                if 'access' in request.POST:  # the access level of the node: nothing / read / read and write (+ delete)
                    level = request.POST.get('access')
                    extra = [r for r in rights if r not in areas.GENERIC_RIGHTS]
                    rights = {'none': [], 'read': ['view'], 'write': ['view', 'add', 'change']}.get(level, ['view'])
                    if level != 'none':
                        rights = rights + (['delete'] if request.POST.get('delete') else []) + (
                            ['import'] if request.POST.get('import') else []) + (
                            ['export'] if request.POST.get('export') else []) + extra
                denied = [k[6:] for k in request.POST if k.startswith('deny__')] if 'access' in request.POST else None
                areas.update_group(group, request.user, name=request.POST.get('name', group.name),
                                   rights=rights, request=request, allow_empty='access' in request.POST, denied=denied)
                chosen = [k[5:] for k in request.POST if k.startswith('tab__')]
                chosen += [k[6:] for k, v in request.POST.items() if k.startswith('tabv__') and v == 'yes']
                areas.set_group_tabs(group, chosen, request.user, request=request)
                messages.success(request, _('Saved.'))
            elif action == 'fields':
                app_label, _dot, model = group.target.partition('.')
                rules = {key: (request.POST.get(f'mode__{key}', 'default'), request.POST.get(f'contains__{key}', ''))
                         for key, _label, _kind in fieldrules.fields_of(app_label, model)}
                count = areas.save_field_rules(area, group, group.target, rules, request.user, request=request)
                messages.success(request, _('Saved ({n} changes).').format(n=count))
            elif action == 'member-add':
                chosen = _chosen_users(request)
                if not chosen:
                    messages.error(request, _('Choose a user.'))
                for user in chosen:
                    areas.add_member(group, user, None, request.user, request=request)
                if chosen:
                    messages.success(request, _('Added to the group.'))
            elif action == 'records':
                areas.set_group_records(group, request.user, request.POST.get('records', ''), request=request)
                messages.success(request, _('Saved.'))
            elif action == 'rule-add':
                op = request.POST.get('op', '')
                values = request.POST.getlist('values') or [request.POST.get('value_text', '')]
                if op in ('in', 'nin') and len(values) == 1:
                    values = values[0].split(',')
                areas.add_group_condition(group, request.user, request.POST.get('field', ''), op, values,
                                          request=request, deny=request.POST.get('kind') == 'deny')
                messages.success(request, _('The condition was added.'))
                if {'add', 'change'} & set(group.rights):
                    messages.warning(request, _('Mind that a record which does not meet the conditions disappears '
                                                'for the group right after it is saved.'))
            elif action == 'rule-delete':
                try:
                    index = int(request.POST.get('index', ''))
                except ValueError:
                    index = -1
                areas.remove_group_condition(group, request.user, index, request=request,
                                             deny=request.POST.get('kind') == 'deny')
                messages.success(request, _('The condition was removed.'))
            elif action == 'revoke':
                areas.revoke_grant(get_object_or_404(AreaGrant, pk=request.POST.get('pk'), profile=group),
                                   request.user, request=request)
                messages.success(request, _('Removed from the group.'))
            elif action == 'group-delete':
                areas.delete_group(group, request.user, request=request)
                messages.success(request, _('Group deleted.'))
                return redirect('plugins:netbox_user_pin:area', pk=area.pk)
            else:
                raise PermissionDenied
        except ValidationError as exc:
            _errors(request, exc)
        anchor = {'rule-add': '#pin-rule-form', 'rule-delete': '#pin-rule-form', 'fields': '#pin-fields-box'}.get(action, '')
        return redirect(reverse('plugins:netbox_user_pin:group', kwargs={'pk': area.pk, 'gid': group.pk}) + anchor)
