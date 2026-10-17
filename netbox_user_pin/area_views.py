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
from .forms import (
    AreaDecideForm, AreaForm, AreaGrantForm, AreaOwnerForm, AreaProfileForm, AreaRequestForm, AreaTargetForm,
    KeeperForm,
)
from .mixins import PinRequiredMixin, area_gate
from .models import (
    AreaFieldRule, AreaGrant, AreaProfile, AreaRequest, AreaRequestStatus, PinEventAction, ProtectedArea,
)
from .views import ADMIN_SCOPE, _errors, _next_url, _step_up_context

__all__ = ('AreaFieldsView', 'AreaListView', 'AreaRequestView', 'AreaView', 'MyAccessView')


class AreaViewMixin(LoginRequiredMixin, PinRequiredMixin):
    """Logged in, allowed to use a PIN and unlocked; 2FA (if the user has it) is asked once in a while only."""
    pin_scope = ADMIN_SCOPE

    def dispatch(self, request, *args, **kwargs):
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
    template_name = 'netbox_user_pin/areas.html'

    def _render(self, request, form=None):
        areas.sync_plugin_areas()
        core = roles.is_core(request.user)
        queryset = ProtectedArea.objects.all() if core else ProtectedArea.objects.filter(owners__user=request.user)
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
            'rows': rows, 'is_core': core, 'form': form or AreaForm(create=True),
            'waiting': areas.pending_requests_for(request.user).count(),
            'deny_on': service.get_settings().default_deny, 'keepers': areas.keepers(),
            'is_keeper': areas.is_keeper(request.user), 'can_keepers': areas.can_manage_keepers(request.user),
            'keeper_form': KeeperForm(),
            'settings': service.get_settings(), **_step_up_context(request),
        })

    def get(self, request):
        return self._render(request)

    def post(self, request):
        action = request.POST.get('action')
        from django.contrib.auth import get_user_model
        try:
            if action == 'create':
                if not roles.is_core(request.user):
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
        return render(request, self.template_name, {
            'area': area, 'status': code, 'status_label': label, 'targets': areas.targets_of(area),
            'owners': list(areas.owners(area)), 'is_owner': mine, 'can_manage': areas.can_manage(request.user, area),
            'bootstrap': not area.owners.exists(),
            'active_grants': [(g, _grant_rows(area, g)) for g in grants if g.is_active],
            'old_grants': [g for g in grants if not g.is_active][:15],
            'pending': [(r, AreaDecideForm(area=area)) for r in pending],
            'area_form': forms.get('area_form') or AreaForm(plugin=area.plugin, initial={
                'name': area.name, 'description': area.description, 'max_hours': area.max_hours,
                'enabled': area.enabled}),
            'target_form': AreaTargetForm(exclude=areas.targets_of(area)),
            'target_labels': [(t, _target_label(t)) for t in areas.targets_of(area)],
            'owner_form': AreaOwnerForm(),
            'grant_form': forms.get('grant_form') or AreaGrantForm(area=area),
            'rights': [(r, areas.right_label(area, r)) for r in areas.rights_available(area)],
            'settings': service.get_settings(), **_step_up_context(request),
        })

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
                                  enabled=data.get('enabled'), max_hours=data['max_hours'], request=request)
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
                form = AreaOwnerForm(request.POST)
                if form.is_valid():
                    areas.add_owner(area, form.cleaned_data['user'], request.user, request=request)
                    messages.success(request, _('Owner added.'))
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
        grant = None if nobody else (self._grants(area).filter(pk=raw).first() if raw.isdigit() else None)
        profile = grant.profile if grant else None
        targets = areas.area_models(area)
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
        if target:
            app_label, _dot, model = target.partition('.')
            rules = {r.field: r for r in AreaFieldRule.objects.filter(area=area, profile=profile, target=target)}
            for key, label, kind in fieldrules.fields_of(app_label, model):
                rule = rules.get(key)
                rows.append({'key': key, 'label': label, 'kind': kind, 'mode': rule.mode if rule else 'default',
                             'contains': rule.contains if rule else ''})
        return render(request, self.template_name, {
            'area': area, 'profile': profile, 'nobody': nobody, 'target': target, 'rows': rows,
            'grant_choices': [(g.pk, f'{g.user.username} · {g.target or "*"}') for g in self._grants(area) if g.is_active],
            'grant_pk': (request.POST.get('grant') or request.GET.get('grant') or ''), 'targets': [(t, _target_label(t)) for t in areas.area_models(area)],
            'can_manage': areas.can_manage(request.user, area),
            'settings': service.get_settings(), **_step_up_context(request),
        })

    def get(self, request, pk):
        return self._render(request, self._area(request, pk))

    def post(self, request, pk):
        area = self._area(request, pk)
        profile, nobody, target = self._choice(request, area)
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
