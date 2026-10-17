"""Pages of the protected areas (administration by the owners, requests, my access)."""
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied, ValidationError
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext as _
from django.views import View

from . import areas, roles, service
from .forms import AreaDecideForm, AreaForm, AreaGrantForm, AreaOwnerForm, AreaProfileForm, AreaRequestForm
from .mixins import PinRequiredMixin, step_up_gate
from .models import (
    AreaGrant, AreaProfile, AreaRequest, AreaRequestStatus, PinEventAction, ProtectedArea,
)
from .views import ADMIN_SCOPE, _errors, _next_url, _step_up_context

__all__ = ('AreaListView', 'AreaRequestView', 'AreaView', 'MyAccessView')


class AreaViewMixin(LoginRequiredMixin, PinRequiredMixin):
    """Logged in, allowed to use a PIN and unlocked."""
    pin_scope = ADMIN_SCOPE


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
            'rows': rows, 'is_core': core, 'form': form or AreaForm(),
            'waiting': areas.pending_requests_for(request.user).count(),
            'settings': service.get_settings(), **_step_up_context(request),
        })

    def get(self, request):
        return self._render(request)

    def post(self, request):
        if (response := step_up_gate(request, 'full')) is not None:
            return response
        if request.POST.get('action') != 'create' or not roles.is_core(request.user):
            raise PermissionDenied
        form = AreaForm(request.POST)
        if not form.is_valid():
            return self._render(request, form=form)
        data = form.cleaned_data
        area = areas.create_area(data['name'], data['targets'], [], request.user, data['description'],
                                 data['max_hours'], request=request)
        messages.success(request, _('Area "{name}" created. Appoint its owners now - until then only the master '
                                    'has access to it.').format(name=area.name))
        return redirect('plugins:netbox_user_pin:area', pk=area.pk)


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
            'profiles': [(p, [areas.right_label(area, r) for r in p.rights], areas.format_filters(p.filters))
                         for p in area.profiles.all()],
            'active_grants': [g for g in grants if g.is_active], 'old_grants': [g for g in grants if not g.is_active][:15],
            'pending': [(r, AreaDecideForm(area=area)) for r in pending],
            'area_form': forms.get('area_form') or AreaForm(plugin=area.plugin, initial={
                'name': area.name, 'description': area.description, 'max_hours': area.max_hours,
                'enabled': area.enabled, 'targets': list(area.targets or [])}),
            'owner_form': AreaOwnerForm(), 'profile_form': forms.get('profile_form') or AreaProfileForm(area=area),
            'grant_form': forms.get('grant_form') or AreaGrantForm(area=area),
            'rights': [(r, areas.right_label(area, r)) for r in areas.rights_available(area)],
            'settings': service.get_settings(), **_step_up_context(request),
        })

    def get(self, request, pk):
        return self._render(request, self._area(request, pk))

    def post(self, request, pk):
        area = self._area(request, pk)
        if (response := step_up_gate(request, 'full')) is not None:
            return response
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
                                  targets=data.get('targets'), enabled=data.get('enabled'),
                                  max_hours=data['max_hours'], request=request)
                messages.success(request, _('Saved.'))
            elif action == 'delete':
                areas.delete_area(area, request.user, request=request)
                messages.success(request, _('Area deleted.'))
                return redirect('plugins:netbox_user_pin:areas')
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
                areas.grant_access(area, data['user'], data['profile'], data['hours'] or None, request.user,
                                   request=request)
                messages.success(request, _('Access granted.'))
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
                        messages.error(request, _('Choose a profile and the duration.'))
                    else:
                        areas.decide_request(req, request.user, True, form.cleaned_data['profile'],
                                             form.cleaned_data['hours'] or None, request=request)
                        messages.success(request, _('Access granted.'))
            else:
                raise PermissionDenied
        except ValidationError as exc:
            _errors(request, exc)
        return redirect('plugins:netbox_user_pin:area', pk=area.pk)


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
