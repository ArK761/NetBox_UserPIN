from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext as _
from django.views import View
from utilities.request import safe_for_redirect

from . import crypto, service
from .forms import ChangePinForm, PinSettingsForm, SetPinForm, UnlockForm
from .mixins import PinRequiredMixin
from .models import PinEvent, PinEventAction, PinSettings, UserPin


def _next_url(request, default='plugins:netbox_user_pin:my_pin'):
    url = request.POST.get('next') or request.GET.get('next')
    if url and safe_for_redirect(url):
        return url
    return reverse(default)


def _apply_form_errors(form, exc, field):
    for message in exc.messages:
        form.add_error(field, message)


#
# End-user views
#

class MyPinView(LoginRequiredMixin, View):
    template_name = 'netbox_user_pin/my_pin.html'

    def get(self, request):
        settings = service.get_settings()
        user_pin = UserPin.objects.filter(user=request.user).first()
        return render(request, self.template_name, {
            'settings': settings,
            'user_pin': user_pin,
            'has_pin': bool(user_pin and user_pin.is_set),
            'expired': service.pin_expired(request.user, settings),
            'unlocked_scopes': service.unlocked_scopes(request),
            'recent_events': PinEvent.objects.filter(user=request.user)[:10],
        })


class SetPinView(LoginRequiredMixin, View):
    """First-time PIN (or after an administrator reset)."""
    template_name = 'netbox_user_pin/set_pin.html'

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated and service.has_pin(request.user):
            return redirect(f"{reverse('plugins:netbox_user_pin:change_pin')}?{request.GET.urlencode()}")
        return super().dispatch(request, *args, **kwargs)

    def _render(self, request, form):
        return render(request, self.template_name, {
            'form': form,
            'settings': service.get_settings(),
            'next': request.POST.get('next') or request.GET.get('next', ''),
        })

    def get(self, request):
        return self._render(request, SetPinForm())

    def post(self, request):
        form = SetPinForm(request.POST)
        if form.is_valid():
            try:
                service.set_pin(request.user, form.cleaned_data['new_pin'], request=request)
            except ValidationError as exc:
                _apply_form_errors(form, exc, 'new_pin')
            else:
                messages.success(request, _('Your PIN has been set.'))
                # Continue to the protected page; it will ask for the new PIN.
                return redirect(_next_url(request))
        return self._render(request, form)


class ChangePinView(LoginRequiredMixin, View):
    template_name = 'netbox_user_pin/change_pin.html'

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated and not service.has_pin(request.user):
            return redirect(f"{reverse('plugins:netbox_user_pin:set_pin')}?{request.GET.urlencode()}")
        return super().dispatch(request, *args, **kwargs)

    def _render(self, request, form):
        return render(request, self.template_name, {
            'form': form,
            'settings': service.get_settings(),
            'expired': bool(request.GET.get('expired')) or service.pin_expired(request.user),
            'next': request.POST.get('next') or request.GET.get('next', ''),
        })

    def get(self, request):
        return self._render(request, ChangePinForm())

    def post(self, request):
        form = ChangePinForm(request.POST)
        if form.is_valid():
            try:
                service.change_pin(
                    request.user, form.cleaned_data['current_pin'], form.cleaned_data['new_pin'], request=request
                )
            except ValidationError as exc:
                field = 'current_pin' if exc.code in ('wrong', 'locked_out') else 'new_pin'
                _apply_form_errors(form, exc, field)
            else:
                messages.success(request, _('Your PIN has been changed.'))
                return redirect(_next_url(request))
        return self._render(request, form)


class UnlockView(LoginRequiredMixin, View):
    template_name = 'netbox_user_pin/unlock.html'

    def _context(self, request, form, **extra):
        user_pin = UserPin.objects.filter(user=request.user).first()
        return {
            'form': form,
            'scope': request.POST.get('scope') or request.GET.get('scope', ''),
            'next': request.POST.get('next') or request.GET.get('next', ''),
            'locked_until': user_pin.locked_until if user_pin and user_pin.is_locked_out else None,
            **extra,
        }

    def get(self, request):
        if not service.has_pin(request.user):
            return redirect(f"{reverse('plugins:netbox_user_pin:set_pin')}?{request.GET.urlencode()}")
        return render(request, self.template_name, self._context(request, UnlockForm()))

    def post(self, request):
        form = UnlockForm(request.POST)
        scope = request.POST.get('scope') or None
        if form.is_valid():
            result = service.unlock(request, form.cleaned_data['pin'], scope=scope)
            if result:
                return redirect(_next_url(request))
            if result.status is service.VerifyStatus.NO_PIN:
                return redirect(reverse('plugins:netbox_user_pin:set_pin'))
            if result.status is service.VerifyStatus.LOCKED_OUT:
                form.add_error('pin', _('Too many failed attempts. You are locked out until {time}.').format(
                    time=timezone.localtime(result.locked_until).strftime('%Y-%m-%d %H:%M')
                ))
            else:
                form.add_error('pin', _('Wrong PIN. Remaining attempts: {n}.').format(n=result.remaining_attempts))
        return render(request, self.template_name, self._context(request, form))


class LockView(LoginRequiredMixin, View):
    def post(self, request):
        service.lock(request)
        messages.info(request, _('Locked. You will be asked for your PIN again.'))
        return redirect(_next_url(request))


class PinTestView(LoginRequiredMixin, PinRequiredMixin, View):
    """A protected page to try the unlock flow."""
    pin_scope = 'test'

    def get(self, request):
        return render(request, 'netbox_user_pin/test.html', {
            'unlocked_scopes': service.unlocked_scopes(request),
        })


#
# Administration
#

class UserPinListView(LoginRequiredMixin, PermissionRequiredMixin, View):
    permission_required = 'netbox_user_pin.view_userpin'
    raise_exception = True

    def get(self, request):
        users = get_user_model().objects.select_related('user_pin').order_by('username')
        q = request.GET.get('q', '').strip()
        if q:
            users = users.filter(username__icontains=q)
        page = Paginator(users, 50).get_page(request.GET.get('page'))
        rows = []
        for user in page:
            user_pin = getattr(user, 'user_pin', None)
            rows.append({'user': user, 'pin': user_pin})
        return render(request, 'netbox_user_pin/user_list.html', {
            'page': page,
            'rows': rows,
            'q': q,
            'can_change': request.user.has_perm('netbox_user_pin.change_userpin'),
            'settings': service.get_settings(),
        })


class UserPinActionView(LoginRequiredMixin, PermissionRequiredMixin, View):
    permission_required = 'netbox_user_pin.change_userpin'
    raise_exception = True

    def post(self, request, pk, action):
        user = get_object_or_404(get_user_model(), pk=pk)
        if action == 'reset':
            service.reset_pin(user, actor=request.user, request=request)
            messages.success(request, _('PIN of {user} has been reset. The user must set a new PIN.').format(
                user=user))
        elif action == 'clear-lockout':
            service.clear_lockout(user, actor=request.user, request=request)
            messages.success(request, _('Lockout of {user} has been cleared.').format(user=user))
        return redirect(_next_url(request, 'plugins:netbox_user_pin:user_list'))


class PinEventListView(LoginRequiredMixin, PermissionRequiredMixin, View):
    permission_required = 'netbox_user_pin.view_pinevent'
    raise_exception = True

    def get(self, request):
        events = PinEvent.objects.all()
        user = request.GET.get('user', '').strip()
        action = request.GET.get('action', '').strip()
        if user:
            events = events.filter(username__icontains=user) | events.filter(actor_username__icontains=user)
        if action:
            events = events.filter(action=action)
        page = Paginator(events.order_by('-time', '-pk'), 50).get_page(request.GET.get('page'))
        return render(request, 'netbox_user_pin/event_list.html', {
            'page': page,
            'user_filter': user,
            'action_filter': action,
            'actions': PinEventAction.choices,
        })


class PinSettingsView(LoginRequiredMixin, PermissionRequiredMixin, View):
    permission_required = 'netbox_user_pin.change_pinsettings'
    raise_exception = True
    template_name = 'netbox_user_pin/settings.html'

    def _context(self, form):
        try:
            key_info = {
                'active': crypto.active_key_id(),
                'fingerprint': crypto.fingerprint(),
                'configured': crypto.configured_key_ids(),
            }
        except Exception as exc:  # configuration errors are shown, not raised
            key_info = {'error': str(exc)}
        return {'form': form, 'key_info': key_info}

    def get(self, request):
        return render(request, self.template_name, self._context(PinSettingsForm(instance=PinSettings.load())))

    def post(self, request):
        instance = PinSettings.load()
        form = PinSettingsForm(request.POST, instance=instance)
        if form.is_valid():
            changes = []
            for name in form.changed_data:
                old = form.initial.get(name)
                new = form.cleaned_data.get(name)
                changes.append(f'{name}: {old!r} -> {new!r}')
            form.save()
            if changes:
                service.log_event(
                    PinEventAction.SETTINGS_CHANGED, actor=request.user, request=request, detail='\n'.join(changes)
                )
            messages.success(request, _('PIN settings saved.'))
            return redirect('plugins:netbox_user_pin:settings')
        return render(request, self.template_name, self._context(form))
