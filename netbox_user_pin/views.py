import segno
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext as _
from django.views import View
from utilities.request import safe_for_redirect

from . import crypto, delegation, service
from .forms import (
    ChangePinForm, DelegateForm, OtpForm, PinOtpForm, PinSettingsForm, RecoveryForm, SetPinForm, UnlockForm,
)
from .mixins import PinRequiredMixin, not_allowed_response, step_up_gate
from .models import PinAccess, PinAccessMode, PinDelegate, PinEvent, PinEventAction, PinSettings, UserPin

ADMIN_SCOPE = 'user-pin-admin'


def _next_url(request, default='plugins:netbox_user_pin:my_pin'):
    url = request.POST.get('next') or request.GET.get('next')
    if url and safe_for_redirect(url):
        return url
    return reverse(default)


def _apply_form_errors(form, exc, field):
    for message in exc.messages:
        form.add_error(field, message)


def _verify_error(form, result, pin_field='pin', otp_field='otp'):
    """Translate a failed VerifyResult into form errors."""
    status = result.status
    if status is service.VerifyStatus.LOCKED_OUT:
        form.add_error(pin_field, _('Too many failed attempts. You are locked out until {time}.').format(
            time=timezone.localtime(result.locked_until).strftime('%Y-%m-%d %H:%M')))
    elif status is service.VerifyStatus.WRONG_2FA:
        form.add_error(otp_field if otp_field in form.fields else None,
                       _('Wrong 2FA code. Remaining attempts: {n}.').format(n=result.remaining_attempts))
    elif status is service.VerifyStatus.WRONG:
        form.add_error(pin_field, _('Wrong PIN. Remaining attempts: {n}.').format(n=result.remaining_attempts))
    elif status is service.VerifyStatus.NEED_2FA:
        form.add_error(None, _('Two-factor authentication must be set up first (My PIN > Two-factor).'))
    elif status is service.VerifyStatus.NOT_ALLOWED:
        form.add_error(None, _('You are not permitted to use a PIN.'))
    else:
        form.add_error(None, _('No PIN is set.'))


class AllowedUserMixin(LoginRequiredMixin):
    """Logged in and permitted to use a PIN."""

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated and not service.is_allowed(request.user):
            return not_allowed_response(request)
        return super().dispatch(request, *args, **kwargs)


#
# End-user views
#

class MyPinView(LoginRequiredMixin, View):
    template_name = 'netbox_user_pin/my_pin.html'

    def get(self, request):
        settings = service.get_settings()
        user_pin = UserPin.objects.filter(user=request.user).first()
        expires = service.pin_expires_at(user_pin, settings)
        days_left = (expires - timezone.now()).days if expires else None
        return render(request, self.template_name, {
            'settings': settings,
            'user_pin': user_pin,
            'has_pin': bool(user_pin and user_pin.is_set),
            'allowed': service.is_allowed(request.user, settings),
            'expired': service.pin_expired(request.user, settings),
            'expires': expires,
            'days_left': days_left,
            'expiry_warning': days_left is not None and days_left <= settings.warn_days,
            'has_2fa': bool(user_pin and user_pin.has_2fa),
            'backup_codes_left': len(user_pin.backup_codes) if user_pin else 0,
            'email_status': service.email_status(request.user, settings),
            'recovery_blockers': service.recovery_blockers(request.user, settings),
            'unlocked_scopes': service.unlocked_scopes(request),
            'recent_events': PinEvent.objects.filter(user=request.user)[:10],
        })


class SetPinView(AllowedUserMixin, View):
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


class ChangePinView(AllowedUserMixin, View):
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


class UnlockView(AllowedUserMixin, View):
    template_name = 'netbox_user_pin/unlock.html'

    def _form(self, data=None):
        return UnlockForm(data, require_otp=service.get_settings().require_2fa_unlock)

    def _context(self, request, form):
        user_pin = UserPin.objects.filter(user=request.user).first()
        return {
            'form': form,
            'scope': request.POST.get('scope') or request.GET.get('scope', ''),
            'next': request.POST.get('next') or request.GET.get('next', ''),
            'locked_until': user_pin.locked_until if user_pin and user_pin.is_locked_out else None,
            'can_recover': not service.recovery_blockers(request.user),
        }

    def get(self, request):
        if not service.has_pin(request.user):
            return redirect(f"{reverse('plugins:netbox_user_pin:set_pin')}?{request.GET.urlencode()}")
        return render(request, self.template_name, self._context(request, self._form()))

    def post(self, request):
        form = self._form(request.POST)
        scope = request.POST.get('scope') or None
        if form.is_valid():
            result = service.unlock(request, form.cleaned_data['pin'], scope=scope,
                                    otp=form.cleaned_data.get('otp'))
            if result:
                return redirect(_next_url(request))
            if result.status is service.VerifyStatus.NO_PIN:
                return redirect(reverse('plugins:netbox_user_pin:set_pin'))
            _verify_error(form, result)
        return render(request, self.template_name, self._context(request, form))


class LockView(LoginRequiredMixin, View):
    def post(self, request):
        service.lock(request)
        service.end_step_up(request)
        messages.info(request, _('Locked. You will be asked for your PIN again.'))
        return redirect(_next_url(request))


class TestRotationView(AllowedUserMixin, View):
    """Force a PIN change on oneself to try the rotation flow."""

    def post(self, request):
        if service.force_change(request.user, actor=request.user, request=request):
            messages.info(request, _('PIN rotation test: you will be asked to change your PIN now.'))
            return redirect('plugins:netbox_user_pin:test')
        return redirect('plugins:netbox_user_pin:my_pin')


class PinTestView(LoginRequiredMixin, PinRequiredMixin, View):
    """A protected page to try the unlock flow."""
    pin_scope = 'test'

    def get(self, request):
        return render(request, 'netbox_user_pin/test.html', {
            'unlocked_scopes': service.unlocked_scopes(request),
        })


#
# Two-factor authentication
#

class TotpSetupView(AllowedUserMixin, View):
    template_name = 'netbox_user_pin/totp_setup.html'

    def _render(self, request, form, secret):
        uri = service.totp.provisioning_uri(secret, request.user.username)
        return render(request, self.template_name, {
            'form': form,
            'secret': ' '.join(secret[i:i + 4] for i in range(0, len(secret), 4)),
            'qr': segno.make(uri, error='m').svg_inline(scale=5, border=2, dark='#000', light='#fff'),
            'next': request.POST.get('next') or request.GET.get('next', ''),
        })

    def get(self, request):
        if service.has_2fa(request.user):
            messages.info(request, _('Two-factor authentication is already enabled.'))
            return redirect('plugins:netbox_user_pin:my_pin')
        secret, _uri = service.start_totp_enrollment(request)
        return self._render(request, OtpForm(), secret)

    def post(self, request):
        secret = service.pending_totp_secret(request)
        if not secret:
            return redirect('plugins:netbox_user_pin:totp_setup')
        form = OtpForm(request.POST)
        if form.is_valid():
            try:
                codes = service.confirm_totp_enrollment(request, form.cleaned_data['otp'])
            except ValidationError as exc:
                _apply_form_errors(form, exc, 'otp')
            else:
                return render(request, 'netbox_user_pin/backup_codes.html', {
                    'codes': codes, 'next': _next_url(request),
                })
        return self._render(request, form, secret)


class TotpManageView(AllowedUserMixin, View):
    """Disable 2FA or generate new backup codes – both need PIN + 2FA."""
    template_name = 'netbox_user_pin/totp_manage.html'

    def _render(self, request, form, action):
        return render(request, self.template_name, {
            'form': form, 'action': action, 'codes_left': service.backup_codes_left(request.user),
        })

    def dispatch(self, request, *args, **kwargs):
        if kwargs.get('action') not in ('disable', 'backup-codes'):
            raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)

    def get(self, request, action):
        if not service.has_2fa(request.user):
            return redirect('plugins:netbox_user_pin:totp_setup')
        return self._render(request, PinOtpForm(), action)

    def post(self, request, action):
        form = PinOtpForm(request.POST)
        if form.is_valid():
            result = service.verify_pin(request.user, form.cleaned_data['pin'], request=request, scope='2fa')
            if result:
                result = service.verify_second_factor(request.user, form.cleaned_data['otp'], request=request)
            if result:
                if action == 'disable':
                    service.disable_totp(request.user, request=request)
                    messages.success(request, _('Two-factor authentication has been disabled.'))
                    return redirect('plugins:netbox_user_pin:my_pin')
                codes = service.new_backup_codes(request.user, request=request)
                return render(request, 'netbox_user_pin/backup_codes.html', {
                    'codes': codes, 'next': reverse('plugins:netbox_user_pin:my_pin'),
                })
            _verify_error(form, result)
        return self._render(request, form, action)


#
# Forgotten PIN: e-mail code + 2FA
#

class RecoverView(AllowedUserMixin, View):
    template_name = 'netbox_user_pin/recover.html'

    def _render(self, request, form=None):
        settings = service.get_settings()
        user_pin = UserPin.objects.filter(user=request.user).first()
        code_pending = bool(user_pin and user_pin.recovery_code and user_pin.recovery_expires
                            and user_pin.recovery_expires > timezone.now())
        return render(request, self.template_name, {
            'form': form or RecoveryForm(),
            'blockers': service.recovery_blockers(request.user, settings),
            'code_pending': code_pending,
            'email': request.user.email,
            'settings': settings,
        })

    def get(self, request):
        return self._render(request)

    def post(self, request):
        if request.POST.get('action') == 'send':
            try:
                service.start_recovery(request.user, request=request)
            except ValidationError as exc:
                for message in exc.messages:
                    messages.error(request, message)
            else:
                messages.success(request, _('A recovery code has been sent to {email}.').format(
                    email=request.user.email))
            return redirect('plugins:netbox_user_pin:recover')
        form = RecoveryForm(request.POST)
        if form.is_valid():
            try:
                service.complete_recovery(
                    request.user, form.cleaned_data['email_code'], form.cleaned_data['otp'],
                    form.cleaned_data['new_pin'], request=request,
                )
            except ValidationError as exc:
                field = {'email_code': 'email_code', 'otp': 'otp'}.get(exc.code, 'new_pin')
                _apply_form_errors(form, exc, field)
            else:
                messages.success(request, _('Your new PIN has been set.'))
                return redirect('plugins:netbox_user_pin:my_pin')
        return self._render(request, form)


#
# Step-up confirmation
#

class StepUpView(AllowedUserMixin, View):
    template_name = 'netbox_user_pin/step_up.html'

    def _render(self, request, form):
        settings = service.get_settings()
        return render(request, self.template_name, {
            'form': form,
            'blockers': service.step_up_blockers(request.user, settings),
            'settings': settings,
            'next': request.POST.get('next') or request.GET.get('next', ''),
        })

    def get(self, request):
        return self._render(request, PinOtpForm(require_otp=service.get_settings().require_2fa_admin))

    def post(self, request):
        form = PinOtpForm(request.POST, require_otp=service.get_settings().require_2fa_admin)
        if form.is_valid():
            result = service.step_up(request, form.cleaned_data['pin'], form.cleaned_data.get('otp'))
            if result:
                return redirect(_next_url(request))
            _verify_error(form, result)
        return self._render(request, form)


#
# Administration (master = superuser, delegates via NetBox object permissions)
#

class AdminViewMixin(LoginRequiredMixin, PermissionRequiredMixin, PinRequiredMixin):
    """Administrators must be logged in, hold the permission and have unlocked their own PIN."""
    raise_exception = True
    pin_scope = ADMIN_SCOPE


class UserPinListView(AdminViewMixin, View):
    permission_required = 'netbox_user_pin.view_userpin'

    def get(self, request):
        settings = service.get_settings()
        users = list(get_user_model().objects.select_related('user_pin').order_by('username'))
        now = timezone.now()
        can_change = request.user.has_perm('netbox_user_pin.change_userpin')
        rows = []
        for user in users:
            user_pin = getattr(user, 'user_pin', None)
            access = user_pin.access if user_pin else PinAccess.DEFAULT
            allowed = user.is_superuser or access == PinAccess.ALLOWED or (
                access == PinAccess.DEFAULT and settings.access_mode == PinAccessMode.ALL
            )
            expires = service.pin_expires_at(user_pin, settings)
            rows.append({
                'user': user,
                'pin': user_pin,
                'access': access,
                'allowed': allowed,
                'is_set': bool(user_pin and user_pin.is_set),
                'has_2fa': bool(user_pin and user_pin.has_2fa),
                'locked': bool(user_pin and user_pin.locked_until and user_pin.locked_until > now),
                'email_status': service.email_status(user, settings),
                'expires': expires,
                'days_left': (expires - now).days if expires else None,
                'must_change': bool(user_pin and user_pin.must_change),
                'role': 'master' if user.is_superuser else ('delegate' if service.is_pin_admin(user) else ''),
                'manageable': can_change and service.can_manage(request.user, user),
            })
        summary = {
            'total': len(rows),
            'with_pin': sum(r['is_set'] for r in rows),
            'without_pin': sum(not r['is_set'] and r['allowed'] for r in rows),
            'locked': sum(r['locked'] for r in rows),
            'not_allowed': sum(not r['allowed'] for r in rows),
            'no_email': sum(r['email_status'] != 'ok' for r in rows),
            'no_2fa': sum(r['allowed'] and not r['has_2fa'] for r in rows),
        }
        filters = {
            'with_pin': lambda r: r['is_set'],
            'without_pin': lambda r: not r['is_set'] and r['allowed'],
            'locked': lambda r: r['locked'],
            'not_allowed': lambda r: not r['allowed'],
            'no_email': lambda r: r['email_status'] != 'ok',
            'no_2fa': lambda r: r['allowed'] and not r['has_2fa'],
        }
        q = request.GET.get('q', '').strip().lower()
        status = request.GET.get('status', '')
        if q:
            rows = [r for r in rows if q in r['user'].username.lower() or q in (r['user'].email or '').lower()]
        if status in filters:
            rows = [r for r in rows if filters[status](r)]
        page = Paginator(rows, 50).get_page(request.GET.get('page'))
        return render(request, 'netbox_user_pin/user_list.html', {
            'page': page,
            'rows': page.object_list,
            'q': request.GET.get('q', ''),
            'status': status,
            'summary': summary,
            'can_change': can_change,
            'step_up_active': service.has_step_up(request),
            'step_up_left': service.step_up_seconds_left(request),
            'settings': settings,
        })


class UserPinActionView(AdminViewMixin, View):
    permission_required = 'netbox_user_pin.change_userpin'
    actions = ('allow', 'deny', 'default', 'reset', 'clear-lockout', 'force-change', 'reset-2fa')

    def post(self, request, pk, action):
        if (response := step_up_gate(request)) is not None:
            return response
        user = get_object_or_404(get_user_model(), pk=pk)
        if action not in self.actions:
            raise PermissionDenied
        if not service.can_manage(request.user, user):
            raise PermissionDenied(_('Delegates cannot manage the master, other delegates or themselves.'))
        if action in ('allow', 'deny', 'default'):
            access = {'allow': PinAccess.ALLOWED, 'deny': PinAccess.DENIED, 'default': PinAccess.DEFAULT}[action]
            service.set_access(user, access, actor=request.user, request=request)
            messages.success(request, _('PIN access of {user} set to {access}.').format(
                user=user, access=PinAccess(access).label))
        elif action == 'reset':
            service.reset_pin(user, actor=request.user, request=request)
            messages.success(request, _('PIN of {user} has been reset. The user must set a new PIN.').format(
                user=user))
        elif action == 'clear-lockout':
            service.clear_lockout(user, actor=request.user, request=request)
            messages.success(request, _('Lockout of {user} has been cleared.').format(user=user))
        elif action == 'force-change':
            if service.force_change(user, actor=request.user, request=request):
                messages.success(request, _('{user} must change the PIN at next use.').format(user=user))
        elif action == 'reset-2fa':
            service.reset_totp(user, actor=request.user, request=request)
            messages.success(request, _('2FA of {user} has been reset.').format(user=user))
        return redirect(_next_url(request, 'plugins:netbox_user_pin:user_list'))


class PinEventListView(AdminViewMixin, View):
    permission_required = 'netbox_user_pin.view_pinevent'

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


class PinSettingsView(AdminViewMixin, View):
    permission_required = 'netbox_user_pin.view_pinsettings'
    template_name = 'netbox_user_pin/settings.html'

    def _context(self, request, form):
        try:
            key_info = {
                'active': crypto.active_key_id(),
                'fingerprint': crypto.fingerprint(),
                'configured': crypto.configured_key_ids(),
            }
        except Exception as exc:  # configuration errors are shown, not raised
            key_info = {'error': str(exc)}
        return {
            'form': form,
            'key_info': key_info,
            'can_edit': request.user.has_perm('netbox_user_pin.change_pinsettings'),
            'email_configured': service.email_configured(),
            'step_up_active': service.has_step_up(request),
            'step_up_left': service.step_up_seconds_left(request),
            'my_email_status': service.email_status(request.user),
        }

    def get(self, request):
        can_edit = request.user.has_perm('netbox_user_pin.change_pinsettings')
        form = PinSettingsForm(instance=PinSettings.load(), read_only=not can_edit)
        return render(request, self.template_name, self._context(request, form))

    def post(self, request):
        if not request.user.has_perm('netbox_user_pin.change_pinsettings'):
            raise PermissionDenied
        if (response := step_up_gate(request)) is not None:
            return response
        if request.POST.get('action') == 'test-mail':
            if service.send_user_mail(request.user, _('Test e-mail'), _('The NetBox PIN e-mail works.'),
                                      request=request):
                messages.success(request, _('Test e-mail sent to {email}.').format(email=request.user.email))
            else:
                messages.error(request, _('Test e-mail could not be sent (mail server, address or domain).'))
            return redirect('plugins:netbox_user_pin:settings')
        instance = PinSettings.load()
        form = PinSettingsForm(request.POST, instance=instance)
        if form.is_valid():
            changes = []
            for name in form.changed_data:
                changes.append(f'{name}: {form.initial.get(name)!r} -> {form.cleaned_data.get(name)!r}')
            form.save()
            if changes:
                service.log_event(
                    PinEventAction.SETTINGS_CHANGED, actor=request.user, request=request, detail='\n'.join(changes)
                )
            messages.success(request, _('PIN settings saved.'))
            return redirect('plugins:netbox_user_pin:settings')
        return render(request, self.template_name, self._context(request, form))


class DelegateListView(AdminViewMixin, View):
    """Only the master (superuser) manages delegates; add_pinsettings is never granted to anybody else."""
    permission_required = 'netbox_user_pin.add_pinsettings'
    template_name = 'netbox_user_pin/delegates.html'

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated and not request.user.is_superuser:
            raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)

    def _render(self, request, form):
        return render(request, self.template_name, {
            'form': form,
            'delegates': PinDelegate.objects.select_related('user', 'group').order_by('created'),
            'step_up_active': service.has_step_up(request),
            'step_up_left': service.step_up_seconds_left(request),
        })

    def get(self, request):
        return self._render(request, DelegateForm())

    def post(self, request):
        if (response := step_up_gate(request)) is not None:
            return response
        action = request.POST.get('action', 'add')
        if action in ('remove', 'toggle'):
            delegate = get_object_or_404(PinDelegate, pk=request.POST.get('pk'))
            if action == 'remove':
                delegate.delete()
                event, detail = PinEventAction.DELEGATE_REMOVED, str(delegate)
            else:
                delegate.can_edit_settings = not delegate.can_edit_settings
                delegate.save()
                event = PinEventAction.DELEGATE_CHANGED
                detail = f'{delegate}: can edit settings = {delegate.can_edit_settings}'
            delegation.sync_permissions()
            service.log_event(event, user=delegate.user, actor=request.user, request=request, detail=detail)
            messages.success(request, _('Delegates updated.'))
            return redirect('plugins:netbox_user_pin:delegates')
        form = DelegateForm(request.POST)
        if form.is_valid():
            delegate = PinDelegate.objects.create(
                user=form.cleaned_data['user'], group=form.cleaned_data['group'],
                can_edit_settings=form.cleaned_data['can_edit_settings'], created_by=request.user.username,
            )
            delegation.sync_permissions()
            service.log_event(
                PinEventAction.DELEGATE_ADDED, user=delegate.user, actor=request.user, request=request,
                detail=f'{delegate}, can edit settings = {delegate.can_edit_settings}',
            )
            messages.success(request, _('Delegate added.'))
            return redirect('plugins:netbox_user_pin:delegates')
        return self._render(request, form)
