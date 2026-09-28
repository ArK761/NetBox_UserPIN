import segno
from django.conf import settings as django_settings
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.paginator import Paginator
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext as _
from django.views import View
from utilities.request import safe_for_redirect

from . import approvals, crypto, delegation, mail, service
from .forms import (
    ApprovalForm, BackupCodesForm, BreakGlassForm, ChangePinForm, DelegateForm, DomainForm, MailSettingsForm, OtpForm, PinOtpForm, PinSettingsForm, RecoveryForm,
    ResetConfirmForm, SetPinForm, TestMailForm, UnlockForm,
)
from .mixins import PinRequiredMixin, not_allowed_response, step_up_gate
from .models import (
    AllowedDomain, ApprovalAction, ApprovalRequest, ApprovalStatus, PinAccess, PinAccessMode, PinDelegate, PinEvent,
    PinEventAction, PinSettings, UserPin,
)

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
    elif status is service.VerifyStatus.SUSPENDED:
        form.add_error(None, _('Your PIN is suspended. Contact your administrator.'))
    elif status is service.VerifyStatus.NOT_ALLOWED:
        form.add_error(None, _('You are not permitted to use a PIN.'))
    else:
        form.add_error(None, _('No PIN is set.'))


def _describe(name, value):
    return f'{name} = ***' if 'password' in name else f'{name} = {value!r}'


def _save_settings(request, form, action, redirect_name):
    """Save a settings form directly, or create a four-eyes request when required."""
    changes = {name: form.cleaned_data.get(name) for name in form.changed_data if name != 'new_smtp_password'}
    if form.cleaned_data.get('new_smtp_password'):
        # never kept in plain text – not even inside a waiting four-eyes request
        changes['smtp_password'] = mail.encrypt_password(form.cleaned_data['new_smtp_password'])
    if not changes:
        messages.info(request, _('No changes.'))
        return redirect(redirect_name)
    if approvals.required_for(action):
        summary = ('Mail settings: ' if action == ApprovalAction.MAIL_SETTINGS else 'Settings: ') + ', '.join(
            _describe(name, value) for name, value in changes.items())
        return _four_eyes(request, action, {'changes': changes}, summary)
    settings = PinSettings.load()
    detail = []
    for name, value in changes.items():
        detail.append(f'{name}: changed' if 'password' in name else f'{name}: {getattr(settings, name)!r} -> {value!r}')
        setattr(settings, name, value)
    settings.save()
    service.log_event(PinEventAction.SETTINGS_CHANGED, actor=request.user, request=request, detail='\n'.join(detail))
    messages.success(request, _('Settings saved.'))
    return redirect(redirect_name)


def _four_eyes(request, action, payload, summary):
    """Create a four-eyes request and send the requester to its page to confirm."""
    try:
        req = approvals.create(action, payload, summary, request.user, request=request)
    except ValidationError as exc:
        for message in exc.messages:
            messages.error(request, message)
        return redirect(_next_url(request, 'plugins:netbox_user_pin:user_list'))
    messages.info(request, _('This change needs a second person. Confirm it with your PIN and 2FA; another '
                             'administrator or delegate confirms it in their session.'))
    return redirect('plugins:netbox_user_pin:approval', pk=req.pk)


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
            'reset_pending': user_pin.reset_pending if user_pin else '',
            'cli_reset_2fa': service.cli_reset_2fa_command(request.user),
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
            'reset_pending': user_pin.reset_pending if user_pin else '',
            'suspended': bool(user_pin and user_pin.suspended),
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


class ResetConfirmView(AllowedUserMixin, View):
    """The user confirms a reset an administrator started (PIN reset: 2FA + new PIN; 2FA reset: PIN)."""
    template_name = 'netbox_user_pin/reset_confirm.html'

    def _pending(self, request):
        user_pin = UserPin.objects.filter(user=request.user).first()
        return (user_pin.reset_pending, user_pin) if user_pin else ('', None)

    def _render(self, request, form, kind, user_pin):
        return render(request, self.template_name, {
            'form': form, 'kind': kind, 'user_pin': user_pin, 'settings': service.get_settings(),
        })

    def get(self, request):
        kind, user_pin = self._pending(request)
        if not kind:
            messages.info(request, _('There is no reset waiting for you.'))
            return redirect('plugins:netbox_user_pin:my_pin')
        return self._render(request, ResetConfirmForm(kind=kind), kind, user_pin)

    def post(self, request):
        kind, user_pin = self._pending(request)
        if not kind:
            return redirect('plugins:netbox_user_pin:my_pin')
        form = ResetConfirmForm(request.POST, kind=kind)
        if form.is_valid():
            try:
                if kind == 'pin':
                    service.complete_pin_reset(request.user, form.cleaned_data['otp'], form.cleaned_data['new_pin'],
                                               request=request)
                else:
                    service.complete_2fa_reset(request.user, form.cleaned_data['pin'], request=request)
            except ValidationError as exc:
                field = {'otp': 'otp', 'pin': 'pin'}.get(exc.code, 'new_pin' if kind == 'pin' else 'pin')
                _apply_form_errors(form, exc, field if field in form.fields else None)
            else:
                if kind == 'pin':
                    messages.success(request, _('Your new PIN has been set.'))
                    return redirect('plugins:netbox_user_pin:my_pin')
                messages.success(request, _('Your old 2FA was removed. Set it up again now.'))
                return redirect('plugins:netbox_user_pin:totp_setup')
        return self._render(request, form, kind, user_pin)


#
# Step-up confirmation
#

class StepUpView(AllowedUserMixin, View):
    template_name = 'netbox_user_pin/step_up.html'

    @staticmethod
    def _level(request):
        return 'settings' if (request.POST.get('level') or request.GET.get('level')) == 'settings' else 'full'

    def _form(self, request, data=None):
        return PinOtpForm(data, require_otp=service.step_up_needs_2fa(self._level(request)))

    def _render(self, request, form):
        settings = service.get_settings()
        level = self._level(request)
        return render(request, self.template_name, {
            'form': form,
            'blockers': service.step_up_blockers(request.user, settings, level),
            'settings': settings,
            'needs_2fa': service.step_up_needs_2fa(level, settings),
            'level': level,
            'next': request.POST.get('next') or request.GET.get('next', ''),
        })

    def get(self, request):
        return self._render(request, self._form(request))

    def post(self, request):
        level = self._level(request)
        form = self._form(request, request.POST)
        ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        if form.is_valid():
            result = service.step_up(request, form.cleaned_data['pin'], form.cleaned_data.get('otp'), level=level)
            if result:
                return JsonResponse({'ok': True}) if ajax else redirect(_next_url(request))
            _verify_error(form, result)
        if ajax:
            errors = [str(e) for errs in form.errors.values() for e in errs]
            if 'no_2fa' in service.step_up_blockers(request.user, level=level):
                errors.append(str(_('Two-factor authentication must be set up first (My PIN > Two-factor).')))
            return JsonResponse({'ok': False, 'errors': errors or [str(_('Confirmation failed.'))]})
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
                'suspended': bool(user_pin and user_pin.suspended),
                'reset_pending': user_pin.reset_pending if user_pin else '',
                'cli_reset_2fa': service.cli_reset_2fa_command(user),
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
            'suspended': sum(r['suspended'] for r in rows),
        }
        filters = {
            'with_pin': lambda r: r['is_set'],
            'without_pin': lambda r: not r['is_set'] and r['allowed'],
            'locked': lambda r: r['locked'],
            'not_allowed': lambda r: not r['allowed'],
            'no_email': lambda r: r['email_status'] != 'ok',
            'no_2fa': lambda r: r['allowed'] and not r['has_2fa'],
            'suspended': lambda r: r['suspended'],
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
            'step_up_level': 'full',
            'step_up_otp': service.step_up_needs_2fa('full'),
            'settings': settings,
        })


class UserPinActionView(AdminViewMixin, View):
    permission_required = 'netbox_user_pin.change_userpin'
    actions = (
        'allow', 'deny', 'default', 'reset', 'reset-2fa', 'cancel-reset', 'suspend', 'unsuspend',
        'clear-lockout', 'force-change',
    )

    def post(self, request, pk, action):
        if (response := step_up_gate(request)) is not None:
            return response
        user = get_object_or_404(get_user_model(), pk=pk)
        if action not in self.actions:
            raise PermissionDenied
        if not service.can_manage(request.user, user):
            raise PermissionDenied(_('Delegates cannot manage the master, other delegates or themselves.'))
        try:
            if (response := self._do(request, user, action)) is not None:
                return response
        except ValidationError as exc:
            for message in exc.messages:
                messages.error(request, message)
        return redirect(_next_url(request, 'plugins:netbox_user_pin:user_list'))

    def _do(self, request, user, action):
        actor = request.user
        if action in ('allow', 'deny', 'default'):
            access = {'allow': PinAccess.ALLOWED, 'deny': PinAccess.DENIED, 'default': PinAccess.DEFAULT}[action]
            if approvals.required_for(ApprovalAction.ACCESS):
                return _four_eyes(request, ApprovalAction.ACCESS, {'user_id': user.pk, 'access': access},
                                  f'PIN access of {user}: {PinAccess(access).label}')
            service.set_access(user, access, actor=actor, request=request)
            messages.success(request, _('PIN access of {user} set to {access}.').format(
                user=user, access=PinAccess(access).label))
        elif action == 'reset':
            service.request_reset(user, 'pin', actor=actor, request=request)
            messages.success(request, _('PIN reset of {user} started. The user confirms it with 2FA in their own '
                                        'session and chooses a new PIN.').format(user=user))
        elif action == 'reset-2fa':
            service.request_reset(user, '2fa', actor=actor, request=request)
            messages.success(request, _('2FA reset of {user} started. The user confirms it with the PIN and sets up '
                                        '2FA again.').format(user=user))
        elif action == 'cancel-reset':
            service.cancel_reset(user, actor=actor, request=request)
            messages.success(request, _('Reset of {user} cancelled.').format(user=user))
        elif action == 'suspend':
            service.suspend(user, actor=actor, request=request)
            messages.success(request, _('PIN of {user} suspended.').format(user=user))
        elif action == 'unsuspend':
            service.unsuspend(user, actor=actor, request=request)
            messages.success(request, _('Suspension of {user} lifted.').format(user=user))
        elif action == 'clear-lockout':
            service.clear_lockout(user, actor=actor, request=request)
            messages.success(request, _('Lockout of {user} has been cleared.').format(user=user))
        elif action == 'force-change':
            if service.force_change(user, actor=actor, request=request):
                messages.success(request, _('{user} must change the PIN at next use.').format(user=user))


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
            'step_up_active': service.has_step_up(request, 'settings'),
            'step_up_left': service.step_up_seconds_left(request, 'settings'),
            'step_up_level': 'settings',
            'step_up_otp': service.step_up_needs_2fa('settings'),
        }

    def get(self, request):
        can_edit = request.user.has_perm('netbox_user_pin.change_pinsettings')
        form = PinSettingsForm(instance=PinSettings.load(), read_only=not can_edit)
        return render(request, self.template_name, self._context(request, form))

    def post(self, request):
        if not request.user.has_perm('netbox_user_pin.change_pinsettings'):
            raise PermissionDenied
        if (response := step_up_gate(request, 'settings')) is not None:
            return response
        form = PinSettingsForm(request.POST, instance=PinSettings.load())
        if form.is_valid():
            return _save_settings(request, form, ApprovalAction.SETTINGS, 'plugins:netbox_user_pin:settings')
        return render(request, self.template_name, self._context(request, form))


class MailSettingsView(AdminViewMixin, View):
    permission_required = 'netbox_user_pin.view_pinsettings'
    template_name = 'netbox_user_pin/mail.html'

    @staticmethod
    def eligible_recipients():
        settings = service.get_settings()
        users = get_user_model().objects.filter(is_active=True).exclude(email='').select_related('user_pin')
        return [u for u in users if service.email_status(u, settings) == 'ok' and service.is_allowed(u, settings)]

    def _render(self, request, form=None, test_form=None, domain_form=None, verify=None):
        settings = PinSettings.load()
        can_edit = request.user.has_perm('netbox_user_pin.change_pinsettings')
        netbox_email = getattr(django_settings, 'EMAIL', {}) or {}
        return render(request, self.template_name, {
            'form': form or MailSettingsForm(instance=settings, read_only=not can_edit),
            'test_form': test_form or self._test_form(),
            'domain_form': domain_form or DomainForm(),
            'domains': AllowedDomain.objects.all(),
            'verify_pk': request.GET.get('verify', ''),
            'verify': verify,
            'can_edit': can_edit,
            'settings': settings,
            'mail_source': mail.source(settings),
            'password_set': bool(settings.smtp_password),
            'netbox_server': netbox_email.get('SERVER', ''),
            'netbox_from': netbox_email.get('FROM_EMAIL', ''),
            'sender': mail.sender(settings),
            'step_up_active': service.has_step_up(request, 'settings'),
            'step_up_left': service.step_up_seconds_left(request, 'settings'),
            'step_up_level': 'settings',
            'step_up_otp': service.step_up_needs_2fa('settings'),
        })

    def _test_form(self, data=None):
        eligible = self.eligible_recipients()
        initial = {}
        default = next((u for u in eligible if u.pk == self.request.user.pk), None)
        if default:
            initial['recipient'] = default.pk
        return TestMailForm(data, eligible=eligible, initial=initial)

    def get(self, request):
        return self._render(request)

    def post(self, request):
        if not request.user.has_perm('netbox_user_pin.change_pinsettings'):
            raise PermissionDenied
        action = request.POST.get('action', 'save')
        # tests change nothing, so they need no PIN + 2FA confirmation
        if action not in ('test-connection', 'test-mail'):
            if (response := step_up_gate(request, 'settings')) is not None:
                return response
        handler = getattr(self, f'_post_{action.replace("-", "_")}', None)
        if handler is None:
            raise PermissionDenied
        return handler(request)

    def _post_save(self, request):
        form = MailSettingsForm(request.POST, instance=PinSettings.load())
        if form.is_valid():
            return _save_settings(request, form, ApprovalAction.MAIL_SETTINGS, 'plugins:netbox_user_pin:mail')
        return self._render(request, form=form)

    def _post_test_connection(self, request):
        ok, text = mail.test_connection(PinSettings.load())
        (messages.success if ok else messages.error)(request, text)
        return redirect('plugins:netbox_user_pin:mail')

    def _post_test_mail(self, request):
        test_form = self._test_form(request.POST)
        if not test_form.is_valid():
            return self._render(request, test_form=test_form)
        recipient = test_form.cleaned_data['recipient']
        if service.send_user_mail(recipient, _('Test e-mail'),
                                  _('This is a test e-mail from NetBox User PIN, sent by {actor}.').format(
                                      actor=request.user), request=request):
            messages.success(request, _('Test e-mail sent to {email}.').format(email=recipient.email))
        else:
            messages.error(request, _('The test e-mail could not be sent – see the audit log for the error.'))
        return redirect('plugins:netbox_user_pin:mail')

    @staticmethod
    def _ajax(request):
        return request.headers.get('X-Requested-With') == 'XMLHttpRequest'

    def _post_add_domain(self, request):
        domain_form = DomainForm(request.POST)
        if not domain_form.is_valid():
            return self._render(request, domain_form=domain_form)
        domain = service.normalize_domain(domain_form.cleaned_data['domain'])
        if approvals.required_for(ApprovalAction.DOMAIN_ADD):
            return _four_eyes(request, ApprovalAction.DOMAIN_ADD, {'domain': domain},
                              f'Add allowed e-mail domain @{domain}')
        try:
            obj = service.add_domain(domain, request.user, request=request)
        except ValidationError as exc:
            domain_form.add_error('domain', exc)
            return self._render(request, domain_form=domain_form)
        messages.success(request, _('Domain @{domain} added. Verify it now.').format(domain=obj.domain))
        # reopen the page with the verification pop-up for this domain
        return redirect(f"{reverse('plugins:netbox_user_pin:mail')}?verify={obj.pk}#domains")

    def _post_remove_domain(self, request):
        domain = get_object_or_404(AllowedDomain, pk=request.POST.get('pk'))
        service.remove_domain(domain, request.user, request=request)
        messages.success(request, _('Domain @{domain} removed.').format(domain=domain))
        return redirect('plugins:netbox_user_pin:mail')

    def _post_send_domain_code(self, request):
        domain = get_object_or_404(AllowedDomain, pk=request.POST.get('pk'))
        address = request.POST.get('address', '')
        try:
            service.send_domain_code(domain, address, request.user, request=request)
        except ValidationError as exc:
            if self._ajax(request):
                return JsonResponse({'ok': False, 'errors': exc.messages})
            messages.error(request, ' '.join(exc.messages))
        else:
            text = _('A verification code was sent to {address}.').format(address=address)
            if self._ajax(request):
                return JsonResponse({'ok': True, 'message': str(text)})
            messages.success(request, text)
        return redirect('plugins:netbox_user_pin:mail')

    def _post_verify_domain(self, request):
        domain = get_object_or_404(AllowedDomain, pk=request.POST.get('pk'))
        try:
            service.verify_domain(domain, request.POST.get('code'), request.user, request=request)
        except ValidationError as exc:
            if self._ajax(request):
                return JsonResponse({'ok': False, 'errors': exc.messages})
            messages.error(request, ' '.join(exc.messages))
        else:
            text = _('Domain @{domain} is verified.').format(domain=domain)
            messages.success(request, text)
            if self._ajax(request):
                return JsonResponse({'ok': True, 'message': str(text)})
        return redirect('plugins:netbox_user_pin:mail')


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
            'step_up_level': 'full',
            'step_up_otp': service.step_up_needs_2fa('full'),
        })

    def get(self, request):
        return self._render(request, DelegateForm())

    def post(self, request):
        if (response := step_up_gate(request)) is not None:
            return response
        action = request.POST.get('action', 'add')
        four_eyes = approvals.required_for(ApprovalAction.DELEGATE_ADD)
        if action in ('remove', 'toggle'):
            delegate = get_object_or_404(PinDelegate, pk=request.POST.get('pk'))
            if four_eyes:
                if action == 'remove':
                    return _four_eyes(request, ApprovalAction.DELEGATE_REMOVE, {'delegate_id': delegate.pk},
                                      f'Remove delegate {delegate}')
                return _four_eyes(request, ApprovalAction.DELEGATE_TOGGLE,
                                  {'delegate_id': delegate.pk, 'can_edit': not delegate.can_edit_settings},
                                  f'Delegate {delegate}: can edit settings = {not delegate.can_edit_settings}')
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
            user, group = form.cleaned_data['user'], form.cleaned_data['group']
            can_edit = form.cleaned_data['can_edit_settings']
            if four_eyes:
                return _four_eyes(
                    request, ApprovalAction.DELEGATE_ADD,
                    {'user_id': user.pk if user else None, 'group_id': group.pk if group else None, 'can_edit': can_edit},
                    f'Add delegate {"user " + str(user) if user else "group " + str(group)}, can edit settings = '
                    f'{can_edit}',
                )
            delegate = PinDelegate.objects.create(
                user=user, group=group, can_edit_settings=can_edit, created_by=request.user.username,
            )
            delegation.sync_permissions()
            service.log_event(
                PinEventAction.DELEGATE_ADDED, user=delegate.user, actor=request.user, request=request,
                detail=f'{delegate}, can edit settings = {delegate.can_edit_settings}',
            )
            messages.success(request, _('Delegate added.'))
            return redirect('plugins:netbox_user_pin:delegates')
        return self._render(request, form)


#
# Four-eyes approvals
#

class ApprovalListView(AdminViewMixin, View):
    permission_required = 'netbox_user_pin.view_userpin'

    def get(self, request):
        for req in ApprovalRequest.objects.filter(status=ApprovalStatus.PENDING):
            approvals.refresh(req)
        requests = ApprovalRequest.objects.prefetch_related('votes')
        pending = [r for r in requests.filter(status=ApprovalStatus.PENDING)]
        history = Paginator(requests.exclude(status=ApprovalStatus.PENDING), 30).get_page(request.GET.get('page'))
        return render(request, 'netbox_user_pin/approval_list.html', {
            'pending': [(r, approvals.can_vote(r, request.user)) for r in pending],
            'page': history,
            'settings': service.get_settings(),
        })


class ApprovalView(AdminViewMixin, View):
    permission_required = 'netbox_user_pin.view_userpin'
    template_name = 'netbox_user_pin/approval.html'

    def _context(self, request, req, form=None, bg_form=None):
        settings = service.get_settings()
        is_requester = request.user.pk == req.requested_by_id
        return {
            'req': req,
            'form': form or ApprovalForm(require_otp=settings.require_2fa_admin, with_reason=is_requester),
            'bg_form': bg_form or BreakGlassForm(require_otp=settings.require_2fa_admin),
            'can_vote': approvals.can_vote(req, request.user),
            'is_requester': is_requester,
            'can_cancel': req.is_open and (is_requester or request.user.is_superuser),
            'can_break_glass': req.is_open and settings.break_glass and request.user.is_superuser,
            **_approval_status_context(req),
        }

    def get(self, request, pk):
        req = approvals.refresh(get_object_or_404(ApprovalRequest, pk=pk))
        return render(request, self.template_name, self._context(request, req))

    def post(self, request, pk):
        req = approvals.refresh(get_object_or_404(ApprovalRequest, pk=pk))
        settings = service.get_settings()
        action = request.POST.get('action')
        if action == 'cancel':
            try:
                approvals.cancel(req, request.user, request=request)
            except ValidationError as exc:
                messages.error(request, ' '.join(exc.messages))
            return redirect('plugins:netbox_user_pin:approval', pk=pk)
        if action == 'break-glass':
            bg_form = BreakGlassForm(request.POST, require_otp=settings.require_2fa_admin)
            if bg_form.is_valid():
                try:
                    approvals.break_glass(req, request.user, bg_form.cleaned_data['reason'],
                                          bg_form.cleaned_data['pin'], bg_form.cleaned_data.get('otp'),
                                          request=request)
                except ValidationError as exc:
                    bg_form.add_error(None, ' '.join(exc.messages))
                else:
                    return redirect('plugins:netbox_user_pin:approval', pk=pk)
            return render(request, self.template_name, self._context(request, req, bg_form=bg_form))
        is_requester = request.user.pk == req.requested_by_id
        form = ApprovalForm(request.POST, require_otp=settings.require_2fa_admin, with_reason=is_requester)
        if form.is_valid():
            try:
                approvals.vote(req, request.user, approve=action != 'reject', pin=form.cleaned_data['pin'],
                               otp=form.cleaned_data.get('otp'), reason=form.cleaned_data.get('reason'),
                               request=request)
            except ValidationError as exc:
                form.add_error(None, ' '.join(exc.messages))
            else:
                return redirect('plugins:netbox_user_pin:approval', pk=pk)
        return render(request, self.template_name, self._context(request, req, form=form))


def _approval_status_context(req):
    votes = {v.user_id: v for v in req.votes.all()}
    requester_vote = votes.get(req.requested_by_id)
    others = [v for uid, v in votes.items() if uid != req.requested_by_id]
    return {
        'req': req,
        'requester_vote': requester_vote,
        'other_vote': others[0] if others else None,
        'is_open': req.is_open,
    }


class ApprovalStatusView(AdminViewMixin, View):
    """HTMX partial, polled every few seconds so both participants see each other's confirmation live."""
    permission_required = 'netbox_user_pin.view_userpin'

    def get(self, request, pk):
        req = approvals.refresh(get_object_or_404(ApprovalRequest, pk=pk))
        response = render(request, 'netbox_user_pin/inc/approval_status.html', _approval_status_context(req))
        if request.GET.get('open') and not req.is_open:
            response['HX-Refresh'] = 'true'   # finished meanwhile: reload the whole page
        return response


#
# Show backup codes (PIN + 2FA code or PIN + e-mailed verification code)
#

class BackupCodesView(AllowedUserMixin, View):
    template_name = 'netbox_user_pin/show_backup_codes.html'
    SESSION_KEY = '_netbox_user_pin_codes_verified'
    VERIFIED_SECONDS = 300

    def _render(self, request, form, codes=None, renewed=False):
        return render(request, self.template_name, {
            'form': form,
            'codes': codes,
            'renewed': renewed,
            'email_blockers': service.backup_codes_email_blockers(request.user),
            'email_pending': service.email_code_pending(request.user, 'backup-codes'),
        })

    def get(self, request):
        if not service.has_2fa(request.user):
            return redirect('plugins:netbox_user_pin:totp_setup')
        return self._render(request, BackupCodesForm())

    def post(self, request):
        import time
        action = request.POST.get('action')
        if action == 'send-email':
            try:
                service.send_backup_codes_email_code(request.user, request=request)
            except ValidationError as exc:
                messages.error(request, ' '.join(exc.messages))
            else:
                messages.success(request, _('A verification code was sent to {email}.').format(
                    email=request.user.email))
            return redirect('plugins:netbox_user_pin:backup_codes')
        if action == 'regenerate':
            if request.session.get(self.SESSION_KEY, 0) < time.time():
                messages.error(request, _('Please verify again.'))
                return redirect('plugins:netbox_user_pin:backup_codes')
            request.session.pop(self.SESSION_KEY, None)
            codes = service.new_backup_codes(request.user, request=request)
            return self._render(request, BackupCodesForm(), [(c, False) for c in codes], renewed=True)
        form = BackupCodesForm(request.POST)
        if form.is_valid():
            try:
                codes, renewed = service.show_backup_codes(
                    request.user, form.cleaned_data['pin'], otp=form.cleaned_data.get('otp'),
                    email_code=form.cleaned_data.get('email_code'), request=request,
                )
            except ValidationError as exc:
                field = {'pin': 'pin', 'otp': 'otp', 'email_code': 'email_code'}.get(exc.code)
                _apply_form_errors(form, exc, field)
            else:
                request.session[self.SESSION_KEY] = time.time() + self.VERIFIED_SECONDS
                return self._render(request, form, codes, renewed)
        return self._render(request, form)
