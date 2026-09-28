"""
Public API of netbox_user_pin. Other plugins should only use the functions exported here, the mixin/decorator in
``netbox_user_pin.mixins`` and the signals in ``netbox_user_pin.signals``.

    from netbox_user_pin import service

    service.has_pin(user)
    service.is_unlocked(request, scope='projects')
    service.unlock(request, pin, scope='projects')   # -> VerifyResult
    service.lock(request)                            # lock everything
    service.has_step_up(request)                     # fresh PIN (+ 2FA) confirmation for a sensitive action
"""
import enum
import logging
import secrets
import time
from dataclasses import dataclass
from datetime import timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext as _
from netbox.plugins import get_plugin_config
from utilities.request import get_client_ip

from . import crypto, mail, signals, totp
from .models import (
    AllowedDomain, PinAccess, PinAccessMode, PinEvent, PinEventAction, PinScopeMode, PinSettings, UserPin,
)
from .policy import validate_pin

__all__ = (
    'API_VERSION',
    'DEFAULT_SCOPE',
    'VerifyResult',
    'VerifyStatus',
    'can_manage',
    'cli_reset_2fa_command',
    'cancel_reset',
    'complete_2fa_reset',
    'complete_pin_reset',
    'change_pin',
    'clear_lockout',
    'complete_recovery',
    'confirm_totp_enrollment',
    'disable_totp',
    'email_configured',
    'email_status',
    'force_change',
    'full_name',
    'get_settings',
    'has_2fa',
    'has_pin',
    'has_step_up',
    'is_allowed',
    'is_master',
    'is_pin_admin',
    'is_unlocked',
    'lock',
    'log_event',
    'maybe_warn_expiry',
    'new_backup_codes',
    'pin_expired',
    'pin_expires_at',
    'is_suspended',
    'recovery_blockers',
    'request_reset',
    'reset_pin',
    'reset_totp',
    'send_backup_codes_email_code',
    'set_access',
    'show_backup_codes',
    'set_pin',
    'start_recovery',
    'start_totp_enrollment',
    'step_up',
    'step_up_blockers',
    'step_up_needs_2fa',
    'suspend',
    'unsuspend',
    'unlock',
    'unlocked_scopes',
    'user_label',
    'verify_pin',
    'verify_second_factor',
)

# Bumped when the public API (service, mixins, signals) gains features. Never decreases; existing calls keep working.
#   1 = PIN, unlock, lock, signals
#   2 = step-up (PIN + 2FA) for sensitive actions, 2FA, e-mail recovery
API_VERSION = 2

logger = logging.getLogger('netbox_user_pin')

SESSION_KEY = '_netbox_user_pin'
STEP_UP_SESSION_KEY = '_netbox_user_pin_step_up'
ENROLL_SESSION_KEY = '_netbox_user_pin_totp_enroll'
RECOVERY_RESEND_SECONDS = 60
DEFAULT_SCOPE = 'default'
GLOBAL_SCOPE_KEY = '*'


class VerifyStatus(enum.Enum):
    OK = 'ok'
    WRONG = 'wrong'
    LOCKED_OUT = 'locked_out'
    NO_PIN = 'no_pin'
    NOT_ALLOWED = 'not_allowed'
    SUSPENDED = 'suspended'
    NEED_2FA = 'need_2fa'          # 2FA required but not enrolled
    WRONG_2FA = 'wrong_2fa'


@dataclass(frozen=True)
class VerifyResult:
    status: VerifyStatus
    remaining_attempts: int | None = None
    locked_until: object = None

    @property
    def ok(self):
        return self.status is VerifyStatus.OK

    def __bool__(self):
        return self.ok


#
# Helpers
#

def get_settings():
    return PinSettings.load()


def _hasher():
    return PasswordHasher(
        time_cost=get_plugin_config('netbox_user_pin', 'argon2_time_cost'),
        memory_cost=get_plugin_config('netbox_user_pin', 'argon2_memory_cost'),
        parallelism=get_plugin_config('netbox_user_pin', 'argon2_parallelism'),
    )


def _user_or_none(user):
    return user if user is not None and getattr(user, 'is_authenticated', False) else None


def log_event(action, user=None, actor=None, request=None, scope='', detail=''):
    """Write an audit record. Never pass a PIN or hash in ``detail``."""
    user = _user_or_none(user)
    if actor is None and request is not None:
        actor = getattr(request, 'user', None)
    actor = _user_or_none(actor)
    ip_address = None
    user_agent = ''
    if request is not None:
        try:
            ip = get_client_ip(request)
            ip_address = str(ip) if ip else None
        except ValueError:
            pass
        user_agent = request.META.get('HTTP_USER_AGENT', '')[:255]
    return PinEvent.objects.create(
        action=action,
        user=user,
        username=user.username if user else '',
        actor=actor,
        actor_username=actor.username if actor else '',
        scope=scope or '',
        ip_address=ip_address,
        user_agent=user_agent,
        detail=detail,
    )


def _get_pin(user):
    if _user_or_none(user) is None:
        return None
    return UserPin.objects.filter(user=user).first()


def _hash_and_encrypt(user_pin, pin):
    return crypto.encrypt(_hasher().hash(pin), user_pin.aad)


def _session_key_for(scope, settings=None):
    settings = settings or get_settings()
    if settings.scope_mode == PinScopeMode.GLOBAL:
        return GLOBAL_SCOPE_KEY
    return scope or DEFAULT_SCOPE


#
# PIN state
#

def has_pin(user):
    user_pin = _get_pin(user)
    return bool(user_pin and user_pin.is_set)


def is_allowed(user, settings=None):
    """True if the administrator permits ``user`` to use a PIN (see PinSettings.access_mode)."""
    if _user_or_none(user) is None:
        return False
    if user.is_superuser:
        return True
    settings = settings or get_settings()
    user_pin = _get_pin(user)
    access = user_pin.access if user_pin else PinAccess.DEFAULT
    if access == PinAccess.DENIED:
        return False
    if access == PinAccess.ALLOWED:
        return True
    if settings.access_mode == PinAccessMode.ALL:
        return True
    # holders of a role (and the invited) always may use a PIN – they need it to accept and to act
    from .models import OPEN_ROLE_STATUSES, PinDelegate
    return PinDelegate.objects.filter(user=user, status__in=OPEN_ROLE_STATUSES).exists()


def _not_allowed_error():
    return ValidationError(_('You are not permitted to use a PIN. Ask an administrator.'), code='not_allowed')


def pin_expires_at(user_pin, settings=None):
    settings = settings or get_settings()
    if not user_pin or not user_pin.is_set or not user_pin.changed:
        return None
    return user_pin.changed + timedelta(days=settings.max_age_days)


def pin_expired(user, settings=None):
    """True when the PIN must be changed: older than the maximum age, or a change was forced."""
    settings = settings or get_settings()
    user_pin = _get_pin(user)
    if not user_pin or not user_pin.is_set:
        return False
    if user_pin.must_change:
        return True
    expires = pin_expires_at(user_pin, settings)
    return expires is not None and expires < timezone.now()


def set_pin(user, pin, request=None):
    """
    Set the PIN of a user who has none (first time or after an admin reset). Raises ValidationError.
    """
    settings = get_settings()
    if not is_allowed(user, settings):
        log_event(PinEventAction.NOT_ALLOWED, user=user, request=request, detail='set PIN')
        raise _not_allowed_error()
    validate_pin(pin, settings)
    with transaction.atomic():
        user_pin, _created = UserPin.objects.select_for_update().get_or_create(user=user)
        if user_pin.is_set:
            raise ValidationError(_('A PIN is already set. Use the change form.'), code='exists')
        user_pin.pin_hash = _hash_and_encrypt(user_pin, pin)
        user_pin.version += 1
        user_pin.failed_attempts = 0
        user_pin.locked_until = None
        user_pin.changed = timezone.now()
        user_pin.must_change = False
        user_pin.expiry_warned = None
        user_pin.save()
    log_event(PinEventAction.SET, user=user, actor=user, request=request)
    notify(user, _('Your PIN was set'), _('A PIN was set for your NetBox account.'), request=request)
    signals.pin_set.send(sender=UserPin, user=user, request=request, scope='')
    if request is not None:
        lock(request, send_signal=False)
    return user_pin


def change_pin(user, current_pin, new_pin, request=None):
    """
    Change an existing PIN. The current PIN is verified first (a wrong one counts as a failed attempt).
    Raises ValidationError.
    """
    settings = get_settings()
    result = verify_pin(user, current_pin, request=request, scope='change-pin')
    if not result:
        if result.status is VerifyStatus.NOT_ALLOWED:
            raise _not_allowed_error()
        if result.status is VerifyStatus.LOCKED_OUT:
            raise ValidationError(_('Too many failed attempts. Try again later.'), code='locked_out')
        raise ValidationError(_('The current PIN is not correct.'), code='wrong')
    validate_pin(new_pin, settings)
    if new_pin == current_pin:
        raise ValidationError(_('The new PIN must differ from the current one.'), code='same')
    with transaction.atomic():
        user_pin = UserPin.objects.select_for_update().get(user=user)
        user_pin.pin_hash = _hash_and_encrypt(user_pin, new_pin)
        user_pin.version += 1
        user_pin.changed = timezone.now()
        user_pin.must_change = False
        user_pin.expiry_warned = None
        user_pin.save()
    log_event(PinEventAction.CHANGED, user=user, actor=user, request=request)
    notify(user, _('Your PIN was changed'), _('The PIN of your NetBox account was changed.'), request=request)
    signals.pin_changed.send(sender=UserPin, user=user, request=request, scope='')
    if request is not None:
        lock(request, send_signal=False)
    return user_pin


def verify_pin(user, pin, request=None, scope=''):
    """
    Check a PIN without touching the session. Handles failed attempt counting and lockout.
    """
    settings = get_settings()
    if _user_or_none(user) is None:
        return VerifyResult(VerifyStatus.NO_PIN)
    if not is_allowed(user, settings):
        log_event(PinEventAction.NOT_ALLOWED, user=user, request=request, scope=scope)
        return VerifyResult(VerifyStatus.NOT_ALLOWED)
    decryption_error = None
    with transaction.atomic():
        user_pin = UserPin.objects.select_for_update().filter(user=user).first()
        if user_pin is None or not user_pin.is_set:
            return VerifyResult(VerifyStatus.NO_PIN)

        if user_pin.suspended:
            log_event(PinEventAction.REJECTED_LOCKED, user=user, request=request, scope=scope, detail='suspended')
            return VerifyResult(VerifyStatus.SUSPENDED)

        if user_pin.is_locked_out:
            log_event(PinEventAction.REJECTED_LOCKED, user=user, request=request, scope=scope)
            return VerifyResult(VerifyStatus.LOCKED_OUT, 0, user_pin.locked_until)

        try:
            stored_hash = crypto.decrypt(user_pin.pin_hash, user_pin.aad)
        except crypto.DecryptionError as exc:
            decryption_error = exc

        if decryption_error is None:
            matched = _check_hash(user_pin, stored_hash, pin)
            if not matched:
                remaining = _register_failure(user_pin, settings)

    if decryption_error is not None:
        logger.error('Cannot decrypt PIN of user %s: %s', user, decryption_error)
        log_event(PinEventAction.ERROR, user=user, request=request, scope=scope, detail=str(decryption_error))
        raise decryption_error

    if matched:
        log_event(PinEventAction.VERIFIED, user=user, request=request, scope=scope)
        return VerifyResult(VerifyStatus.OK)

    return _after_failure(PinEventAction.FAILED, user, user_pin, remaining, request, scope)


def _register_failure(user_pin, settings):
    """Count a failed PIN / 2FA attempt (caller holds the row lock). Returns the remaining attempts."""
    user_pin.failed_attempts += 1
    remaining = max(settings.max_attempts - user_pin.failed_attempts, 0)
    if remaining == 0:
        user_pin.locked_until = timezone.now() + timedelta(minutes=settings.lockout_minutes)
        user_pin.failed_attempts = 0
    user_pin.save()
    return remaining


def _after_failure(action, user, user_pin, remaining, request, scope):
    log_event(action, user=user, request=request, scope=scope, detail=f'remaining attempts: {remaining}')
    signals.pin_failed.send(
        sender=UserPin, user=user, request=request, scope=scope, remaining_attempts=remaining
    )
    if remaining == 0:
        log_event(
            PinEventAction.LOCKED_OUT, user=user, request=request, scope=scope,
            detail=f'until {user_pin.locked_until.isoformat()}',
        )
        signals.pin_locked_out.send(
            sender=UserPin, user=user, request=request, scope=scope, until=user_pin.locked_until
        )
        notify(
            user, _('Your PIN is locked'),
            _('Too many wrong PIN / 2FA attempts. Your PIN is locked until {time}. If this was not you, '
              'contact your administrator.').format(time=timezone.localtime(user_pin.locked_until)),
            request=request,
        )
        return VerifyResult(VerifyStatus.LOCKED_OUT, 0, user_pin.locked_until)
    return VerifyResult(VerifyStatus.WRONG, remaining)


def _check_hash(user_pin, stored_hash, pin):
    """Compare ``pin`` with the decrypted hash; on success reset counters (caller holds the row lock)."""
    hasher = _hasher()
    try:
        matched = hasher.verify(stored_hash, pin or '')
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    if matched:
        user_pin.failed_attempts = 0
        user_pin.locked_until = None
        user_pin.last_verified = timezone.now()
        if hasher.check_needs_rehash(stored_hash):
            user_pin.pin_hash = _hash_and_encrypt(user_pin, pin)
        user_pin.save()
    return matched


#
# Session unlock state
#

def unlock(request, pin, scope=None, otp=None):
    """
    Verify the PIN (and the 2FA code when 'Require 2FA on every unlock' is on) of ``request.user`` and, if
    correct, unlock ``scope`` in the session.
    """
    settings = get_settings()
    scope = scope or DEFAULT_SCOPE
    if settings.require_2fa_unlock and not has_2fa(request.user):
        return VerifyResult(VerifyStatus.NEED_2FA)
    result = verify_pin(request.user, pin, request=request, scope=scope)
    if result and settings.require_2fa_unlock:
        result = verify_second_factor(request.user, otp, request=request, scope=scope)
    if result:
        user_pin = _get_pin(request.user)
        data = request.session.get(SESSION_KEY) or {}
        if data.get('v') != user_pin.version or data.get('u') != request.user.pk:
            data = {'v': user_pin.version, 'u': request.user.pk, 'unlocks': {}}
        data['unlocks'][_session_key_for(scope, settings)] = time.time() + settings.unlock_minutes * 60
        request.session[SESSION_KEY] = data
        request.session.modified = True
        signals.pin_unlocked.send(sender=UserPin, user=request.user, request=request, scope=scope)
        maybe_warn_expiry(request.user, request=request)
    return result


def is_unlocked(request, scope=None, touch=True):
    """
    True if ``request.user`` has entered a valid PIN for ``scope`` recently. With ``touch`` and sliding unlock
    enabled, the unlock timer is restarted.
    """
    user = _user_or_none(getattr(request, 'user', None))
    if user is None:
        return False
    data = request.session.get(SESSION_KEY)
    if not data or data.get('u') != user.pk:
        return False
    settings = get_settings()
    user_pin = _get_pin(user)
    if not user_pin or not user_pin.is_set or data.get('v') != user_pin.version or user_pin.suspended:
        return False
    if pin_expired(user, settings) or not is_allowed(user, settings):
        return False
    key = _session_key_for(scope, settings)
    expires = data.get('unlocks', {}).get(key)
    now = time.time()
    if not expires or expires <= now:
        return False
    if touch and settings.sliding_unlock:
        data['unlocks'][key] = now + settings.unlock_minutes * 60
        request.session[SESSION_KEY] = data
        request.session.modified = True
    return True


def unlocked_scopes(request):
    """{scope_key: seconds_left} for display purposes."""
    data = request.session.get(SESSION_KEY) or {}
    user = _user_or_none(getattr(request, 'user', None))
    user_pin = _get_pin(user)
    if not user_pin or data.get('u') != user.pk or data.get('v') != user_pin.version:
        return {}
    now = time.time()
    return {k: int(v - now) for k, v in data.get('unlocks', {}).items() if v > now}


def lock(request, scope=None, send_signal=True):
    """Lock ``scope`` (or everything when scope is None) in the current session."""
    data = request.session.get(SESSION_KEY)
    if not data:
        return
    if scope is None:
        data['unlocks'] = {}
    else:
        data.get('unlocks', {}).pop(_session_key_for(scope), None)
    request.session[SESSION_KEY] = data
    request.session.modified = True
    if send_signal:
        log_event(PinEventAction.LOCKED, user=request.user, request=request, scope=scope or '')
        signals.pin_locked.send(sender=UserPin, user=request.user, request=request, scope=scope or '')


#
# Administration
#

def reset_pin(user, actor, request=None):
    """Remove a user's PIN; they must set a new one. Existing unlocks of that user become invalid."""
    with transaction.atomic():
        user_pin, _created = UserPin.objects.select_for_update().get_or_create(user=user)
        user_pin.pin_hash = ''
        user_pin.version += 1
        user_pin.failed_attempts = 0
        user_pin.locked_until = None
        user_pin.changed = None
        user_pin.must_change = False
        user_pin.expiry_warned = None
        user_pin.save()
    log_event(PinEventAction.RESET, user=user, actor=actor, request=request)
    notify(user, _('Your PIN was reset'),
           _('Your PIN was reset by {actor}. Set a new PIN the next time you are asked for it.').format(actor=actor),
           request=request)
    signals.pin_reset.send(sender=UserPin, user=user, actor=actor, request=request, scope='')


def set_access(user, access, actor, request=None):
    """Allow / deny / reset to default whether ``user`` may use a PIN."""
    if access not in PinAccess.values:
        raise ValueError(f'Invalid access value: {access}')
    with transaction.atomic():
        user_pin, _created = UserPin.objects.select_for_update().get_or_create(user=user)
        old = user_pin.access
        user_pin.access = access
        user_pin.save()
    log_event(PinEventAction.ACCESS_CHANGED, user=user, actor=actor, request=request, detail=f'{old} -> {access}')


def clear_lockout(user, actor, request=None):
    UserPin.objects.filter(user=user).update(failed_attempts=0, locked_until=None)
    log_event(PinEventAction.LOCKOUT_CLEARED, user=user, actor=actor, request=request)


def force_change(user, actor, request=None):
    """Require ``user`` to choose a new PIN at the next use (also used to test PIN rotation)."""
    updated = UserPin.objects.filter(user=user).exclude(pin_hash='').update(must_change=True)
    if updated:
        log_event(PinEventAction.FORCE_CHANGE, user=user, actor=actor, request=request)
    return bool(updated)


#
# Roles
#

def is_master(user):
    """The master is a NetBox superuser."""
    return bool(_user_or_none(user) and user.is_active and user.is_superuser)


def is_pin_admin(user):
    """Master, CORE deputy, department head or delegate (anyone allowed to manage other users' PINs)."""
    from . import roles
    return bool(_user_or_none(user) and user.is_active and roles.is_manager(user))


def can_manage(actor, target):
    """
    Separation of duties: nobody manages themselves here (own PIN only under My PIN); the master manages everybody
    else; CORE deputies everybody except the master and other CORE deputies; department heads and delegates only
    the members of their department (see roles.can_manage).
    """
    from . import roles
    return roles.can_manage(actor, target)


#
# Two-factor authentication (TOTP + backup codes)
#

def has_2fa(user):
    user_pin = _get_pin(user)
    return bool(user_pin and user_pin.has_2fa)


def _totp_aad(user_pin):
    return f'netbox_user_pin:totp:{user_pin.user_id}'.encode()


def start_totp_enrollment(request):
    """Create a pending secret (kept in the server-side session until confirmed). Returns (secret, uri)."""
    secret = totp.generate_secret()
    request.session[ENROLL_SESSION_KEY] = {'u': request.user.pk, 'secret': secret, 'created': time.time()}
    return secret, totp.provisioning_uri(secret, request.user.username)


def pending_totp_secret(request):
    data = request.session.get(ENROLL_SESSION_KEY) or {}
    if data.get('u') != request.user.pk or time.time() - data.get('created', 0) > 15 * 60:
        return None
    return data.get('secret')


def confirm_totp_enrollment(request, code):
    """Activate 2FA after the first valid code. Returns the list of new backup codes (shown only once)."""
    secret = pending_totp_secret(request)
    if not secret:
        raise ValidationError(_('The setup expired. Start again.'), code='expired')
    step = totp.match_step(secret, code)
    if step is None:
        log_event(PinEventAction.TOTP_FAILED, user=request.user, request=request, detail='enrollment')
        raise ValidationError(_('The code is not correct. Check the time on your phone and try again.'),
                              code='wrong')
    codes = totp.generate_backup_codes()
    with transaction.atomic():
        user_pin, _created = UserPin.objects.select_for_update().get_or_create(user=request.user)
        user_pin.totp_secret = crypto.encrypt(secret, _totp_aad(user_pin))
        user_pin.totp_enabled = timezone.now()
        user_pin.totp_last_step = step
        user_pin.backup_codes = [totp.hash_backup_code(c) for c in codes]
        user_pin.backup_codes_encrypted = _encrypt_backup_codes(user_pin, codes)
        user_pin.save()
    request.session.pop(ENROLL_SESSION_KEY, None)
    log_event(PinEventAction.TOTP_ENABLED, user=request.user, actor=request.user, request=request)
    notify(request.user, _('Two-factor authentication enabled'),
           _('Two-factor authentication was enabled for your NetBox PIN.'), request=request)
    return codes


def verify_second_factor(user, code, request=None, scope='2fa'):
    """
    Check a TOTP code (a code / time step is accepted only once) or a one-time backup code.
    Wrong codes count towards the same lockout as wrong PINs.
    """
    settings = get_settings()
    code = (code or '').strip()
    with transaction.atomic():
        user_pin = UserPin.objects.select_for_update().filter(user=user).first()
        if user_pin is None or not user_pin.has_2fa:
            return VerifyResult(VerifyStatus.NEED_2FA)
        if user_pin.is_locked_out:
            log_event(PinEventAction.REJECTED_LOCKED, user=user, request=request, scope=scope)
            return VerifyResult(VerifyStatus.LOCKED_OUT, 0, user_pin.locked_until)
        secret = crypto.decrypt(user_pin.totp_secret, _totp_aad(user_pin))
        step = totp.match_step(secret, code)
        if step is not None and step > user_pin.totp_last_step:
            user_pin.totp_last_step = step
            user_pin.failed_attempts = 0
            user_pin.save()
            return VerifyResult(VerifyStatus.OK)
        digest = totp.hash_backup_code(code)
        if len(totp.normalize_backup_code(code)) == 20 and digest in user_pin.backup_codes:
            user_pin.backup_codes = [d for d in user_pin.backup_codes if d != digest]
            user_pin.failed_attempts = 0
            user_pin.save()
            used_backup = True
        else:
            used_backup = False
            remaining = _register_failure(user_pin, settings)
    if used_backup:
        log_event(PinEventAction.BACKUP_CODE_USED, user=user, request=request, scope=scope,
                  detail=f'{len(user_pin.backup_codes)} backup codes left')
        return VerifyResult(VerifyStatus.OK)
    result = _after_failure(PinEventAction.TOTP_FAILED, user, user_pin, remaining, request, scope)
    if result.status is VerifyStatus.WRONG:
        return VerifyResult(VerifyStatus.WRONG_2FA, result.remaining_attempts)
    return result


def _backup_aad(user_pin):
    return f'netbox_user_pin:backup:{user_pin.user_id}'.encode()


def _encrypt_backup_codes(user_pin, codes):
    import json
    return crypto.encrypt(json.dumps(codes), _backup_aad(user_pin))


def new_backup_codes(user, request=None):
    """Replace the backup codes (caller must have verified the user). Returns the new codes."""
    codes = totp.generate_backup_codes()
    user_pin = UserPin.objects.get(user=user)
    UserPin.objects.filter(pk=user_pin.pk).update(
        backup_codes=[totp.hash_backup_code(c) for c in codes],
        backup_codes_encrypted=_encrypt_backup_codes(user_pin, codes),
    )
    log_event(PinEventAction.BACKUP_CODES_NEW, user=user, request=request)
    return codes


def backup_codes_email_blockers(user, settings=None):
    """Reasons why a verification code cannot be e-mailed to ``user`` (empty = possible)."""
    settings = settings or get_settings()
    reasons = []
    if not email_configured():
        reasons.append('mail_not_configured')
    status = email_status(user, settings)
    if status != 'ok':
        reasons.append(f'email_{status}')
    return reasons


def send_backup_codes_email_code(user, request=None):
    if backup_codes_email_blockers(user):
        raise ValidationError(_('No verification e-mail can be sent to your account.'), code='blocked')
    _send_email_code(
        user, 'backup-codes', _('Verification code'),
        _('Your verification code for showing your 2FA backup codes is: {code}\n\nIt is valid for {minutes} '
          'minutes. If you did not request it, contact your administrator.'),
        request=request,
    )
    log_event(PinEventAction.EMAIL_CODE_SENT, user=user, request=request, detail='backup codes')


def show_backup_codes(user, pin, otp=None, email_code=None, request=None):
    """
    Return [(code, used), ...] after verifying the PIN plus either a 2FA code or an e-mailed verification code.
    Users enrolled before encrypted storage get new codes (the old ones cannot be shown).
    Raises ValidationError (code 'pin', 'otp' or 'email_code').
    """
    import json
    if not has_2fa(user):
        raise ValidationError(_('Two-factor authentication is not set up.'), code='no_2fa')
    result = verify_pin(user, pin, request=request, scope='backup-codes')
    if not result:
        raise ValidationError(_('The PIN is not correct.'), code='pin')
    if otp:
        if not verify_second_factor(user, otp, request=request, scope='backup-codes'):
            raise ValidationError(_('The 2FA code is not correct.'), code='otp')
    elif not _check_email_code(user, 'backup-codes', email_code):
        raise ValidationError(_('The e-mail code is wrong or expired.'), code='email_code')
    user_pin = UserPin.objects.get(user=user)
    renewed = False
    if user_pin.backup_codes_encrypted:
        codes = json.loads(crypto.decrypt(user_pin.backup_codes_encrypted, _backup_aad(user_pin)))
    else:
        codes, renewed = new_backup_codes(user, request=request), True
        user_pin.refresh_from_db()
    unused = set(user_pin.backup_codes)
    log_event(PinEventAction.BACKUP_CODES_VIEWED, user=user, request=request,
              detail='verified with ' + ('2FA' if otp else 'e-mail code') + (', new codes issued' if renewed else ''))
    notify(user, _('Your backup codes were viewed'),
           _('Your 2FA backup codes were displayed in NetBox. If this was not you, contact your administrator and '
             'generate new codes.'), request=request)
    return [(code, totp.hash_backup_code(code) not in unused) for code in codes], renewed


def backup_codes_left(user):
    user_pin = _get_pin(user)
    return len(user_pin.backup_codes) if user_pin else 0


def _clear_totp(user):
    UserPin.objects.filter(user=user).update(
        totp_secret='', totp_enabled=None, totp_last_step=0, backup_codes=[], backup_codes_encrypted='',
    )


def disable_totp(user, request=None):
    """Turn 2FA off for oneself (caller must have verified PIN + 2FA)."""
    _clear_totp(user)
    log_event(PinEventAction.TOTP_DISABLED, user=user, actor=user, request=request)
    notify(user, _('Two-factor authentication disabled'),
           _('Two-factor authentication was disabled for your NetBox PIN.'), request=request)


def reset_totp(user, actor, request=None):
    """Administrator removes a user's 2FA (lost phone); the user enrolls again."""
    _clear_totp(user)
    log_event(PinEventAction.TOTP_RESET, user=user, actor=actor, request=request)
    notify(user, _('Two-factor authentication reset'),
           _('Your two-factor authentication was reset by {actor}. Set it up again under My PIN.').format(
               actor=actor), request=request)


#
# Step-up: fresh PIN (+ 2FA) confirmation for sensitive actions
#

def step_up_needs_2fa(level='full', settings=None):
    """
    ``level='full'``: actions on other people's accounts, delegates, approvals – PIN + 2FA (when
    'Require PIN + 2FA for administrative actions' is on). ``level='settings'``: Settings and Mail pages – the PIN
    is enough unless 'Require 2FA also for settings' is on.
    """
    settings = settings or get_settings()
    if not settings.require_2fa_admin:
        return False
    return level != 'settings' or settings.require_2fa_settings


def step_up_blockers(user, settings=None, level='full'):
    """Reasons why ``user`` cannot perform a step-up yet (empty list = possible)."""
    settings = settings or get_settings()
    reasons = []
    if not has_pin(user):
        reasons.append('no_pin')
    if step_up_needs_2fa(level, settings) and not has_2fa(user):
        reasons.append('no_2fa')
    return reasons


def step_up(request, pin, otp=None, level='full'):
    """Confirm identity with PIN (+ 2FA for level 'full') and open the administrative window."""
    settings = get_settings()
    needs_2fa = step_up_needs_2fa(level, settings)
    if step_up_blockers(request.user, settings, level):
        return VerifyResult(VerifyStatus.NEED_2FA if has_pin(request.user) else VerifyStatus.NO_PIN)
    result = verify_pin(request.user, pin, request=request, scope='step-up')
    if result and needs_2fa:
        result = verify_second_factor(request.user, otp, request=request, scope='step-up')
    if result:
        user_pin = _get_pin(request.user)
        previous = request.session.get(STEP_UP_SESSION_KEY) or {}
        keep_2fa = previous.get('u') == request.user.pk and previous.get('fa2') and previous.get('until', 0) > time.time()
        request.session[STEP_UP_SESSION_KEY] = {
            'u': request.user.pk, 'v': user_pin.version, 'until': time.time() + settings.step_up_minutes * 60,
            'fa2': bool(needs_2fa or keep_2fa or not settings.require_2fa_admin),
        }
        log_event(PinEventAction.STEP_UP_OK, user=request.user, request=request,
                  detail='PIN + 2FA' if needs_2fa else 'PIN')
    elif result.status in (VerifyStatus.WRONG, VerifyStatus.WRONG_2FA):
        log_event(PinEventAction.STEP_UP_FAILED, user=request.user, request=request)
    return result


def has_step_up(request, level='full'):
    """True while the administrative window opened by step_up() is valid for ``level``."""
    user = _user_or_none(getattr(request, 'user', None))
    data = request.session.get(STEP_UP_SESSION_KEY) if user else None
    if not data or data.get('u') != user.pk or data.get('until', 0) <= time.time():
        return False
    if step_up_needs_2fa(level) and not data.get('fa2'):
        return False
    user_pin = _get_pin(user)
    return bool(user_pin and user_pin.version == data.get('v') and not user_pin.suspended and is_allowed(user))


def step_up_seconds_left(request, level='full'):
    data = request.session.get(STEP_UP_SESSION_KEY) or {}
    return max(int(data.get('until', 0) - time.time()), 0) if has_step_up(request, level) else 0


def end_step_up(request):
    request.session.pop(STEP_UP_SESSION_KEY, None)


#
# E-mail
#

def full_name(user, settings=None):
    """First and last name when 'Show first and last name' is on, else ''."""
    settings = settings or get_settings()
    if not settings.show_full_names or user is None:
        return ''
    return (user.get_full_name() or '').strip()


def user_label(user, settings=None):
    """'username (First Last)' or just 'username'."""
    name = full_name(user, settings)
    return f'{user.username} ({name})' if name else user.username


def email_configured(settings=None):
    return mail.configured(settings or get_settings())


def allowed_domains(settings=None):
    """Verified allowed e-mail domains (lower case)."""
    return set(AllowedDomain.objects.exclude(verified=None).values_list('domain', flat=True))


def normalize_domain(domain):
    return (domain or '').strip().lower().lstrip('@').rstrip('.')


def email_status(user, settings=None):
    """'ok', 'missing' (no address) or 'domain' (address outside the verified allowed domains)."""
    address = (getattr(user, 'email', '') or '').strip()
    if not address or '@' not in address:
        return 'missing'
    if address.rsplit('@', 1)[1].lower() not in allowed_domains(settings):
        return 'domain'
    return 'ok'


def _deliver(settings, recipients, subject, body):
    mail.send(settings, recipients, f'[NetBox PIN] {subject}',
              f'{body}\n\n-- \nNetBox User PIN. This is an automatic message.')


def send_user_mail(user, subject, body, request=None, settings=None):
    """Send an e-mail to ``user`` if the address is in a verified allowed domain. Returns True when sent."""
    settings = settings or get_settings()
    if email_status(user, settings) != 'ok' or not email_configured(settings):
        return False
    try:
        _deliver(settings, [user.email], subject, body)
    except Exception as exc:  # SMTP problems must not break the security flow
        logger.warning('Cannot send PIN e-mail to %s: %s', user, exc)
        log_event(PinEventAction.MAIL_FAILED, user=user, request=request, detail=f'{subject}: {exc}')
        return False
    log_event(PinEventAction.MAIL_SENT, user=user, request=request, detail=subject)
    return True


#
# Allowed e-mail domains (must be verified before use)
#

def add_domain(domain, actor, request=None):
    domain = normalize_domain(domain)
    if not domain or '.' not in domain or '@' in domain or ' ' in domain:
        raise ValidationError(_('Enter a domain such as firma.sk.'), code='invalid')
    obj, created = AllowedDomain.objects.get_or_create(
        domain=domain, defaults={'created_by': getattr(actor, 'username', '')})
    if created:
        log_event(PinEventAction.DOMAIN_ADDED, actor=actor, request=request, detail=domain)
    return obj


def remove_domain(domain_obj, actor, request=None):
    name = domain_obj.domain
    domain_obj.delete()
    log_event(PinEventAction.DOMAIN_REMOVED, actor=actor, request=request, detail=name)


def send_domain_code(domain_obj, address, actor, request=None):
    """Send a verification code to ``address`` which must be in the domain."""
    settings = get_settings()
    address = (address or '').strip()
    if not address.lower().endswith('@' + domain_obj.domain):
        raise ValidationError(_('The address must end with @{domain}.').format(domain=domain_obj.domain),
                              code='address')
    if not email_configured(settings):
        raise ValidationError(_('No mail server is configured.'), code='mail')
    code = f'{secrets.randbelow(10 ** 8):08d}'
    try:
        _deliver(settings, [address], _('Domain verification'),
                 _('Verification code for the domain {domain}: {code}\n\nEnter it in NetBox > User PIN > Mail. '
                   'It is valid for {minutes} minutes.').format(domain=domain_obj.domain, code=code,
                                                               minutes=settings.recovery_minutes))
    except Exception as exc:
        log_event(PinEventAction.MAIL_FAILED, actor=actor, request=request, detail=f'domain verification: {exc}')
        raise ValidationError(_('The e-mail could not be sent: {error}').format(error=exc), code='mail')
    AllowedDomain.objects.filter(pk=domain_obj.pk).update(
        code=crypto.keyed_digest(code, f'domain:{domain_obj.pk}:{address.lower()}'), code_email=address,
        code_expires=timezone.now() + timedelta(minutes=settings.recovery_minutes), code_attempts=0,
    )
    log_event(PinEventAction.EMAIL_CODE_SENT, actor=actor, request=request,
              detail=f'domain verification {domain_obj.domain} -> {address}')


def verify_domain(domain_obj, code, actor, request=None):
    domain_obj.refresh_from_db()
    ok = (domain_obj.code_pending and domain_obj.code_attempts < 5 and crypto.check_keyed_digest(
        (code or '').strip(), f'domain:{domain_obj.pk}:{domain_obj.code_email.lower()}', domain_obj.code))
    if not ok:
        AllowedDomain.objects.filter(pk=domain_obj.pk).update(code_attempts=domain_obj.code_attempts + 1)
        log_event(PinEventAction.DOMAIN_VERIFY_FAILED, actor=actor, request=request, detail=domain_obj.domain)
        raise ValidationError(_('The code is wrong or expired.'), code='code')
    AllowedDomain.objects.filter(pk=domain_obj.pk).update(
        verified=timezone.now(), verified_by=getattr(actor, 'username', ''), verified_email=domain_obj.code_email,
        code='', code_expires=None, code_attempts=0,
    )
    log_event(PinEventAction.DOMAIN_VERIFIED, actor=actor, request=request,
              detail=f'{domain_obj.domain} via {domain_obj.code_email}')


def notify(user, subject, body, request=None):
    """Security notification (only when enabled in the settings)."""
    settings = get_settings()
    if settings.notify_email:
        return send_user_mail(user, subject, body, request=request, settings=settings)
    return False


def maybe_warn_expiry(user, request=None):
    """Send one e-mail per PIN when it enters the warning period before expiry."""
    settings = get_settings()
    user_pin = _get_pin(user)
    expires = pin_expires_at(user_pin, settings)
    if not expires or user_pin.expiry_warned or not settings.warn_days:
        return
    if expires - timedelta(days=settings.warn_days) > timezone.now():
        return
    UserPin.objects.filter(pk=user_pin.pk).update(expiry_warned=timezone.now())
    notify(user, _('Your PIN expires soon'),
           _('Your NetBox PIN expires on {date}. Change it under User PIN > My PIN.').format(
               date=timezone.localtime(expires).strftime('%Y-%m-%d')), request=request)


#
# Self-service recovery of a forgotten PIN: e-mailed code AND 2FA code
#

def recovery_blockers(user, settings=None):
    """Reasons why self-recovery is not possible for ``user`` (empty list = possible)."""
    settings = settings or get_settings()
    reasons = []
    if not settings.self_recovery:
        reasons.append('disabled')
    if not is_allowed(user, settings):
        reasons.append('not_allowed')
    if not email_configured():
        reasons.append('mail_not_configured')
    status = email_status(user, settings)
    if status != 'ok':
        reasons.append(f'email_{status}')
    if not has_2fa(user):
        reasons.append('no_2fa')
    return reasons


def _send_email_code(user, purpose, subject, body, request=None, settings=None):
    """
    E-mail a one-time 8 digit code for ``purpose`` (stored only as a keyed digest; valid for the recovery code
    validity, max 5 attempts, resend after 60 s). ``body`` may contain {code} and {minutes}.
    """
    settings = settings or get_settings()
    user_pin, _created = UserPin.objects.get_or_create(user=user)
    if user_pin.recovery_sent and (timezone.now() - user_pin.recovery_sent).total_seconds() < RECOVERY_RESEND_SECONDS:
        raise ValidationError(_('A code was sent a moment ago. Please wait a minute.'), code='throttled')
    code = f'{secrets.randbelow(10 ** 8):08d}'
    UserPin.objects.filter(pk=user_pin.pk).update(
        recovery_code=crypto.keyed_digest(code, f'{purpose}:{user.pk}'),
        email_code_purpose=purpose,
        recovery_expires=timezone.now() + timedelta(minutes=settings.recovery_minutes),
        recovery_attempts=0,
        recovery_sent=timezone.now(),
    )
    sent = send_user_mail(user, subject, body.format(code=code, minutes=settings.recovery_minutes),
                          request=request, settings=settings)
    if not sent:
        UserPin.objects.filter(pk=user_pin.pk).update(recovery_code='', recovery_expires=None)
        raise ValidationError(_('The e-mail could not be sent. Contact your administrator.'), code='mail')


def _check_email_code(user, purpose, code, consume=True):
    """Check (and with ``consume`` use up) an e-mailed code. Wrong codes count; after 5 the code is invalid."""
    with transaction.atomic():
        user_pin = UserPin.objects.select_for_update().get(user=user)
        valid = bool(user_pin.recovery_code and user_pin.email_code_purpose == purpose and user_pin.recovery_expires
                     and user_pin.recovery_expires > timezone.now() and user_pin.recovery_attempts < 5)
        code_ok = valid and crypto.check_keyed_digest(
            (code or '').strip(), f'{purpose}:{user.pk}', user_pin.recovery_code
        )
        if code_ok:
            if consume:
                user_pin.recovery_code = ''
                user_pin.recovery_expires = None
        else:
            user_pin.recovery_attempts += 1
            if user_pin.recovery_attempts >= 5:
                user_pin.recovery_code = ''
        user_pin.save()
    return code_ok


def email_code_pending(user, purpose):
    user_pin = _get_pin(user)
    return bool(user_pin and user_pin.recovery_code and user_pin.email_code_purpose == purpose
                and user_pin.recovery_expires and user_pin.recovery_expires > timezone.now())


def start_recovery(user, request=None):
    """E-mail a one-time 8 digit code. Raises ValidationError when not possible."""
    settings = get_settings()
    if recovery_blockers(user, settings):
        raise ValidationError(_('Self-service recovery is not available for your account.'), code='blocked')
    _send_email_code(
        user, 'recovery', _('PIN recovery code'),
        _('Your PIN recovery code is: {code}\n\nIt is valid for {minutes} minutes and must be entered together '
          'with a code from your authenticator app. If you did not request it, contact your administrator.'),
        request=request, settings=settings,
    )
    log_event(PinEventAction.RECOVERY_SENT, user=user, request=request)


def complete_recovery(user, email_code, otp, new_pin, request=None):
    """Both the e-mailed code and the 2FA code must be correct; then the new PIN is set."""
    settings = get_settings()
    validate_pin(new_pin, settings)
    # the code is used up only when the whole recovery succeeds (a mistyped 2FA code needs no new e-mail)
    if not _check_email_code(user, 'recovery', email_code, consume=False):
        log_event(PinEventAction.RECOVERY_FAILED, user=user, request=request, detail='e-mail code')
        raise ValidationError(_('The e-mail code is wrong or expired.'), code='email_code')
    result = verify_second_factor(user, otp, request=request, scope='recovery')
    if not result:
        log_event(PinEventAction.RECOVERY_FAILED, user=user, request=request, detail='2FA code')
        raise ValidationError(_('The 2FA code is not correct.'), code='otp')
    with transaction.atomic():
        user_pin = UserPin.objects.select_for_update().get(user=user)
        user_pin.pin_hash = _hash_and_encrypt(user_pin, new_pin)
        user_pin.version += 1
        user_pin.changed = timezone.now()
        user_pin.must_change = False
        user_pin.expiry_warned = None
        user_pin.failed_attempts = 0
        user_pin.locked_until = None
        user_pin.recovery_code = ''
        user_pin.recovery_expires = None
        user_pin.save()
    log_event(PinEventAction.RECOVERY_OK, user=user, actor=user, request=request)
    notify(user, _('Your PIN was recovered'),
           _('A new PIN was set using the e-mail code and 2FA. If this was not you, contact your administrator '
             'immediately.'), request=request)
    if request is not None:
        lock(request, send_signal=False)


#
# Suspension and administrator-initiated resets
#
# Principle: an administrator alone can only REMOVE access (suspend). Restoring access always needs the user:
# a reset started by an administrator is confirmed by the user in their own session with a second factor
# (PIN reset -> 2FA code, 2FA reset -> PIN). The administrator never learns the new PIN.
#

def is_suspended(user):
    user_pin = _get_pin(user)
    return bool(user_pin and user_pin.suspended)


def suspend(user, actor, request=None):
    """Block the PIN immediately (suspected leak, user absent). Existing unlocks are invalidated."""
    with transaction.atomic():
        user_pin, _created = UserPin.objects.select_for_update().get_or_create(user=user)
        user_pin.suspended = True
        user_pin.suspended_by = getattr(actor, 'username', '') or ''
        user_pin.version += 1
        user_pin.save()
    log_event(PinEventAction.SUSPENDED, user=user, actor=actor, request=request)
    notify(user, _('Your PIN was suspended'),
           _('Your NetBox PIN was suspended by {actor}. Contact your administrator.').format(actor=actor),
           request=request)


def unsuspend(user, actor, request=None):
    UserPin.objects.filter(user=user).update(suspended=False, suspended_by='')
    log_event(PinEventAction.UNSUSPENDED, user=user, actor=actor, request=request)
    notify(user, _('Your PIN is active again'),
           _('The suspension of your NetBox PIN was lifted by {actor}.').format(actor=actor), request=request)


def request_reset(user, kind, actor, request=None):
    """
    Start a reset that the user confirms in their own session:
    ``kind='pin'`` (forgotten PIN) -> user confirms with a 2FA code and sets a new PIN;
    ``kind='2fa'`` (lost phone) -> user confirms with the PIN and enrolls 2FA again.
    """
    settings = get_settings()
    user_pin = _get_pin(user)
    if kind == 'pin':
        if not (user_pin and user_pin.has_2fa):
            raise ValidationError(
                _('{user} has no 2FA, so the reset cannot be confirmed by the user.').format(user=user),
                code='no_2fa')
    elif kind == '2fa':
        if not (user_pin and user_pin.has_2fa and user_pin.is_set):
            raise ValidationError(_('{user} has no 2FA or no PIN.').format(user=user), code='no_2fa')
    else:
        raise ValueError(kind)
    expires = timezone.now() + timedelta(hours=settings.reset_valid_hours)
    UserPin.objects.filter(pk=user_pin.pk).update(
        pending_reset=kind, pending_reset_by=getattr(actor, 'username', '') or '', pending_reset_expires=expires,
        # a forgotten PIN usually ends in a lockout; the user must be able to confirm
        failed_attempts=0, locked_until=None,
    )
    log_event(PinEventAction.RESET_REQUESTED, user=user, actor=actor, request=request,
              detail=f'{kind}, valid until {expires.isoformat()}')
    what = _('PIN') if kind == 'pin' else _('two-factor authentication')
    how = _('your 2FA code') if kind == 'pin' else _('your PIN')
    notify(user, _('Reset of your {what} started').format(what=what),
           _('{actor} started a reset of your {what}. Log in to NetBox, open User PIN > My PIN and confirm it with '
             '{how} until {time}. If you did not ask for it, contact your administrator.').format(
               actor=actor, what=what, how=how, time=timezone.localtime(expires).strftime('%Y-%m-%d %H:%M')),
           request=request)


def cancel_reset(user, actor, request=None):
    UserPin.objects.filter(user=user).update(pending_reset='', pending_reset_by='', pending_reset_expires=None)
    log_event(PinEventAction.RESET_CANCELLED, user=user, actor=actor, request=request)


def _clear_pending(user_pin):
    user_pin.pending_reset = ''
    user_pin.pending_reset_by = ''
    user_pin.pending_reset_expires = None


def complete_pin_reset(user, otp, new_pin, request=None):
    """User confirms an administrator's PIN reset with a 2FA code and chooses a new PIN."""
    settings = get_settings()
    user_pin = _get_pin(user)
    if not user_pin or user_pin.reset_pending != 'pin':
        raise ValidationError(_('There is no PIN reset waiting for you.'), code='none')
    validate_pin(new_pin, settings)
    result = verify_second_factor(user, otp, request=request, scope='reset')
    if not result:
        raise ValidationError(_('The 2FA code is not correct.'), code='otp')
    with transaction.atomic():
        user_pin = UserPin.objects.select_for_update().get(user=user)
        by = user_pin.pending_reset_by
        user_pin.pin_hash = _hash_and_encrypt(user_pin, new_pin)
        user_pin.version += 1
        user_pin.changed = timezone.now()
        user_pin.must_change = False
        user_pin.expiry_warned = None
        user_pin.failed_attempts = 0
        user_pin.locked_until = None
        _clear_pending(user_pin)
        user_pin.save()
    log_event(PinEventAction.RESET_COMPLETED, user=user, actor=user, request=request,
              detail=f'PIN reset started by {by}, confirmed with 2FA')
    notify(user, _('Your PIN was reset'), _('You set a new PIN (reset started by {by}).').format(by=by),
           request=request)
    signals.pin_reset.send(sender=UserPin, user=user, actor=user, request=request, scope='')
    if request is not None:
        lock(request, send_signal=False)


def complete_2fa_reset(user, pin, request=None):
    """User confirms an administrator's 2FA reset with the PIN; 2FA is removed and can be enrolled again."""
    user_pin = _get_pin(user)
    if not user_pin or user_pin.reset_pending != '2fa':
        raise ValidationError(_('There is no 2FA reset waiting for you.'), code='none')
    result = verify_pin(user, pin, request=request, scope='reset')
    if not result:
        raise ValidationError(_('The PIN is not correct.'), code='pin')
    by = user_pin.pending_reset_by
    UserPin.objects.filter(pk=user_pin.pk).update(
        totp_secret='', totp_enabled=None, totp_last_step=0, backup_codes=[], backup_codes_encrypted='',
        pending_reset='', pending_reset_by='', pending_reset_expires=None,
    )
    log_event(PinEventAction.RESET_COMPLETED, user=user, actor=user, request=request,
              detail=f'2FA reset started by {by}, confirmed with PIN')
    notify(user, _('Your two-factor authentication was reset'),
           _('Set it up again under User PIN > My PIN (reset started by {by}).').format(by=by), request=request)


def cli_reset_2fa_command(user):
    """Emergency server command that removes the 2FA of ``user`` (shown in the UI, run as root on the server)."""
    import shlex
    venv = get_plugin_config('netbox_user_pin', 'cli_venv')
    netbox_dir = get_plugin_config('netbox_user_pin', 'cli_netbox_dir')
    inner = (f'source {shlex.quote(venv + "/bin/activate")} && cd {shlex.quote(netbox_dir)} && '
             f'python manage.py userpin_reset_2fa {shlex.quote(user.username)}')
    return f"sudo bash -c {shlex.quote(inner)}"
