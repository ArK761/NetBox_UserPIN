"""
Public API of netbox_user_pin. Other plugins should only use the functions exported here, the mixin/decorator in
``netbox_user_pin.mixins`` and the signals in ``netbox_user_pin.signals``.

    from netbox_user_pin import service

    service.has_pin(user)
    service.is_unlocked(request, scope='projects')
    service.unlock(request, pin, scope='projects')   # -> VerifyResult
    service.lock(request)                            # lock everything
"""
import enum
import logging
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

from . import crypto, signals
from .models import PinAccess, PinAccessMode, PinEvent, PinEventAction, PinScopeMode, PinSettings, UserPin
from .policy import validate_pin

__all__ = (
    'DEFAULT_SCOPE',
    'VerifyResult',
    'VerifyStatus',
    'change_pin',
    'clear_lockout',
    'get_settings',
    'has_pin',
    'is_allowed',
    'is_unlocked',
    'lock',
    'log_event',
    'pin_expired',
    'reset_pin',
    'set_access',
    'set_pin',
    'unlock',
    'unlocked_scopes',
    'verify_pin',
)

logger = logging.getLogger('netbox_user_pin')

SESSION_KEY = '_netbox_user_pin'
DEFAULT_SCOPE = 'default'
GLOBAL_SCOPE_KEY = '*'


class VerifyStatus(enum.Enum):
    OK = 'ok'
    WRONG = 'wrong'
    LOCKED_OUT = 'locked_out'
    NO_PIN = 'no_pin'
    NOT_ALLOWED = 'not_allowed'


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
    settings = settings or get_settings()
    user_pin = _get_pin(user)
    access = user_pin.access if user_pin else PinAccess.DEFAULT
    if access == PinAccess.DENIED:
        return False
    if access == PinAccess.ALLOWED:
        return True
    return settings.access_mode == PinAccessMode.ALL


def _not_allowed_error():
    return ValidationError(_('You are not permitted to use a PIN. Ask an administrator.'), code='not_allowed')


def pin_expired(user, settings=None):
    """True when the PIN is older than the configured maximum age and must be changed."""
    settings = settings or get_settings()
    user_pin = _get_pin(user)
    if not settings.max_age_days or not user_pin or not user_pin.is_set or not user_pin.changed:
        return False
    return user_pin.changed + timedelta(days=settings.max_age_days) < timezone.now()


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
        user_pin.save()
    log_event(PinEventAction.SET, user=user, actor=user, request=request)
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
        user_pin.save()
    log_event(PinEventAction.CHANGED, user=user, actor=user, request=request)
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
                user_pin.failed_attempts += 1
                remaining = max(settings.max_attempts - user_pin.failed_attempts, 0)
                if remaining == 0:
                    user_pin.locked_until = timezone.now() + timedelta(minutes=settings.lockout_minutes)
                    user_pin.failed_attempts = 0
                user_pin.save()

    if decryption_error is not None:
        logger.error('Cannot decrypt PIN of user %s: %s', user, decryption_error)
        log_event(PinEventAction.ERROR, user=user, request=request, scope=scope, detail=str(decryption_error))
        raise decryption_error

    if matched:
        log_event(PinEventAction.VERIFIED, user=user, request=request, scope=scope)
        return VerifyResult(VerifyStatus.OK)

    log_event(
        PinEventAction.FAILED, user=user, request=request, scope=scope,
        detail=f'remaining attempts: {remaining}',
    )
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

def unlock(request, pin, scope=None):
    """
    Verify the PIN of ``request.user`` and, if correct, unlock ``scope`` in the session.
    """
    settings = get_settings()
    scope = scope or DEFAULT_SCOPE
    result = verify_pin(request.user, pin, request=request, scope=scope)
    if result:
        user_pin = _get_pin(request.user)
        data = request.session.get(SESSION_KEY) or {}
        if data.get('v') != user_pin.version or data.get('u') != request.user.pk:
            data = {'v': user_pin.version, 'u': request.user.pk, 'unlocks': {}}
        data['unlocks'][_session_key_for(scope, settings)] = time.time() + settings.unlock_minutes * 60
        request.session[SESSION_KEY] = data
        request.session.modified = True
        signals.pin_unlocked.send(sender=UserPin, user=request.user, request=request, scope=scope)
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
    if not user_pin or not user_pin.is_set or data.get('v') != user_pin.version:
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
        user_pin.save()
    log_event(PinEventAction.RESET, user=user, actor=actor, request=request)
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
