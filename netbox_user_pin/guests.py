"""
PIN-only access: a person without a NetBox account works through a personal link and a PIN of their own.

A technical user without a usable password stands behind the access (the groups of the protected areas give it rights,
exactly as for any user). What is different: no 2FA, no password, no API, never a keeper, an owner or an exception, a
PIN that is chosen by the person alone, a pause after a wrong PIN instead of a lock, and a short session.
"""
import hashlib
import ipaddress
import logging
import secrets
import time
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.validators import validate_email
from django.db import transaction
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext as _

from . import areas, crypto, service
from .models import AreaGrant, PinAccess, PinEventAction, PinGuest, UserPin

logger = logging.getLogger('netbox_user_pin.guests')

SESSION_KEY = 'userpin_guest'
MIN_PIN_LENGTH = 8
MAX_PIN_LENGTH = 64
INVITE_DAYS = 7
RESET_MINUTES = 60
PAUSES = (30, 60, 300, 900)  # seconds after the 1st, 2nd, 3rd, 4th and every further wrong PIN
ALERT_EVERY = 5  # wrong PINs between two warnings

__all__ = ('check_pin', 'create', 'delete', 'find', 'guard', 'guest_of', 'invite', 'is_guest', 'pause_seconds',
           'request_reset', 'restore', 'revoke', 'set_pin', 'start_session')


def _hash(token):
    return hashlib.sha256((token or '').encode()).hexdigest()


def _new_token():
    return secrets.token_urlsafe(32)


def guest_of(user):
    """The PinGuest of a user, or None (looked up once per user object)."""
    if not getattr(user, 'is_authenticated', False):
        return None
    cached = getattr(user, '_userpin_guest', False)
    if cached is False:
        cached = PinGuest.objects.filter(user_id=user.pk).first()
        try:
            user._userpin_guest = cached
        except AttributeError:
            pass
    return cached


def is_guest(user):
    return guest_of(user) is not None


def link_path(token):
    return reverse('plugins:netbox_user_pin:guest_login', args=[token])


def find(token):
    """The usable access of a link, or None."""
    if not token:
        return None
    guest = PinGuest.objects.select_related('user').filter(token_hash=_hash(token)).first()
    return guest if guest is not None and guest.is_active and guest.user.is_active else None


def _clean_pin(pin):
    pin = pin or ''
    if not MIN_PIN_LENGTH <= len(pin) <= MAX_PIN_LENGTH:
        raise ValidationError(_('The PIN must have %(min)d to %(max)d characters.') % {
            'min': MIN_PIN_LENGTH, 'max': MAX_PIN_LENGTH})
    if len(set(pin)) < 4:
        raise ValidationError(_('This PIN is too easy to guess. Use at least four different characters.'))
    return pin


def _parse_ips(text):
    result = []
    for part in (text or '').replace(';', ',').replace('\n', ',').split(','):
        part = part.strip()
        if part:
            try:
                ipaddress.ip_network(part, strict=False)
            except ValueError:
                raise ValidationError(_('"%(value)s" is not an IP address or a network.') % {'value': part})
            result.append(part)
    return ', '.join(result)


def ip_allowed(guest, request):
    if not guest.allowed_ips:
        return True
    try:
        address = ipaddress.ip_address(str(service.get_client_ip(request)))
    except ValueError:
        return False
    return any(address in ipaddress.ip_network(part.strip(), strict=False) for part in guest.allowed_ips.split(','))


def _may_manage(actor):
    return areas.is_keeper(actor) or areas.administers_any(actor)


def _log(action, guest, actor=None, request=None, detail=''):
    service.log_event(action, user=guest.user, actor=actor, request=request, scope='guest',
                      detail=f'{guest.email}{" - " + detail if detail else ""}')


def _mail(guest, subject, body):
    """The mail goes to the person's own address, whatever the allowed domains say (the keeper wrote it)."""
    settings = service.get_settings()
    if not service.email_configured(settings):
        return False
    try:
        service._deliver(settings, [guest.email], subject, body)
    except Exception as exc:  # noqa: BLE001 - SMTP problems must not break the flow
        logger.warning('Cannot send the PIN-only e-mail to %s: %s', guest.email, exc)
        service.log_event(PinEventAction.MAIL_FAILED, user=guest.user, scope='guest', detail=f'{subject}: {exc}')
        return False
    service.log_event(PinEventAction.MAIL_SENT, user=guest.user, scope='guest', detail=subject)
    return True


def _absolute(request, path):
    return request.build_absolute_uri(path) if request is not None else path


def create(name, email, group, actor, expires=None, ips='', idle=30, hours=8, note='', request=None):
    """
    Create the access: the technical user, its group and the personal link. Returns ``(guest, token)``; the token is
    shown only now (and e-mailed by ``invite``).
    """
    if not _may_manage(actor) or not areas._may_grant(actor, group.area):
        raise PermissionDenied
    name = (name or '').strip()[:150]
    email = (email or '').strip().lower()
    if not name:
        raise ValidationError(_('Write the name of the person.'))
    try:
        validate_email(email)
    except ValidationError:
        raise ValidationError(_('Write a valid e-mail address.'))
    if PinGuest.objects.filter(email__iexact=email).exists():
        raise ValidationError(_('An access with this e-mail address exists.'))
    if group.private or not group.target:
        raise ValidationError(_('Choose a group.'))
    if expires is not None and expires <= timezone.now():
        raise ValidationError(_('The end of the access must be in the future.'))
    idle, hours = int(idle or 30), int(hours or 8)
    if not 5 <= idle <= 240 or not 1 <= hours <= 24:
        raise ValidationError(_('Idle time is 5 to 240 minutes, the whole session 1 to 24 hours.'))
    ips = _parse_ips(ips)
    token = _new_token()
    with transaction.atomic():
        user_model = get_user_model()
        user = user_model(username=f'pin-{secrets.token_hex(5)}', first_name=name[:150], email=email,
                          is_active=True, is_staff=False, is_superuser=False)
        user.set_unusable_password()
        user.save()
        UserPin.objects.create(user=user, access=PinAccess.ALLOWED)
        guest = PinGuest.objects.create(
            user=user, name=name, email=email, token_hash=_hash(token), expires=expires, allowed_ips=ips,
            idle_minutes=idle, max_hours=hours, note=(note or '').strip()[:200], created_by_name=actor.username,
            invite_expires=timezone.now() + timedelta(days=INVITE_DAYS))
        areas.add_member(group, user, None, actor, request=request, notify=False)
    _log(PinEventAction.GUEST_CREATED, guest, actor, request, f'{group.area.name} / {group.name}')
    return guest, token


def invite(guest, actor, request=None):
    """
    Send the personal link (a new one: the old link stops working). A person who has no PIN yet has 7 days to set it.
    Returns ``(token, sent)``.
    """
    if not _may_manage(actor):
        raise PermissionDenied
    token = _new_token()
    now = timezone.now()
    guest.token_hash = _hash(token)
    if not UserPin.objects.filter(user=guest.user).exclude(pin_hash='').exists():
        guest.invite_expires = now + timedelta(days=INVITE_DAYS)
    guest.save(update_fields=['token_hash', 'invite_expires'])
    link = _absolute(request, link_path(token))
    sent = _mail(guest, _('Your access to NetBox'), _(
        'Hello %(name)s,\n\nyou were given access to NetBox through a PIN.\n\nYour personal link:\n%(link)s\n\n'
        '%(first)s\nKeep the link to yourself: it works only together with your PIN.') % {
            'name': guest.name, 'link': link,
            'first': _('Open it and choose your own PIN within %(days)d days.') % {'days': INVITE_DAYS}
            if guest.invite_expires and not has_pin(guest) else _('Open it and enter your PIN.')})
    _log(PinEventAction.GUEST_INVITED, guest, actor, request, 'sent' if sent else 'not sent')
    return token, sent


def has_pin(guest):
    return UserPin.objects.filter(user=guest.user).exclude(pin_hash='').exists()


def pause_seconds(guest):
    """Seconds the person must still wait before the next attempt."""
    if guest.retry_after is None:
        return 0
    return max(0, int((guest.retry_after - timezone.now()).total_seconds()) + 1)


def set_pin(guest, pin, request=None, first=False):
    """The person chooses a PIN (the first one, after a reset, or - ``first=False`` - a change)."""
    pin = _clean_pin(pin)
    with transaction.atomic():
        user_pin = UserPin.objects.select_for_update().get(user=guest.user)
        user_pin.pin_hash = service._hash_and_encrypt(user_pin, pin)
        user_pin.version += 1
        user_pin.changed = timezone.now()
        user_pin.must_change = False
        user_pin.failed_attempts = 0
        user_pin.locked_until = None
        user_pin.save()
        guest.failed, guest.retry_after, guest.reset_hash, guest.reset_expires = 0, None, '', None
        guest.invite_expires = None
        guest.save(update_fields=['failed', 'retry_after', 'reset_hash', 'reset_expires', 'invite_expires'])
    _log(PinEventAction.GUEST_PIN, guest, guest.user, request, 'first' if first else 'changed')


def check_pin(guest, pin, request=None):
    """
    ``'ok'``, ``'wrong'``, ``'pause'`` (do not even try), ``'nopin'`` or ``'blocked'`` (revoked / ended / other address).
    A wrong PIN never locks the account: it only makes the person wait (30 s, 1 min, 5 min, 15 min).
    """
    if not guest.is_active or not guest.user.is_active or not ip_allowed(guest, request):
        return 'blocked'
    if pause_seconds(guest):
        return 'pause'
    with transaction.atomic():
        user_pin = UserPin.objects.select_for_update().get(user=guest.user)
        if not user_pin.is_set:
            return 'nopin'
        try:
            stored = crypto.decrypt(user_pin.pin_hash, user_pin.aad)
        except crypto.DecryptionError:
            return 'blocked'
        if service._check_hash(user_pin, stored, pin):
            guest = PinGuest.objects.select_for_update().get(pk=guest.pk)
            guest.failed, guest.retry_after = 0, None
            guest.last_login = timezone.now()
            try:
                guest.last_ip = str(service.get_client_ip(request)) or None
            except ValueError:
                guest.last_ip = None
            guest.save(update_fields=['failed', 'retry_after', 'last_login', 'last_ip'])
            return 'ok'
        guest = PinGuest.objects.select_for_update().get(pk=guest.pk)
        guest.failed += 1
        guest.retry_after = timezone.now() + timedelta(seconds=PAUSES[min(guest.failed, len(PAUSES)) - 1])
        guest.save(update_fields=['failed', 'retry_after'])
    _log(PinEventAction.GUEST_FAILED, guest, request=request, detail=f'attempt {guest.failed}')
    if guest.failed % ALERT_EVERY == 0:
        _alert(guest, request)
    return 'wrong'


def _alert(guest, request):
    """Several wrong PINs: the person and the keepers are told."""
    _mail(guest, _('Wrong PIN attempts on your NetBox access'), _(
        'There were %(n)d wrong PIN attempts on your access. If it was not you, ask the administrator to revoke it.')
        % {'n': guest.failed})
    for keeper in areas.keepers():
        service.send_user_mail(keeper, _('Wrong PIN attempts: %(name)s') % {'name': guest.name}, _(
            '%(n)d wrong PIN attempts on the PIN-only access of %(name)s (%(email)s).') % {
                'n': guest.failed, 'name': guest.name, 'email': guest.email}, request=request)


def request_reset(guest, request=None):
    """The person forgot the PIN: an e-mail with a link for a new one (valid 1 hour, once). At most one per minute."""
    now = timezone.now()
    if not guest.is_active or (guest.reset_sent and guest.reset_sent > now - timedelta(seconds=60)):
        return False
    token = _new_token()
    guest.reset_hash, guest.reset_expires, guest.reset_sent = _hash(token), now + timedelta(minutes=RESET_MINUTES), now
    guest.save(update_fields=['reset_hash', 'reset_expires', 'reset_sent'])
    link = _absolute(request, reverse('plugins:netbox_user_pin:guest_reset', args=[token]))
    sent = _mail(guest, _('New PIN for your NetBox access'), _(
        'Hello %(name)s,\n\nyou asked for a new PIN. Open this link and choose it (valid %(minutes)d minutes, once):'
        '\n%(link)s\n\nIf it was not you, ignore this message.') % {
            'name': guest.name, 'link': link, 'minutes': RESET_MINUTES})
    _log(PinEventAction.GUEST_RESET, guest, request=request, detail='requested' + ('' if sent else ' (not sent)'))
    return sent


def find_reset(token):
    if not token:
        return None
    guest = PinGuest.objects.select_related('user').filter(reset_hash=_hash(token)).first()
    if guest is None or not guest.is_active or not guest.reset_expires or guest.reset_expires < timezone.now():
        return None
    return guest


def revoke(guest, actor, request=None):
    if not _may_manage(actor):
        raise PermissionDenied
    guest.revoked = timezone.now()
    guest.save(update_fields=['revoked'])
    guest.user.is_active = False  # every session of the account ends at the next request
    guest.user.save(update_fields=['is_active'])
    _log(PinEventAction.GUEST_REVOKED, guest, actor, request)
    areas.clear_cache()


def restore(guest, actor, request=None):
    if not _may_manage(actor):
        raise PermissionDenied
    guest.revoked = None
    guest.save(update_fields=['revoked'])
    guest.user.is_active = True
    guest.user.save(update_fields=['is_active'])
    _log(PinEventAction.GUEST_INVITED, guest, actor, request, 'restored')
    areas.clear_cache()


def delete(guest, actor, request=None):
    if not _may_manage(actor):
        raise PermissionDenied
    _log(PinEventAction.GUEST_DELETED, guest, actor, request)
    guest.user.delete()  # takes the access, the PIN and the grants along; the changelog keeps the name
    areas.clear_cache()


def groups_of(guest):
    now = timezone.now()
    return [g for g in AreaGrant.objects.filter(user=guest.user, revoked__isnull=True).select_related('profile', 'area')
            if g.expires is None or g.expires > now]


#
# The session
#

def start_session(request, guest):
    from django.contrib.auth import login
    login(request, guest.user, backend='django.contrib.auth.backends.ModelBackend')  # also renews the session key
    version = UserPin.objects.get(user=guest.user).version
    now = time.time()
    request.session[SESSION_KEY] = {'id': guest.pk, 'start': now, 'last': now, 'ver': version,
                                    'link': request.session.get('userpin_guest_link', '')}
    request.session.pop('userpin_guest_link', None)
    _log(PinEventAction.GUEST_LOGIN, guest, guest.user, request)


def end_session(request):
    from django.contrib.auth import logout
    link = (request.session.get(SESSION_KEY) or {}).get('link', '')
    logout(request)
    return link


def session_problem(request, guest):
    """Why the session of this access must end ('' = none). Touches the idle clock."""
    data = request.session.get(SESSION_KEY)
    if not data or data.get('id') != guest.pk:
        return 'login'
    if not guest.is_active or not guest.user.is_active:
        return 'revoked'
    if not ip_allowed(guest, request):
        return 'ip'
    user_pin = UserPin.objects.filter(user=guest.user).first()
    if user_pin is None or user_pin.version != data.get('ver'):
        return 'pin'
    now = time.time()
    if now - data.get('last', 0) > guest.idle_minutes * 60:
        return 'idle'
    if now - data.get('start', 0) > guest.max_hours * 3600:
        return 'max'
    if not request.path_info.startswith(('/htmx/', '/static/', '/api/')) and request.headers.get('HX-Request') != 'true':
        data['last'] = now
        request.session[SESSION_KEY] = data
    return ''


def seconds_left(request, guest):
    data = request.session.get(SESSION_KEY) or {}
    now = time.time()
    return max(0, int(min(data.get('last', now) + guest.idle_minutes * 60, data.get('start', now) + guest.max_hours * 3600)
                      - now))


OPEN_PATHS = ('/plugins/user-pin/guest/', '/static/', '/media/', '/htmx/')
# what a PIN-only person never reaches, whatever the groups say: the account pages, the tokens, the admin of NetBox
CLOSED_PATHS = ('/user/', '/admin/', '/api/users/', '/core/', '/api/core/', '/graphql/', '/login/', '/oauth/',
                '/social-auth/', '/plugins/user-pin/')


def guard(request, guest):
    """Called for every request of a PIN-only account: ends the session or refuses what is closed. None = go on."""
    from django.shortcuts import redirect
    path = request.path_info
    problem = session_problem(request, guest)
    if problem:
        link = end_session(request)
        if request.headers.get('HX-Request') == 'true' or path.startswith('/api/'):
            from django.http import HttpResponse
            return HttpResponse(status=401)
        return redirect(link or reverse('plugins:netbox_user_pin:guest_ended'))
    if path.startswith('/plugins/user-pin/guest/') and not path.startswith('/plugins/user-pin/guest/reset/'):
        return None
    if path == '/' or path.startswith('/plugins/user-pin/'):
        return redirect('plugins:netbox_user_pin:guest_home')
    if path.startswith('/logout/'):
        return redirect('plugins:netbox_user_pin:guest_logout')
    if path.startswith(('/static/', '/media/', '/htmx/')):
        return None
    if path.startswith(CLOSED_PATHS):
        from .area_guard import denied_response
        return denied_response(request, None, right='view', target=None)
    return None
