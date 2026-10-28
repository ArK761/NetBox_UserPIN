"""
PIN-only access: a person without a NetBox account works through a personal link and a PIN of their own.

A technical user without a usable password stands behind the access (the groups of the protected areas give it rights,
exactly as for any user). What is different: no 2FA, no password, no API, never a keeper, an owner or an exception, a
PIN that is chosen by the person alone, waits after wrong PINs (on the personal link a block after the last step), and a short session.
"""
import hashlib
import ipaddress
import logging
import secrets
import time
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.validators import validate_email
from django.db import transaction
from django.urls import reverse
from django.utils import timezone
from django.utils import translation
from django.utils.translation import gettext as _

from . import areas, crypto, service
from .models import AreaGrant, PinAccess, PinEventAction, PinGuest, UserPin

logger = logging.getLogger('netbox_user_pin.guests')

SESSION_KEY = 'userpin_guest'
MIN_PIN_LENGTH = 8
MAX_PIN_LENGTH = 64
INVITE_DAYS = 7
RESET_MINUTES = 60
DEFAULT_STEP = 5
DEFAULT_WAITS = (10, 20, 30)

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


def find_disabled(token):
    """The access of a link that is disabled or whose validity ended (to say so instead of 'invalid link')."""
    if not token:
        return None
    guest = PinGuest.objects.select_related('user').filter(token_hash=_hash(token)).first()
    if guest is not None and (guest.revoked or (guest.expires and guest.expires <= timezone.now())):
        return guest
    return None


def stop_message(guest):
    """Why the person cannot sign in: disabled (by whom, since when) or the validity ended."""
    if guest.revoked:
        return disabled_message(guest)
    return _('The validity of your account ended on %(time)s. Contact the administrator.') % {
        'time': timezone.localtime(guest.expires).strftime('%d.%m.%Y %H:%M')}


UNBLOCK_EVERY = 3600  # seconds between two requests of one person


def request_unblock(guest, request=None):
    """
    The person asks for the access back (disabled or ended): an e-mail to the administrator who disabled it (or the
    protection keepers). At most once an hour. Returns the usernames told, or [] when nothing was sent now.
    """
    key = f'userpin-unblock-{guest.pk}'
    if cache.get(key):
        return []
    user_model = get_user_model()
    recipients = []
    if guest.revoked:
        who, _when = disabled_by(guest)
        admin = user_model.objects.filter(username=who, is_active=True).first()
        if admin is not None:
            recipients.append(admin)
    if not recipients:
        recipients = areas.keepers()
    link = _absolute(request, reverse('plugins:netbox_user_pin:guests'))
    with translation.override(service.get_settings().language or 'en'):
        if guest.revoked:
            state = _('disabled since %(time)s') % {'time': timezone.localtime(guest.revoked).strftime('%d.%m.%Y %H:%M')}
        elif guest.expires and guest.expires <= timezone.now():
            state = _('its validity ended on %(time)s') % {
                'time': timezone.localtime(guest.expires).strftime('%d.%m.%Y %H:%M')}
        else:
            state = _('blocked after %(n)d wrong PINs') % {'n': guest.failed}
        subject = _('Request to unblock the PIN-only access %(id)s') % {'id': guest.user.username}
        body = _('%(name)s (%(id)s%(alias)s, %(email)s) asks to get the access back – %(state)s.\n\n'
                 'Enable it or extend its validity here: %(link)s') % {
            'name': guest.name, 'id': guest.user.username, 'alias': f', {guest.alias}' if guest.alias else '',
            'email': guest.email, 'state': state, 'link': link}
        sent = [r.username for r in recipients if service.send_user_mail(r, subject, body, request=request)]
    cache.set(key, True, UNBLOCK_EVERY)
    _log(PinEventAction.GUEST_UNBLOCK_ASKED, guest, guest.user, request, ', '.join(sent) or 'nobody reachable')
    return sent or [r.username for r in recipients]


def set_expiry(guest, actor, expires, request=None):
    """The end of the whole access (None = unlimited); a later end re-arms the e-mails before it."""
    if not _may_manage(actor):
        raise PermissionDenied
    if expires is not None and expires <= timezone.now():
        raise ValidationError(_('The end of the access must be in the future.'))
    guest.expires, guest.expiry_warned = expires, ''
    guest.save(update_fields=['expires', 'expiry_warned'])
    _log(PinEventAction.GUEST_EXPIRES, guest, actor, request,
         timezone.localtime(expires).strftime('%Y-%m-%d %H:%M') if expires else 'unlimited')
    _tell(guest, actor, lambda: _('Your access is valid until %(time)s.') % {
        'time': timezone.localtime(expires).strftime('%d.%m.%Y %H:%M')} if expires else
        _('Your access is valid without a time limit.'))
    areas.clear_cache()


def announce_expiry():
    """Hourly: e-mail the person 30 days and 1 day before the end of the access (in their language)."""
    now = timezone.now()
    for guest in PinGuest.objects.select_related('user').filter(revoked__isnull=True, expires__gt=now):
        left = guest.expires - now
        step = '1' if left <= timedelta(days=1) else ('30' if left <= timedelta(days=30) else '')
        if not step or guest.expiry_warned == step or (step == '30' and guest.expiry_warned == '1'):
            continue
        guest.expiry_warned = step
        guest.save(update_fields=['expiry_warned'])
        _say(guest, lambda: (_('Your NetBox access ends on %(time)s') % {
            'time': timezone.localtime(guest.expires).strftime('%d.%m.%Y %H:%M')}, _(
            'Hello %(name)s,\n\nyour access to NetBox ends on %(time)s. If you still need it, ask the administrator '
            'to extend it.') % {'name': guest.name,
                                'time': timezone.localtime(guest.expires).strftime('%d.%m.%Y %H:%M')}))
        _log(PinEventAction.GUEST_EXPIRY_WARNED, guest, detail=f'{step} day(s) before')


def disabled_by(guest):
    """(username of the administrator, time) of the last disabling, from the audit log."""
    from .models import PinEvent
    event = PinEvent.objects.filter(user=guest.user, action=PinEventAction.GUEST_REVOKED).order_by('-time').first()
    return (event.actor_username or '?', event.time) if event else ('?', guest.revoked)


def disabled_message(guest):
    who, when = disabled_by(guest)
    return _('Your account is temporarily disabled by the administrator %(admin)s (since %(time)s). Contact them.') % {
        'admin': who, 'time': timezone.localtime(when).strftime('%d.%m.%Y %H:%M') if when else ''}


def find(token):
    """The usable access of a link, or None."""
    if not token:
        return None
    guest = PinGuest.objects.select_related('user').filter(token_hash=_hash(token)).first()
    return guest if guest is not None and guest.is_active and guest.user.is_active else None


def _client_ip(request):
    try:
        return ipaddress.ip_address(str(service.get_client_ip(request)))
    except ValueError:
        return None


def _refresh_pin_index(guest, pin):
    """After a key rotation the index moves to the active key at the first right PIN."""
    index = crypto.pin_lookup(pin)
    if guest.pin_index != index:
        guest.pin_index = index
        guest.save(update_fields=['pin_index'])


def _pin_matches(guest, pin):
    """Does ``pin`` fit the PIN of the access (nothing is counted or changed)?"""
    user_pin = UserPin.objects.filter(user=guest.user).first()
    if user_pin is None or not user_pin.is_set:
        return False
    try:
        stored = crypto.decrypt(user_pin.pin_hash, user_pin.aad)
        return bool(service._hasher().verify(stored, pin or ''))
    except Exception:  # noqa: BLE001 - a wrong PIN, a damaged hash: no match
        return False


def _take_pin_index(guest, pin):
    """The PIN identifies the person on the shared page: two accesses never hold the same one."""
    index = crypto.pin_lookup(pin)
    if PinGuest.objects.exclude(pk=guest.pk).filter(pin_index__in=crypto.pin_lookups(pin)).exists():
        raise ValidationError(_('Choose another PIN.'))
    return index


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
    """
    The mail goes to the person's own address, whatever the allowed domains say (the keeper wrote it). Callers that
    want the person's language build the texts inside ``translation.override(language_of(guest))``.
    """
    settings = service.get_settings()
    if not mails_person(guest, settings) or not service.email_configured(settings):
        return False
    try:
        service._deliver(settings, [guest.email], subject, body)
    except Exception as exc:  # noqa: BLE001 - SMTP problems must not break the flow
        logger.warning('Cannot send the PIN-only e-mail to %s: %s', guest.email, exc)
        service.log_event(PinEventAction.MAIL_FAILED, user=guest.user, scope='guest', detail=f'{subject}: {exc}')
        return False
    service.log_event(PinEventAction.MAIL_SENT, user=guest.user, scope='guest', detail=subject)
    return True


def mails_person(guest, settings=None):
    """E-mails to the person: switched on on the PIN-only page and for this access."""
    return (settings or service.get_settings()).guest_mail_person and guest.mail_person


def mails_changes(guest, settings=None):
    """Summary of what the person changed to the administrators: on the PIN-only page and for this access."""
    return (settings or service.get_settings()).guest_mail_changes and guest.mail_changes


def _tell(guest, actor, what):
    """One e-mail to the person about an action of an administrator; ``what`` is built in the person's language."""
    _say(guest, lambda: (_('Your NetBox access was changed'), _(
        'Hello %(name)s,\n\nthe administrator %(admin)s changed your access to NetBox:\n\n%(what)s') % {
            'name': guest.name, 'admin': actor.get_full_name() or actor.username, 'what': what()}))


def _say(guest, make):
    """E-mail the person in their own language: ``make`` returns (subject, body) built under that language."""
    with translation.override(language_of(guest)):
        subject, body = make()
    return _mail(guest, subject, body)


def _absolute(request, path):
    return request.build_absolute_uri(path) if request is not None else path


def _may_put_in(actor, area):
    """Owners of the area, and the protection keepers (the authority above the owners)."""
    return areas._may_grant(actor, area) or areas.is_keeper(actor)


def _join(group, user, actor, request):
    if areas._may_grant(actor, group.area):
        return areas.add_member(group, user, None, actor, request=request, notify=False)
    grant = AreaGrant.objects.create(area=group.area, user=user, profile=group, expires=None, granted_by=actor,
                                     granted_by_name=actor.username, target=group.target)
    areas._log(PinEventAction.AREA_GRANTED, group.area, actor, user=user, request=request,
               detail=f'{group.target} ({", ".join(group.rights)}) by a protection keeper')
    areas.clear_cache()
    return grant


LANGUAGES = (('', 'default'), ('sk', 'Slovenčina'), ('en', 'English'))


def next_account_id():
    """The stable username of a new PIN-only account: PinUser0001, PinUser0002 ... (never reused, never renamed)."""
    import re
    numbers = [int(m.group(1)) for m in (re.fullmatch(r'PinUser(\d+)', u) for u in
                                         get_user_model().objects.filter(username__startswith='PinUser')
                                         .values_list('username', flat=True)) if m]
    return f'PinUser{max(numbers, default=0) + 1:04d}'


def language_of(guest):
    """Language of the PIN pages and e-mails for this person."""
    return (guest.pin_language if guest is not None and guest.pin_language else None) \
        or service.get_settings().language or 'en'


def _set_ui_language(guest):
    """The NetBox interface language of the account (its own preference, like any user)."""
    try:
        config = guest.user.config
        if guest.ui_language:
            config.set('locale.language', guest.ui_language, commit=True)
        else:
            config.clear('locale.language', commit=True)
    except Exception as exc:  # noqa: BLE001 - a missing preference must not break the change
        logger.warning('Cannot set the language of %s: %s', guest.user, exc)


def set_languages(guest, actor, pin_language=None, ui_language=None, request=None):
    """Languages of one person: PIN pages / e-mails, and the NetBox interface. ``actor=None`` = the person."""
    if actor is not None and not _may_manage(actor):
        raise PermissionDenied
    valid = {code for code, _label in LANGUAGES}
    fields = []
    if pin_language is not None and pin_language in valid and pin_language != guest.pin_language:
        guest.pin_language = pin_language
        fields.append('pin_language')
    if ui_language is not None and ui_language in valid and ui_language != guest.ui_language:
        guest.ui_language = ui_language
        fields.append('ui_language')
    if fields:
        guest.save(update_fields=fields)
        if 'ui_language' in fields:
            _set_ui_language(guest)
        _log(PinEventAction.GUEST_RULES, guest, actor or guest.user, request,
             f'languages: PIN {guest.pin_language or "default"}, NetBox {guest.ui_language or "default"}')
        if actor is not None:
            names = dict(LANGUAGES)
            _tell(guest, actor, lambda: _('Language of the PIN pages and e-mails: %(pin)s; of NetBox: %(ui)s.') % {
                'pin': names.get(guest.pin_language, '-'), 'ui': names.get(guest.ui_language, '-')})


def set_alias(guest, actor, alias, description='', request=None):
    """Alias and description are texts only: the account keeps its ID (username), nothing in NetBox is renamed."""
    if not _may_manage(actor):
        raise PermissionDenied
    alias, description = (alias or '').strip()[:100], (description or '').strip()[:150]
    if (alias, description) == (guest.alias, guest.description):
        return guest.alias
    guest.alias, guest.description = alias, description
    guest.save(update_fields=['alias', 'description'])
    _log(PinEventAction.GUEST_RULES, guest, actor, request, f'alias: {guest.alias}; description: {guest.description}')
    _tell(guest, actor, lambda: _('Name shown with your account: %(alias)s; description: %(description)s.') % {
        'alias': guest.alias or '-', 'description': guest.description or '-'})
    return guest.alias


def set_mails(guest, actor, person, changes, request=None):
    """E-mails of one access (``guest``) or on the PIN-only page (``guest=None``): to the person / to the administrators."""
    if not _may_manage(actor):
        raise PermissionDenied
    person, changes = bool(person), bool(changes)
    if guest is None:
        settings = service.get_settings()
        settings.guest_mail_person, settings.guest_mail_changes = person, changes
        settings.save()
        service.log_event(PinEventAction.GUEST_RULES, actor=actor, request=request, scope='guest',
                          detail=f'e-mails: to the people {person}, to the administrators {changes}')
        return
    guest.mail_person, guest.mail_changes = person, changes
    guest.save(update_fields=['mail_person', 'mail_changes'])
    _log(PinEventAction.GUEST_RULES, guest, actor, request,
         f'e-mails: to the person {person}, to the administrators {changes}')


def display(guest):
    """'PinUser0001 – alias (name)' for lists."""
    parts = [guest.user.username]
    if guest.alias:
        parts.append(guest.alias)
    return ' – '.join(parts)


def create(name, email, group, actor, expires=None, ips='', idle=30, hours=8, note='', request=None, alias='',
           description='', pin_language='', ui_language=''):
    """
    Create the access: the technical user, its group and the personal link. Returns ``(guest, token)``; the token is
    shown only now (and e-mailed by ``invite``).
    """
    if not _may_manage(actor) or not _may_put_in(actor, group.area):
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
    owner = get_user_model().objects.filter(email__iexact=email).first()
    if owner is not None:
        raise ValidationError(_(
            'The PIN-only access cannot be created. The address %(email)s already belongs to the NetBox account '
            '%(user)s. This person signs in to NetBox with their own account, so a PIN-only access is not needed: add '
            'the account to the group as a regular user. If they really need a PIN-only access, first delete the '
            'account %(user)s or change its e-mail to another address (Admin > Users > %(user)s: %(url)s), then '
            'create the access again.') % {'email': email, 'user': owner.username,
                                            'url': reverse('users:user', kwargs={'pk': owner.pk})})
    if group.private or not group.target:
        raise ValidationError(_('Choose a group.'))
    if expires is not None and expires <= timezone.now():
        raise ValidationError(_('The end of the access must be in the future.'))
    idle, hours = int(idle or 30), int(hours or 8)
    if not 5 <= idle <= 240 or not 1 <= hours <= 24:
        raise ValidationError(_('Idle time is 5 to 240 minutes, the whole session 1 to 24 hours.'))
    ips = _parse_ips(ips)
    alias = (alias or '').strip()[:100]
    description = ' – '.join(x for x in ((description or '').strip(), (note or '').strip()) if x)[:150]
    valid = {code for code, _label in LANGUAGES}
    pin_language = pin_language if pin_language in valid else ''
    ui_language = ui_language if ui_language in valid else ''
    token = _new_token()
    with transaction.atomic():
        user_model = get_user_model()
        user = user_model(username=next_account_id(), first_name=name[:150], email=email,
                          is_active=True, is_superuser=False)
        user.set_unusable_password()
        user.save()
        UserPin.objects.create(user=user, access=PinAccess.ALLOWED)
        guest = PinGuest.objects.create(
            user=user, name=name, email=email, token_hash=_hash(token), expires=expires, allowed_ips=ips,
            idle_minutes=idle, max_hours=hours, created_by_name=actor.username,
            description=description, alias=alias, pin_language=pin_language, ui_language=ui_language,
            invite_expires=timezone.now() + timedelta(days=INVITE_DAYS))
        _join(group, user, actor, request)
    _log(PinEventAction.GUEST_CREATED, guest, actor, request, f'{group.area.name} / {group.name}')
    if ui_language:
        _set_ui_language(guest)
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
    sent = _say(guest, lambda: (_('Your access to NetBox'), _(
        'Hello %(name)s,\n\nyou were given access to NetBox through a PIN.\n\nYour personal link:\n%(link)s\n\n'
        '%(first)s\nKeep the link to yourself: it works only together with your PIN.') % {
            'name': guest.name, 'link': link,
            'first': (_('Open it and choose your own PIN within %(days)d days.') % {'days': INVITE_DAYS}
                      if guest.invite_expires and not has_pin(guest) else _('Open it and enter your PIN.'))
            + '\n' + _('Afterwards save this page and sign in there with your PIN only: %(page)s') % {
                'page': _absolute(request, login_path())}}))
    _log(PinEventAction.GUEST_INVITED, guest, actor, request, 'sent' if sent else 'not sent')
    return token, sent


def parse_waits(text):
    """'10,20,30' -> (10, 20, 30); 1 to 10 waits of 1 to 3600 seconds."""
    try:
        waits = tuple(int(part) for part in str(text or '').replace(';', ',').split(',') if part.strip())
    except ValueError:
        raise ValidationError(_('Write the waits as whole seconds separated by commas, e.g. 10,20,30.'))
    if not 1 <= len(waits) <= 10 or not all(1 <= w <= 3600 for w in waits):
        raise ValidationError(_('1 to 10 waits, each 1 to 3600 seconds.'))
    return waits


def rules(guest=None):
    """(wrong PINs per step, waits) – the person's own rules or the defaults."""
    settings = service.get_settings()
    step = (guest.step_attempts if guest is not None and guest.step_attempts else None) \
        or settings.guest_step_attempts or DEFAULT_STEP
    try:
        waits = parse_waits(guest.waits if guest is not None and guest.waits else settings.guest_waits)
    except ValidationError:
        waits = DEFAULT_WAITS
    return step, waits


def rules_text(guest=None):
    step, waits = rules(guest)
    return _('%(n)d wrong PINs, wait %(waits)s s; then blocked') % {'n': step, 'waits': ' / '.join(map(str, waits))}


def set_rules(guest, actor, step, waits, request=None):
    """Own rules of one person (``guest``) or the defaults (``guest=None``); empty values = back to the defaults."""
    if not _may_manage(actor):
        raise PermissionDenied
    step = int(step) if str(step or '').strip() else None
    if step is not None and not 1 <= step <= 50:
        raise ValidationError(_('Wrong PINs per step: 1 to 50.'))
    waits = ','.join(map(str, parse_waits(waits))) if str(waits or '').strip() else ''
    if guest is None:
        settings = service.get_settings()
        settings.guest_step_attempts = step or DEFAULT_STEP
        settings.guest_waits = waits or ','.join(map(str, DEFAULT_WAITS))
        settings.save()
        service.log_event(PinEventAction.GUEST_RULES, actor=actor, request=request, scope='guest',
                          detail=f'defaults: {settings.guest_step_attempts} / {settings.guest_waits}')
        return
    guest.step_attempts, guest.waits = step, waits
    guest.save(update_fields=['step_attempts', 'waits'])
    _log(PinEventAction.GUEST_RULES, guest, actor, request, f'{step or "default"} / {waits or "default"}')
    _tell(guest, actor, lambda: _('Rules for wrong PINs: %(rules)s.') % {'rules': rules_text(guest)})


def unblock(guest, actor, request=None):
    """The old PIN works again; the counting starts from zero."""
    if not _may_manage(actor):
        raise PermissionDenied
    guest.failed, guest.retry_after, guest.blocked = 0, None, None
    guest.save(update_fields=['failed', 'retry_after', 'blocked'])
    _log(PinEventAction.GUEST_UNBLOCKED, guest, actor, request)
    _say(guest, lambda: (_('Your NetBox access works again'), _(
        'Hello %(name)s,\n\nthe administrator unblocked your access. You can sign in with your PIN again.') % {
            'name': guest.name}))


def force_change(guest, actor, request=None):
    """Like 'User must change password at next logon': the next sign-in asks for a new PIN."""
    if not _may_manage(actor):
        raise PermissionDenied
    UserPin.objects.filter(user=guest.user).exclude(pin_hash='').update(must_change=True)
    service.log_event(PinEventAction.FORCE_CHANGE, user=guest.user, actor=actor, request=request, scope='guest')
    with translation.override(language_of(guest)):
        _say(guest, lambda: (_('You must change your PIN'), _(
            'Hello %(name)s,\n\nthe administrator %(admin)s asked you to choose a new PIN. If you are signed in, you '
            'are asked for it right away; otherwise at your next sign-in.') % {
                'name': guest.name, 'admin': actor.username}))


def must_change(guest):
    """The PIN expired (rotation) or a change was forced."""
    return service.pin_expired(guest.user)


def pin_valid_until(guest):
    return service.pin_expires_at(UserPin.objects.filter(user=guest.user).first())


def _block(guest, request):
    guest.blocked = timezone.now()
    guest.save(update_fields=['blocked'])
    _log(PinEventAction.GUEST_BLOCKED, guest, request=request, detail=f'after {guest.failed} wrong PINs')
    _say(guest, lambda: (_('Your NetBox access is blocked'), _(
        'Hello %(name)s,\n\nafter %(n)d wrong PINs your access was blocked. Ask the administrator to unblock it or to '
        'send you a link for a new PIN.') % {'name': guest.name, 'n': guest.failed}))
    for keeper in areas.keepers():
        service.send_user_mail(keeper, _('PIN-only access blocked: %(name)s') % {'name': guest.name}, _(
            'The PIN-only access of %(name)s (%(email)s) was blocked after %(n)d wrong PINs. Unblock it or send a '
            'reset e-mail on the page People with a PIN only.') % {
                'name': guest.name, 'email': guest.email, 'n': guest.failed}, request=request)


def _after_wrong(guest, request):
    """Count a wrong PIN: a wait after every step, a block after the last one. Returns 'wrong' or 'locked'."""
    step, waits = rules(guest)
    guest.failed += 1
    if guest.failed > step * len(waits):
        guest.save(update_fields=['failed'])
        _log(PinEventAction.GUEST_FAILED, guest, request=request, detail=f'attempt {guest.failed}')
        _block(guest, request)
        return 'locked'
    if guest.failed % step == 0:
        guest.retry_after = timezone.now() + timedelta(seconds=waits[guest.failed // step - 1])
    guest.save(update_fields=['failed', 'retry_after'])
    _log(PinEventAction.GUEST_FAILED, guest, request=request, detail=f'attempt {guest.failed}')
    return 'wrong'


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
    if not first and _pin_matches(guest, pin):
        raise ValidationError(_('The new PIN must differ from the current one.'))
    index = _take_pin_index(guest, pin)
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
        guest.invite_expires, guest.pin_index, guest.blocked = None, index, None
        guest.save(update_fields=['failed', 'retry_after', 'reset_hash', 'reset_expires', 'invite_expires',
                                  'pin_index', 'blocked'])
    _log(PinEventAction.GUEST_PIN, guest, guest.user, request, 'first' if first else 'changed')


def check_pin(guest, pin, request=None):
    """
    ``'ok'``, ``'wrong'``, ``'pause'`` (do not even try), ``'nopin'``, ``'locked'`` (too many wrong PINs, only an
    administrator unblocks) or ``'blocked'`` (revoked / ended / other address). See ``rules()``.
    """
    if guest.revoked:
        return 'disabled'
    if guest.expires and guest.expires <= timezone.now():
        return 'ended'
    if not guest.is_active or not guest.user.is_active or not ip_allowed(guest, request):
        return 'blocked'
    if guest.blocked:
        return 'locked'
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
            if guest.pin_index:
                _refresh_pin_index(guest, pin)
            elif not PinGuest.objects.exclude(pk=guest.pk).filter(pin_index__in=crypto.pin_lookups(pin)).exists():
                guest.pin_index = crypto.pin_lookup(pin)
                guest.save(update_fields=['pin_index'])
            guest.last_login = timezone.now()
            try:
                guest.last_ip = (str(service.get_client_ip(request)) or None) if request is not None else None
            except ValueError:
                guest.last_ip = None
            guest.save(update_fields=['failed', 'retry_after', 'last_login', 'last_ip'])
            return 'ok'
        guest = PinGuest.objects.select_for_update().get(pk=guest.pk)
        return _after_wrong(guest, request)


def request_reset(guest, request=None, actor=None):
    """
    An e-mail with a link for a new PIN (valid 1 hour, once): the person forgot it (at most one per minute), or an
    administrator (``actor``) sends it, e.g. to a blocked access – the new PIN also unblocks it.
    """
    now = timezone.now()
    if actor is not None and not _may_manage(actor):
        raise PermissionDenied
    if guest.revoked or not guest.is_active or (actor is None and guest.reset_sent and guest.reset_sent > now - timedelta(seconds=60)):
        return False
    token = _new_token()
    guest.reset_hash, guest.reset_expires, guest.reset_sent = _hash(token), now + timedelta(minutes=RESET_MINUTES), now
    guest.save(update_fields=['reset_hash', 'reset_expires', 'reset_sent'])
    link = _absolute(request, reverse('plugins:netbox_user_pin:guest_reset', args=[token]))
    sent = _say(guest, lambda: (_('New PIN for your NetBox access'), _(
        'Hello %(name)s,\n\nyou asked for a new PIN. Open this link and choose it (valid %(minutes)d minutes, once):'
        '\n%(link)s\n\nIf it was not you, ignore this message.') % {
            'name': guest.name, 'link': link, 'minutes': RESET_MINUTES}))
    _log(PinEventAction.GUEST_RESET, guest, actor, request=request,
         detail=('sent by the administrator' if actor else 'requested') + ('' if sent else ' (not sent)'))
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
    _say(guest, lambda: (_('Your NetBox access was disabled'), _(
        'Hello %(name)s,\n\nthe administrator %(admin)s disabled your access to NetBox on %(time)s. Signing in with '
        'your PIN shows a page where you can ask the administrator to enable it again.') % {
            'name': guest.name, 'admin': actor.get_full_name() or actor.username,
            'time': timezone.localtime(guest.revoked).strftime('%d.%m.%Y %H:%M')}))
    areas.clear_cache()


def restore(guest, actor, request=None):
    if not _may_manage(actor):
        raise PermissionDenied
    guest.revoked = None
    guest.save(update_fields=['revoked'])
    guest.user.is_active = True
    guest.user.save(update_fields=['is_active'])
    _say(guest, lambda: (_('Your NetBox access works again'), _(
        'Hello %(name)s,\n\nthe administrator enabled your access again. You can sign in with your PIN.') % {
            'name': guest.name}))
    _log(PinEventAction.GUEST_INVITED, guest, actor, request, 'restored')
    areas.clear_cache()


def delete(guest, actor, request=None):
    if not _may_manage(actor):
        raise PermissionDenied
    _log(PinEventAction.GUEST_DELETED, guest, actor, request)
    _say(guest, lambda: (_('Your NetBox access was deleted'), _(
        'Hello %(name)s,\n\nthe administrator %(admin)s deleted your access to NetBox. Your PIN does not work any '
        'more.') % {'name': guest.name, 'admin': actor.get_full_name() or actor.username}))
    guest.user.delete()  # takes the access, the PIN and the grants along; the changelog keeps the name
    areas.clear_cache()


def groups_of(guest):
    now = timezone.now()
    return [g for g in AreaGrant.objects.filter(user=guest.user, revoked__isnull=True).select_related('profile', 'area')
            if g.expires is None or g.expires > now]


#
# The session
#

def _backend():
    """NetBox's own permission backend (the one that is configured; ModelBackend may not be)."""
    from django.conf import settings as django_settings
    wanted = 'netbox.authentication.ObjectPermissionBackend'
    backends = list(django_settings.AUTHENTICATION_BACKENDS)
    return wanted if wanted in backends else backends[-1]


def start_session(request, guest, link=''):
    from django.contrib.auth import login
    login(request, guest.user, backend=_backend())  # also renews the session key
    version = UserPin.objects.get(user=guest.user).version
    now = time.time()
    request.session[SESSION_KEY] = {'id': guest.pk, 'start': now, 'last': now, 'ver': version,
                                    'link': link}  # (login() flushes the session of a browser that held another user)
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


def _drop_down_request(request):
    """The request a drop-down of a form field sends: the brief list of a type, or the values of a select custom field."""
    if request.method != 'GET':
        return False
    path = request.path_info
    if path.startswith('/api/extras/custom-field-choice-sets/') and path.rstrip('/').endswith('/choices'):
        return True
    return bool(request.GET.get('brief')) and not path.startswith(('/api/schema', '/api/docs', '/api/status',
                                                                   '/api/authentication-check'))


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
        return redirect(return_url(guest, link))
    if must_change(guest) and not path.startswith(('/plugins/user-pin/guest/change/', '/plugins/user-pin/guest/logout/',
                                                   '/static/', '/media/')):
        return redirect('plugins:netbox_user_pin:guest_change')  # like 'must change password at next logon'
    if path.startswith('/plugins/user-pin/guest/') and not path.startswith('/plugins/user-pin/guest/reset/'):
        return None
    if path == '/' or path.startswith('/plugins/user-pin/'):
        return redirect('plugins:netbox_user_pin:guest_home')
    if path.startswith('/logout/'):
        return redirect('plugins:netbox_user_pin:guest_logout')
    if path.startswith('/api/') and _drop_down_request(request) and not path.startswith(CLOSED_PATHS):
        return None  # a drop-down of a form field fills itself through the API: the protection decides what it lists
    if path.startswith(('/static/docs', '/api/')):  # documentation and the whole API: never for a PIN-only person
        from .area_guard import denied_response
        return denied_response(request, None, right='view', target=None)
    if path.startswith(('/static/', '/media/', '/htmx/')):
        return None
    if path.startswith(CLOSED_PATHS):
        from .area_guard import denied_response
        return denied_response(request, None, right='view', target=None)
    return None


#
# The page that asks only for the PIN: the person is told by the address of the computer and the PIN
#

def _ip_key(address):
    return f'userpin-guestpin-{address}'


def ip_pause(request):
    """Seconds the computer must still wait (wrong PINs from one address, whoever the person is)."""
    address = _client_ip(request)
    state = cache.get(_ip_key(address)) if address else None
    return max(0, int(state['until'] - time.time()) + 1) if state and state.get('until', 0) > time.time() else 0


def pin_only_login(request, pin):
    """
    ``('ok', guest)``, ``('wrong', None)``, ``('pause', None)`` or ``('blocked', None)``. The PIN alone tells who the person
    is (it is unique). A wrong PIN cannot be put down to a person, so the computer (its address) waits by the steps of the
    default rules; the last wait repeats and nobody is blocked. The keepers get an e-mail after every full round.
    """
    address = _client_ip(request)
    if address is None:
        return 'blocked', None
    if ip_pause(request):
        return 'pause', None
    guest = None
    if pin and MIN_PIN_LENGTH <= len(pin) <= MAX_PIN_LENGTH:
        guest = PinGuest.objects.select_related('user').filter(pin_index__in=crypto.pin_lookups(pin)).first()
    if guest is not None and _pin_matches(guest, pin):
        if guest.revoked:
            return 'disabled', guest  # the right PIN of a disabled account: say who disabled it
        if guest.expires and guest.expires <= timezone.now():
            return 'ended', guest
        if not guest.is_active or not guest.user.is_active or not ip_allowed(guest, request):
            return 'blocked', None
        if guest.blocked:
            return 'locked', None
        if pause_seconds(guest):
            return 'pause', None
        cache.delete(_ip_key(address))
        _refresh_pin_index(guest, pin)
        guest.failed, guest.retry_after, guest.last_login, guest.last_ip = 0, None, timezone.now(), str(address)
        guest.save(update_fields=['failed', 'retry_after', 'last_login', 'last_ip'])
        return 'ok', guest
    # the person is not known: the computer waits by the same steps (the last wait repeats, nobody is blocked)
    step, waits = rules()
    state = cache.get(_ip_key(address)) or {'n': 0, 'until': 0}
    state['n'] += 1
    if state['n'] % step == 0:
        state['until'] = time.time() + waits[min(state['n'] // step, len(waits)) - 1]
    cache.set(_ip_key(address), state, 3600)
    service.log_event(PinEventAction.GUEST_FAILED, scope='guest', request=request,
                      detail=f'PIN page, address {address}, attempt {state["n"]}')
    if state['n'] % (step * len(waits)) == 0:
        for keeper in areas.keepers():
            service.send_user_mail(keeper, _('Wrong PINs from %(ip)s') % {'ip': address}, _(
                '%(n)d wrong PINs on the PIN-only page from the address %(ip)s.') % {'n': state['n'], 'ip': address},
                request=request)
    return 'wrong', None


def login_path():
    """The address the people with a PIN only save: ``/<slug>/`` (``BASE_PATH`` of NetBox first, if it has one)."""
    from django.conf import settings as django_settings
    return f'/{django_settings.BASE_PATH}{areas.guest_path()}/'


def return_url(guest, link=''):
    """Where a person goes after signing out / when the session ended: the shared PIN page."""
    return login_path()


#
# A NetBox user may not take the e-mail address of a PIN-only access
#

def email_taken_by_guest(email, user=None):
    """The PIN-only access that uses ``email`` (other than the one of ``user``), or None."""
    email = (email or '').strip()
    if not email:
        return None
    qs = PinGuest.objects.select_related('user').filter(email__iexact=email)
    if user is not None and user.pk:
        qs = qs.exclude(user_id=user.pk)
    return qs.first()


def install_user_email_check():
    """User.clean (forms, REST API, import) refuses an address that a PIN-only access uses."""
    user_model = get_user_model()
    if getattr(user_model, '_userpin_email_check', False):
        return
    original = user_model.clean

    def clean(self):
        original(self)
        guest = email_taken_by_guest(self.email, self)
        if guest is not None:
            raise ValidationError({'email': _(
                'The address %(email)s is used by the PIN-only access %(id)s%(alias)s. Use another address, or delete '
                'that PIN-only access first (User PIN > People with a PIN only).') % {
                    'email': self.email, 'id': guest.user.username,
                    'alias': f' ({guest.alias})' if guest.alias else ''}})

    user_model.clean = clean
    user_model._userpin_email_check = True


#
# E-mails both ways: the person hears about their groups, the administrators about what the person changed
#

def _grant_saved(sender, instance, created, **kwargs):
    """Added to / removed from a group: the person is told (not while the access is still being set up)."""
    guest = PinGuest.objects.select_related('user').filter(user_id=instance.user_id).first()
    if guest is None or not has_pin(guest):
        return
    group = f'{instance.profile.name} ({instance.area.name})'
    if created:
        who = instance.granted_by_name
        what = lambda: _('You were added to the group %(group)s.') % {'group': group}  # noqa: E731
    elif instance.revoked is not None and timezone.now() - instance.revoked < timedelta(minutes=1):
        who = getattr(instance, 'revoked_by_name', '') or instance.granted_by_name
        what = lambda: _('You were removed from the group %(group)s.') % {'group': group}  # noqa: E731
    else:
        return
    actor = get_user_model().objects.filter(username=who).first()
    _say(guest, lambda: (_('Your NetBox access was changed'), _(
        'Hello %(name)s,\n\nthe administrator %(admin)s changed your access to NetBox:\n\n%(what)s') % {
            'name': guest.name, 'admin': (actor.get_full_name() or actor.username) if actor else who, 'what': what()}))


def install_signals():
    from django.db.models.signals import post_save
    post_save.connect(_grant_saved, sender=AreaGrant, dispatch_uid='userpin_guest_grant_mail')


def _change_line(change):
    action = {'create': _('added'), 'update': _('changed'), 'delete': _('deleted')}.get(
        str(change.action), str(change.action))
    model = change.changed_object_type.name if change.changed_object_type_id else ''
    return f'{timezone.localtime(change.time).strftime("%d.%m.%Y %H:%M")}  {action}  {model}: {change.object_repr}'


def report_changes():
    """Hourly: what each person with a PIN only added, changed or deleted, to the creator and the keepers."""
    from core.models import ObjectChange
    settings = service.get_settings()
    now = timezone.now()
    for guest in PinGuest.objects.select_related('user'):
        since = guest.changes_mailed or guest.created
        if not mails_changes(guest, settings):
            guest.changes_mailed = now  # nothing piles up while it is switched off
            guest.save(update_fields=['changes_mailed'])
            continue
        changes = list(ObjectChange.objects.filter(user=guest.user, time__gt=since, time__lte=now)
                       .select_related('changed_object_type').order_by('time')[:500])
        if changes:
            recipients = list(areas.keepers())
            creator = get_user_model().objects.filter(username=guest.created_by_name, is_active=True).first()
            if creator is not None and creator not in recipients:
                recipients.insert(0, creator)
            with translation.override(settings.language or 'en'):
                subject = _('What %(id)s changed in NetBox') % {'id': display(guest)}
                body = _('%(name)s (%(id)s, %(email)s) made %(n)d change(s) since %(since)s:') % {
                    'name': guest.name, 'id': guest.user.username, 'email': guest.email, 'n': len(changes),
                    'since': timezone.localtime(since).strftime('%d.%m.%Y %H:%M')}
                body += '\n\n' + '\n'.join(_change_line(c) for c in changes)
            for recipient in recipients:
                service.send_user_mail(recipient, subject, body)
            _log(PinEventAction.MAIL_SENT, guest, detail=f'{len(changes)} change(s) reported')
        guest.changes_mailed = now
        guest.save(update_fields=['changes_mailed'])
