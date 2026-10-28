"""Pages of the PIN-only access: the person's (public link, PIN, home) and the administration (keepers, owners)."""
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied, ValidationError
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import NoReverseMatch, reverse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from datetime import timedelta

from django.utils.translation import gettext as _
from django.views import View

from . import areas, guests, service
from .area_views import AreaViewMixin, _target_label
from .models import PinGuest

__all__ = ('GuestChangeView', 'GuestEndedView', 'GuestForgotView', 'GuestHomeView', 'GuestLanguageView', 'GuestListView',
           'GuestLoginView', 'GuestLogoutView', 'GuestPinLoginView', 'GuestPinForgotView', 'GuestResetView', 'GuestUnblockRequestView')

T = 'netbox_user_pin/guest_'


def _error(exc):
    return ' '.join(exc.messages) if isinstance(exc, ValidationError) else str(exc)


STOP_KEY = 'userpin_guest_stop'


def _stopped(request, guest, message):
    """The account may not sign in (disabled, ended, blocked): no PIN form, no reset – only 'ask the administrator'."""
    import time
    request.session[STOP_KEY] = {'id': guest.pk, 't': time.time()}
    return render(request, T + 'stopped.html', {'error': message, 'guest_name': guest.name}, status=403)


def _same(request):
    first, second = request.POST.get('pin', ''), request.POST.get('pin2', '')
    if first != second:
        raise ValidationError(_('The two PINs differ.'))
    return first


class GuestLoginView(View):
    """The personal link: the first visit chooses the PIN, the next ones ask for it."""

    def _page(self, request, guest, token, **extra):
        has_pin = guests.has_pin(guest) if guest else False
        setup_ok = bool(guest) and not has_pin and guest.invite_expires and guest.invite_expires > timezone.now()
        return render(request, T + 'login.html', {
            'guest': guest, 'token': token, 'has_pin': has_pin, 'setup_ok': setup_ok,
            'pause': guests.pause_seconds(guest) if guest else 0, 'min_length': guests.MIN_PIN_LENGTH, **extra})

    def get(self, request, token):
        guest = guests.find(token)
        if guest is None:
            disabled = guests.find_disabled(token)
            if disabled is not None:
                return _stopped(request, disabled, guests.stop_message(disabled))
            return render(request, T + 'invalid.html', status=404)
        if request.user.is_authenticated and request.session.get(guests.SESSION_KEY, {}).get('id') == guest.pk:
            return redirect('plugins:netbox_user_pin:guest_home')
        return self._page(request, guest, token)

    def post(self, request, token):
        guest = guests.find(token)
        if guest is None:
            disabled = guests.find_disabled(token)
            if disabled is not None:
                return _stopped(request, disabled, guests.stop_message(disabled))
            return render(request, T + 'invalid.html', status=404)
        link = guests.link_path(token)
        if not guests.has_pin(guest):  # the person chooses the first PIN
            if not (guest.invite_expires and guest.invite_expires > timezone.now()):
                return self._page(request, guest, token, error=_('The invitation has expired. Ask for a new one.'))
            try:
                guests.set_pin(guest, _same(request), request=request, first=True)
            except ValidationError as exc:
                return self._page(request, guest, token, error=_error(exc))
            guests.start_session(request, guest, link)
            return redirect('plugins:netbox_user_pin:guest_home')
        if guest.blocked:
            return _stopped(request, guest, LOCKED_TEXT())
        status = guests.check_pin(guest, request.POST.get('pin', ''), request=request)
        if status == 'ok':
            guests.start_session(request, guest, link)
            return redirect('plugins:netbox_user_pin:guest_home')
        guest.refresh_from_db()
        if status == 'locked':
            return _stopped(request, guest, LOCKED_TEXT())
        error = {'pause': _('Wait a moment before the next attempt.'),
                 'blocked': _('This access is not usable now (ended, revoked or from another address).'),
                 'disabled': _('Your account is disabled (suspended). Contact the administrator.'),
                 'locked': _('Your access is blocked after too many wrong PINs. Ask the administrator to unblock it or to send you a link for a new PIN.'),
                 'nopin': _('Choose your PIN first.')}.get(status, _('The PIN is not correct.'))
        return self._page(request, guest, token, error=error, wrong=status == 'wrong')


class GuestPinLoginView(View):
    """The stable address of the computers: only the PIN is asked, the person is told by the address + PIN."""

    def _page(self, request, **extra):
        return render(request, T + 'pin.html', {'pause': guests.ip_pause(request), **extra})

    def get(self, request):
        if request.user.is_authenticated and guests.guest_of(request.user) is not None:
            return redirect('plugins:netbox_user_pin:guest_home')
        return self._page(request)

    def post(self, request):
        status, guest = guests.pin_only_login(request, request.POST.get('pin', ''))
        if status in ('disabled', 'ended') and guest is not None:
            return _stopped(request, guest, guests.stop_message(guest))
        if status == 'locked' and guest is not None:
            return _stopped(request, guest, LOCKED_TEXT())
        if status == 'ok':
            guests.start_session(request, guest, guests.login_path())
            return redirect('plugins:netbox_user_pin:guest_home')
        error = {'pause': _('Wait a moment before the next attempt.'),
                 'blocked': _('This access is not usable now (ended, revoked or from another address).'),
                 'disabled': _('Your account is disabled (suspended). Contact the administrator.'),
                 'locked': _('Your access is blocked after too many wrong PINs. Ask the administrator to unblock it or to send you a link for a new PIN.'),
                 }.get(status, _('The PIN is not correct.'))
        return self._page(request, error=error, wrong=status == 'wrong')


def LOCKED_TEXT():  # noqa: N802 - a translated text built when used
    return _('Your access is blocked after too many wrong PINs. Ask the administrator to unblock it.')


class GuestUnblockRequestView(View):
    """'Ask the administrator': an e-mail to who disabled the account (or the keepers), at most once an hour."""

    def post(self, request):
        import time
        data = request.session.get(STOP_KEY) or {}
        guest = PinGuest.objects.select_related('user').filter(pk=data.get('id') or 0).first()
        if guest is None or time.time() - data.get('t', 0) > 1800:
            return render(request, T + 'invalid.html', status=404)
        sent = guests.request_unblock(guest, request=request)
        if sent:
            text = _('Your request was sent to: %(admins)s. You will get an e-mail when the access works again.') % {
                'admins': ', '.join(sent)}
        else:
            text = _('Your request was sent already. You can ask again in an hour.')
        return render(request, T + 'stopped.html', {'info': text, 'sent': True, 'guest_name': guest.name})


class GuestPinForgotView(View):
    """Forgotten PIN: write the e-mail address; the answer is always the same."""

    def post(self, request):
        email = (request.POST.get('email') or '').strip().lower()
        guest = PinGuest.objects.select_related('user').filter(email__iexact=email).first() if email else None
        if guest is not None and guest.is_active and not guest.revoked:
            guests.request_reset(guest, request=request)
        return render(request, T + 'forgot.html', {'token': ''})


class GuestForgotView(View):
    """The same answer whatever happens, so nobody learns anything from it."""

    def post(self, request, token):
        guest = guests.find(token)
        if guest is not None:
            guests.request_reset(guest, request=request)
        return render(request, T + 'forgot.html', {'token': token})


class GuestResetView(View):
    def get(self, request, token):
        if guests.find_reset(token) is None:
            return render(request, T + 'invalid.html', status=404)
        return render(request, T + 'reset.html', {'min_length': guests.MIN_PIN_LENGTH})

    def post(self, request, token):
        guest = guests.find_reset(token)
        if guest is None:
            return render(request, T + 'invalid.html', status=404)
        try:
            guests.set_pin(guest, _same(request), request=request)
        except ValidationError as exc:
            return render(request, T + 'reset.html', {'min_length': guests.MIN_PIN_LENGTH, 'error': _error(exc)})
        guests.start_session(request, guest)
        request.session.modified = True
        return redirect('plugins:netbox_user_pin:guest_home')


class GuestEndedView(View):
    def get(self, request):
        return render(request, T + 'ended.html')


class GuestMixin(LoginRequiredMixin):
    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated and guests.guest_of(request.user) is None:
            raise Http404
        return super().dispatch(request, *args, **kwargs)


def _rights_text(rights):
    labels = {'view': _('read'), 'add': _('add'), 'change': _('edit'), 'delete': _('delete')}
    return ', '.join(str(labels.get(r, r)) for r in rights)


def _doors(user):
    """What the person may open: the lists of the object types their groups allow."""
    rows = []
    for grant in guests.groups_of(user.pin_guest):
        profile = grant.profile
        if 'view' not in profile.rights or not profile.target:
            continue
        app_label, _dot, model = profile.target.partition('.')
        try:
            url = reverse(f'{app_label}:{model}_list')
        except NoReverseMatch:
            try:
                url = reverse(f'plugins:{app_label}:{model}_list')
            except NoReverseMatch:
                continue
        add = None
        if 'add' in profile.rights:
            try:
                add = reverse(f'{app_label}:{model}_add')
            except NoReverseMatch:
                add = None
        ends = [d for d in (grant.expires, user.pin_guest.expires) if d]
        rows.append({'label': _target_label(profile.target), 'url': url, 'add': add, 'rights': profile.rights,
                     'rights_text': _rights_text(profile.rights), 'group': profile.name, 'area': grant.area.name,
                     'valid_until': min(ends) if ends else None})
    return rows


class GuestHomeView(GuestMixin, View):
    def get(self, request):
        guest = request.user.pin_guest
        until = guests.pin_valid_until(guest)
        settings = service.get_settings()
        left = (until - timezone.now()) if until else None
        days = left.days if left else None
        hours = left.seconds // 3600 if left else None
        return render(request, T + 'home.html', {
            'guest': guest, 'doors': _doors(request.user), 'left': guests.seconds_left(request, guest) // 60,
            'pin_until': until, 'pin_days': days, 'pin_hours': hours,
            'pin_warn': days is not None and days <= settings.warn_days, 'languages': guests.LANGUAGES[1:],
            'pin_language': guests.language_of(guest)})


class GuestChangeView(GuestMixin, View):
    def _page(self, request, **extra):
        return render(request, T + 'change.html', {'min_length': guests.MIN_PIN_LENGTH,
                                                   'forced': guests.must_change(request.user.pin_guest), **extra})

    def get(self, request):
        return self._page(request)

    def post(self, request):
        guest = request.user.pin_guest
        if not guests.must_change(guest):  # a forced change of a signed-in person needs no current PIN
            status = guests.check_pin(guest, request.POST.get('current', ''), request=request)
            if status == 'locked':
                guests.end_session(request)
                return redirect(guests.return_url(guest))
            if status != 'ok':
                return self._page(request, error=_('The current PIN is not correct, or you must wait a moment.'))
        try:
            guests.set_pin(guest, _same(request), request=request)
        except ValidationError as exc:
            return self._page(request, error=_error(exc))
        messages.success(request, _('Your PIN was changed. Sign in again.'))
        guest = request.user.pin_guest
        link = guests.end_session(request)
        return redirect(guests.return_url(guest, link))


class GuestLanguageView(GuestMixin, View):
    """The person switches the language (PIN pages and the NetBox interface)."""

    def post(self, request):
        code = request.POST.get('language', '')
        guest = request.user.pin_guest
        guests.set_languages(guest, None, pin_language=code, ui_language=code, request=request)
        response = redirect('plugins:netbox_user_pin:guest_home')
        from django.conf import settings as django_settings
        if code:
            response.set_cookie(django_settings.LANGUAGE_COOKIE_NAME, code)
        return response


class GuestLogoutView(View):
    def get(self, request):
        guest = guests.guest_of(request.user)
        link = guests.end_session(request) if request.user.is_authenticated else ''
        return redirect(guests.return_url(guest, link))

    post = get


#
# Administration
#

def _time(text):
    if not text:
        return None
    value = parse_datetime(text)
    if value is None:
        raise ValidationError(_('Write the end as a date and a time.'))
    return timezone.make_aware(value) if timezone.is_naive(value) else value


class GuestListView(AreaViewMixin, View):
    template_name = T + 'list.html'

    def _groups(self, user):
        rows = []
        for group in areas.AreaProfile.objects.filter(private=False).exclude(target='').select_related('area'):
            if areas.can_see(user, group.area) and guests._may_put_in(user, group.area):
                rows.append((group.pk, f'{group.area.name} › {_target_label(group.target)} › {group.name}'))
        return sorted(rows, key=lambda r: r[1])

    def _render(self, request, **extra):
        if not (areas.is_keeper(request.user) or areas.administers_any(request.user)):
            raise PermissionDenied
        rows = []
        for guest in PinGuest.objects.select_related('user'):
            if guest.revoked:
                state = ('revoked', _('Disabled'))
            elif guest.blocked:
                state = ('blocked', _('Blocked (wrong PINs)'))
            elif guest.expires and guest.expires <= timezone.now():
                state = ('ended', _('Ended'))
            elif not guests.has_pin(guest):
                state = ('invited', _('Invited'))
            elif guests.pause_seconds(guest):
                state = ('pause', _('Pause after a wrong PIN'))
            else:
                state = ('active', _('Active'))
            rows.append({'guest': guest, 'state': state, 'groups': guests.groups_of(guest),
                         'must_change': guests.has_pin(guest) and guests.must_change(guest),
                         'pin_until': guests.pin_valid_until(guest), 'rules': guests.rules_text(guest),
                         'activity': _activity(guest),
                         'ended': bool(guest.expires and guest.expires <= timezone.now()),
                         'ends_soon': bool(guest.expires and guest.expires - timezone.now() <= timedelta(days=7))})
        return render(request, self.template_name, {
            'login_url': request.build_absolute_uri(guests.login_path()), 'guest_path': areas.guest_path(),
            'path_a': areas.guest_path().split('/')[0],
            'path_b': areas.guest_path().split('/')[1] if '/' in areas.guest_path() else '',
            'is_keeper': areas.is_keeper(request.user),
            'rows': rows, 'group_choices': self._groups(request.user), 'mail_ok': service.email_configured(),
            'min_length': guests.MIN_PIN_LENGTH, 'default_step': service.get_settings().guest_step_attempts,
            'default_waits': service.get_settings().guest_waits, 'default_rules': guests.rules_text(),
            'languages': guests.LANGUAGES[1:], 'pin_settings': service.get_settings(), 'mail_every': guests.MAIL_EVERY, **extra})

    def get(self, request):
        return self._render(request)

    def post(self, request):
        action = request.POST.get('action')
        try:
            if action == 'path':
                slug = areas.set_guest_path(request.user, (request.POST.get('path_a'), request.POST.get('path_b')),
                                            request=request)
                messages.success(request, _('The address is /%(slug)s/.') % {'slug': slug})
                return redirect('plugins:netbox_user_pin:guests')
            if action == 'rules-default':
                guests.set_rules(None, request.user, request.POST.get('step'), request.POST.get('waits'),
                                 request=request)
                messages.success(request, _('The rules for wrong PINs were saved.'))
                return redirect('plugins:netbox_user_pin:guests')
            if action == 'mails-default':
                guests.set_mails(None, request.user, request.POST.get('mail_person'), request.POST.get('mail_changes'),
                                 request=request)
                guests.set_mail_mode(request.user, request.POST.get('mail_mode'), request.POST.get('mail_every'),
                                     request=request)
                messages.success(request, _('Saved.'))
                return redirect('plugins:netbox_user_pin:guests')
            if action == 'create':
                group = get_object_or_404(areas.AreaProfile, pk=request.POST.get('group') or 0)
                guest, token = guests.create(
                    request.POST.get('name'), request.POST.get('email'), group, request.user,
                    expires=_time(request.POST.get('expires')), ips=request.POST.get('ips', ''),
                    idle=request.POST.get('idle'), hours=request.POST.get('hours'), note=request.POST.get('note', ''),
                    request=request, alias=request.POST.get('alias', ''),
                    description=request.POST.get('description', ''),
                    pin_language=request.POST.get('pin_language', ''), ui_language=request.POST.get('ui_language', ''))
                if not (request.POST.get('mail_person') and request.POST.get('mail_changes')):
                    guests.set_mails(guest, request.user, request.POST.get('mail_person'),
                                     request.POST.get('mail_changes'), request=request)
                token, sent = guests.invite(guest, request.user, request=request)
                if sent:
                    messages.success(request, _('The access was created and the invitation sent to %(email)s.') % {
                        'email': guest.email})
                    return redirect('plugins:netbox_user_pin:guests')
                return self._render(request, new_link=request.build_absolute_uri(guests.link_path(token)),
                                    new_guest=guest)  # no working e-mail: the link is shown once
            guest = get_object_or_404(PinGuest, pk=request.POST.get('pk') or 0)
            if action == 'invite':
                token, sent = guests.invite(guest, request.user, request=request)
                if sent:
                    messages.success(request, _('The invitation was sent.'))
                    return redirect('plugins:netbox_user_pin:guests')
                return self._render(request, new_link=request.build_absolute_uri(guests.link_path(token)),
                                    new_guest=guest)
            if action == 'reset':
                from .models import UserPin
                UserPin.objects.filter(user=guest.user).update(pin_hash='', version=guest.user.user_pin.version + 1)
                guest.failed, guest.retry_after, guest.pin_index = 0, None, None
                guest.save(update_fields=['failed', 'retry_after', 'pin_index'])
                token, sent = guests.invite(guest, request.user, request=request)
                messages.success(request, _('The PIN was cleared; the person chooses a new one through the new link.'))
                if not sent:
                    return self._render(request, new_link=request.build_absolute_uri(guests.link_path(token)),
                                        new_guest=guest)
            elif action == 'expires':
                guests.set_expiry(guest, request.user, _time(request.POST.get('expires')), request=request)
                messages.success(request, _('The validity of the access was saved.'))
            elif action == 'unblock':
                guests.unblock(guest, request.user, request=request)
                messages.success(request, _('The access is unblocked; the old PIN works again.'))
            elif action == 'reset-mail':
                if guests.request_reset(guest, request=request, actor=request.user):
                    messages.success(request, _('A link for a new PIN was sent to %(email)s.') % {'email': guest.email})
                else:
                    messages.error(request, _('The e-mail could not be sent – see the audit log.'))
            elif action == 'force-change':
                guests.force_change(guest, request.user, request=request)
                messages.success(request, _('The person must choose a new PIN at the next sign-in.'))
            elif action == 'alias':
                guests.set_alias(guest, request.user, request.POST.get('alias'), request.POST.get('description', ''),
                                 request=request)
                guests.set_languages(guest, request.user, request.POST.get('pin_language'),
                                     request.POST.get('ui_language'), request=request)
                messages.success(request, _('Saved.'))
            elif action == 'mails':
                guests.set_mails(guest, request.user, request.POST.get('mail_person'), request.POST.get('mail_changes'),
                                 request=request)
                messages.success(request, _('Saved.'))
            elif action == 'rules':
                guests.set_rules(guest, request.user, request.POST.get('step'), request.POST.get('waits'),
                                 request=request)
                messages.success(request, _('The rules for wrong PINs were saved.'))
            elif action == 'revoke':
                guests.revoke(guest, request.user, request=request)
                messages.success(request, _('The access was revoked.'))
            elif action == 'restore':
                guests.restore(guest, request.user, request=request)
                messages.success(request, _('The access works again.'))
            elif action == 'delete':
                guests.delete(guest, request.user, request=request)
                messages.success(request, _('The access was deleted.'))
        except ValidationError as exc:
            messages.error(request, _error(exc))
        except PermissionDenied:
            messages.error(request, _('You may not do this.'))
        return redirect('plugins:netbox_user_pin:guests')


def _activity(guest, limit=30):
    """Sign-ins and PIN events of the access, and what it changed in NetBox (newest first)."""
    from core.models import ObjectChange
    from .models import PinEvent
    return {
        'events': list(PinEvent.objects.filter(user=guest.user).order_by('-time')[:limit]),
        'changes': list(ObjectChange.objects.filter(user=guest.user).order_by('-time')[:limit]),
        'changes_total': ObjectChange.objects.filter(user=guest.user).count(),
    }
