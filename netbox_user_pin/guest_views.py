"""Pages of the PIN-only access: the person's (public link, PIN, home) and the administration (keepers, owners)."""
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied, ValidationError
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import NoReverseMatch, reverse
from datetime import timedelta

from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.utils.translation import gettext as _
from django.views import View

from . import areas, guests, service
from .area_views import AreaViewMixin, _target_label
from .models import PinGuest

__all__ = ('GuestChangeView', 'GuestEndedView', 'GuestForgotView', 'GuestHomeView', 'GuestListView',
           'GuestLoginView', 'GuestLogoutView', 'GuestPinLoginView', 'GuestPinForgotView', 'GuestResetView')

T = 'netbox_user_pin/guest_'


def _error(exc):
    return ' '.join(exc.messages) if isinstance(exc, ValidationError) else str(exc)


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
            'pause': guests.pause_seconds(guest) if guest else 0, 'min_length': guests.min_length(),
            'reset_offered': bool(guest) and guests.reset_offered(guest.failed), **extra})

    def get(self, request, token):
        guest = guests.find(token)
        if guest is None:
            return render(request, T + 'invalid.html', status=404)
        if request.user.is_authenticated and request.session.get(guests.SESSION_KEY, {}).get('id') == guest.pk:
            return redirect('plugins:netbox_user_pin:guest_home')
        return self._page(request, guest, token)

    def post(self, request, token):
        guest = guests.find(token)
        if guest is None:
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
        status = guests.check_pin(guest, request.POST.get('pin', ''), request=request)
        if status == 'ok':
            guests.start_session(request, guest, link)
            return redirect('plugins:netbox_user_pin:guest_home')
        guest.refresh_from_db()
        error = {'pause': _('Wait a moment before the next attempt.'),
                 'blocked': _('This access is not usable now (ended, revoked or from another address).'),
                 'nopin': _('Choose your PIN first.')}.get(status, _('The PIN is not correct.'))
        return self._page(request, guest, token, error=error, wrong=status == 'wrong')


class GuestPinLoginView(View):
    """The stable address of the computers: only the PIN is asked, the person is told by the address + PIN."""

    def _page(self, request, **extra):
        pause, wrong = guests.ip_state(request)
        return render(request, T + 'pin.html', {'pause': pause, 'reset_offered': guests.reset_offered(wrong), **extra})

    def get(self, request):
        if request.user.is_authenticated and guests.guest_of(request.user) is not None:
            return redirect('plugins:netbox_user_pin:guest_home')
        return self._page(request)

    def post(self, request):
        status, guest = guests.pin_only_login(request, request.POST.get('pin', ''))
        if status == 'ok':
            guests.start_session(request, guest, guests.login_path())
            return redirect('plugins:netbox_user_pin:guest_home')
        error = {'pause': _('Wait a moment before the next attempt.'),
                 'blocked': _('This access is not usable now (ended, revoked or from another address).')
                 }.get(status, _('The PIN is not correct.'))
        return self._page(request, error=error, wrong=status == 'wrong')


class GuestPinForgotView(View):
    """Forgotten PIN: write the e-mail address; the answer is always the same."""

    def post(self, request):
        email = (request.POST.get('email') or '').strip().lower()
        guest = PinGuest.objects.select_related('user').filter(email__iexact=email).first() if email else None
        if guest is not None and guest.is_active:
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
        return render(request, T + 'reset.html', {'min_length': guests.min_length()})

    def post(self, request, token):
        guest = guests.find_reset(token)
        if guest is None:
            return render(request, T + 'invalid.html', status=404)
        try:
            guests.set_pin(guest, _same(request), request=request)
        except ValidationError as exc:
            return render(request, T + 'reset.html', {'min_length': guests.min_length(), 'error': _error(exc)})
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
        rows.append({'label': _target_label(profile.target), 'url': url, 'add': add, 'rights': profile.rights})
    return rows


class GuestHomeView(GuestMixin, View):
    def get(self, request):
        guest = request.user.pin_guest
        doors = _doors(request.user)
        if len(doors) == 1:  # one place to work in: straight there (no page in between)
            return redirect(doors[0]['url'])
        return render(request, T + 'home.html', {
            'guest': guest, 'doors': doors, 'left': guests.seconds_left(request, guest) // 60})


class GuestChangeView(GuestMixin, View):
    def _page(self, request, **extra):
        return render(request, T + 'change.html', {'min_length': guests.min_length(), **extra})

    def get(self, request):
        return self._page(request)

    def post(self, request):
        guest = request.user.pin_guest
        if guests.check_pin(guest, request.POST.get('current', ''), request=request) != 'ok':
            return self._page(request, error=_('The current PIN is not correct, or you must wait a moment.'))
        try:
            guests.set_pin(guest, _same(request), request=request)
        except ValidationError as exc:
            return self._page(request, error=_error(exc))
        messages.success(request, _('Your PIN was changed. Sign in again.'))
        guest = request.user.pin_guest
        link = guests.end_session(request)
        return redirect(guests.return_url(guest, link))


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
                state = ('revoked', _('Revoked'))
            elif guest.expires and guest.expires <= timezone.now():
                state = ('ended', _('Ended'))
            elif not guests.has_pin(guest):
                state = ('invited', _('Invited'))
            elif guests.pause_seconds(guest):
                state = ('pause', _('Pause after a wrong PIN'))
            else:
                state = ('active', _('Active'))
            rows.append({'guest': guest, 'state': state, 'groups': guests.groups_of(guest),
                         'wait': guests.pause_seconds(guest), 'activity': guests.activity(guest)})
        now = timezone.now()
        states = [r['state'][0] for r in rows]
        stats = {
            'total': len(rows), 'active': states.count('active'), 'invited': states.count('invited'),
            'waiting': states.count('pause'), 'revoked': states.count('revoked') + states.count('ended'),
            'today': sum(1 for r in rows if r['guest'].last_login and r['guest'].last_login > now - timedelta(hours=24)),
        }
        waiting = [r for r in rows if r['wait']]
        return render(request, self.template_name, {
            'stats': stats, 'waiting': waiting,
            'tiles': [(_('Accesses'), stats['total'], 'body'), (_('Active'), stats['active'], 'green'),
                      (_('Invited'), stats['invited'], 'yellow'), (_('Waiting after wrong PINs'), stats['waiting'] + len(guests.blocked_computers()), 'orange'),
                      (_('Revoked or ended'), stats['revoked'], 'red'), (_('Signed in in 24 h'), stats['today'], 'azure')], 'login_url': request.build_absolute_uri(guests.login_path()), 'guest_path': areas.guest_path(),
            'is_keeper': areas.is_keeper(request.user), 'cfg': service.get_settings(),
            'blocked': guests.blocked_computers(),
            'rows': rows, 'group_choices': self._groups(request.user), 'mail_ok': service.email_configured(),
            'min_length': guests.min_length(), **extra})

    def get(self, request):
        return self._render(request)

    def post(self, request):
        action = request.POST.get('action')
        try:
            if action == 'unblock-ip':
                guests.unblock_computer(request.user, request.POST.get('pk') or 0, request=request)
                messages.success(request, _('The computer was released.'))
                return redirect('plugins:netbox_user_pin:guests')
            if action == 'policy':
                guests.set_policy(request.user, request.POST.get('free'), request.POST.get('pauses', ''),
                                  request.POST.get('reset_after'), request.POST.get('minimum'), request=request)
                messages.success(request, _('Saved.'))
                return redirect('plugins:netbox_user_pin:guests')
            if action == 'path':
                slug = areas.set_guest_path(request.user, request.POST.get('path'), request=request)
                messages.success(request, _('The address is /%(slug)s/.') % {'slug': slug})
                return redirect('plugins:netbox_user_pin:guests')
            if action == 'create':
                group = get_object_or_404(areas.AreaProfile, pk=request.POST.get('group') or 0)
                guest, token = guests.create(
                    request.POST.get('name'), request.POST.get('email'), group, request.user,
                    expires=_time(request.POST.get('expires')), ips=request.POST.get('ips', ''),
                    idle=request.POST.get('idle'), hours=request.POST.get('hours'), note=request.POST.get('note', ''),
                    request=request)
                token, sent = guests.invite(guest, request.user, request=request)
                if sent:
                    messages.success(request, _('The access was created and the invitation sent to %(email)s.') % {
                        'email': guest.email})
                    return redirect('plugins:netbox_user_pin:guests')
                return self._render(request, new_link=request.build_absolute_uri(guests.link_path(token)),
                                    new_guest=guest)  # no working e-mail: the link is shown once
            guest = get_object_or_404(PinGuest, pk=request.POST.get('pk') or 0)
            if action == 'unblock':
                guests.unblock_guest(request.user, guest, request=request)
                messages.success(request, _('Released: the access may try again.'))
            elif action == 'invite':
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
