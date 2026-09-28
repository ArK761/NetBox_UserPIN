import time
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core import mail
from django.core.exceptions import ValidationError
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from netbox_user_pin import approvals, crypto, service, totp
from netbox_user_pin.models import (
    ApprovalRequest, ApprovalStatus, PinAccess, PinAccessMode, PinDelegate, PinEvent, PinEventAction, PinScopeMode, PinSettings, UserPin,
)
from netbox_user_pin.policy import is_weak_pin

User = get_user_model()


class PinTestCase(TestCase):
    """Most tests run in 'all users' mode; access control itself is tested in AccessTest."""

    def setUp(self):
        super().setUp()
        settings = PinSettings.load()
        settings.access_mode = PinAccessMode.ALL
        settings.save()
GOOD_PIN = '482915'
OTHER_PIN = '730461'


def enable_2fa(user):
    """Enroll 2FA directly; returns the secret."""
    secret = totp.generate_secret()
    user_pin, _created = UserPin.objects.get_or_create(user=user)
    user_pin.totp_secret = crypto.encrypt(secret, f'netbox_user_pin:totp:{user.pk}'.encode())
    user_pin.save()
    return secret


def current_code(secret, offset=0):
    return totp._code_at(secret, int(time.time() // totp.STEP) + offset)


def admin_login(client, user, pin=GOOD_PIN, secret=None):
    """Log in, set PIN + 2FA, unlock the admin area and perform a step-up."""
    if not service.has_pin(user):
        service.set_pin(user, pin)
    if secret is None:
        secret = enable_2fa(user)
    client.force_login(user)
    client.post(reverse('plugins:netbox_user_pin:unlock'), {'pin': pin, 'scope': 'user-pin-admin'})
    response = client.post(reverse('plugins:netbox_user_pin:step_up'), {'pin': pin, 'otp': current_code(secret)})
    assert response.status_code == 302, response.content[:500]
    return secret


def allow_domains(*domains):
    from netbox_user_pin.models import AllowedDomain
    for domain in domains:
        AllowedDomain.objects.update_or_create(domain=domain, defaults={'verified': timezone.now()})


class PolicyTest(PinTestCase):

    def test_weak_pins(self):
        for pin in ('000000', '111111', '123456', '654321', '121212', '123123', '012345'):
            self.assertTrue(is_weak_pin(pin), pin)
        for pin in (GOOD_PIN, OTHER_PIN, '100200'):
            self.assertFalse(is_weak_pin(pin), pin)
        self.assertTrue(is_weak_pin(GOOD_PIN, blocked={GOOD_PIN}))

    def test_validation(self):
        settings = PinSettings.load()
        for pin in ('12345', '1234567', 'abcdef', '１２３４５６', '111111'):
            with self.assertRaises(ValidationError, msg=pin):
                service.set_pin(User.objects.create_user(f'u{abs(hash(pin))}'), pin)
        settings.block_weak_pins = False
        settings.save()
        service.set_pin(User.objects.create_user('weakok'), '111111')


class CryptoTest(PinTestCase):

    def test_roundtrip_and_aad(self):
        token = crypto.encrypt('secret', b'a')
        self.assertTrue(token.startswith('k1:'))
        self.assertEqual(crypto.decrypt(token, b'a'), 'secret')
        with self.assertRaises(crypto.DecryptionError):
            crypto.decrypt(token, b'b')

    def test_tampered(self):
        token = crypto.encrypt('secret', b'a')
        tampered = token[:-4] + ('AAAA' if not token.endswith('AAAA') else 'BBBB')
        with self.assertRaises(crypto.DecryptionError):
            crypto.decrypt(tampered, b'a')

    def test_unknown_key(self):
        with self.assertRaises(crypto.DecryptionError):
            crypto.decrypt('zz:' + crypto.encrypt('x', b'a').split(':', 1)[1], b'a')


class ServiceTest(PinTestCase):

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user('alice')
        self.factory = RequestFactory()

    def _request(self):
        from django.contrib.sessions.backends.db import SessionStore
        request = self.factory.get('/')
        request.user = self.user
        request.session = SessionStore()
        return request

    def test_stored_value_is_encrypted_hash(self):
        user_pin = service.set_pin(self.user, GOOD_PIN)
        self.assertNotIn(GOOD_PIN, user_pin.pin_hash)
        self.assertNotIn('argon2', user_pin.pin_hash)
        self.assertTrue(crypto.decrypt(user_pin.pin_hash, user_pin.aad).startswith('$argon2id$'))

    def test_hash_bound_to_user(self):
        user_pin = service.set_pin(self.user, GOOD_PIN)
        bob = User.objects.create_user('bob')
        service.set_pin(bob, OTHER_PIN)
        UserPin.objects.filter(user=bob).update(pin_hash=user_pin.pin_hash)
        with self.assertRaises(crypto.DecryptionError):
            service.verify_pin(bob, GOOD_PIN)
        self.assertTrue(PinEvent.objects.filter(user=bob, action=PinEventAction.ERROR).exists())

    def test_verify_and_lockout(self):
        service.set_pin(self.user, GOOD_PIN)
        settings = PinSettings.load()
        settings.max_attempts = 3
        settings.save()
        self.assertTrue(service.verify_pin(self.user, GOOD_PIN))
        r = service.verify_pin(self.user, '000001')
        self.assertEqual((r.status, r.remaining_attempts), (service.VerifyStatus.WRONG, 2))
        service.verify_pin(self.user, '000001')
        r = service.verify_pin(self.user, '000001')
        self.assertEqual(r.status, service.VerifyStatus.LOCKED_OUT)
        # even the right PIN is refused while locked out
        self.assertEqual(service.verify_pin(self.user, GOOD_PIN).status, service.VerifyStatus.LOCKED_OUT)
        self.assertTrue(PinEvent.objects.filter(action=PinEventAction.LOCKED_OUT).exists())
        service.clear_lockout(self.user, actor=self.user)
        self.assertTrue(service.verify_pin(self.user, GOOD_PIN))

    def test_lockout_expires(self):
        service.set_pin(self.user, GOOD_PIN)
        UserPin.objects.filter(user=self.user).update(locked_until=timezone.now() - timedelta(seconds=1))
        self.assertTrue(service.verify_pin(self.user, GOOD_PIN))

    def test_success_resets_counter(self):
        service.set_pin(self.user, GOOD_PIN)
        service.verify_pin(self.user, '000001')
        service.verify_pin(self.user, GOOD_PIN)
        self.assertEqual(UserPin.objects.get(user=self.user).failed_attempts, 0)

    def test_change_pin(self):
        service.set_pin(self.user, GOOD_PIN)
        with self.assertRaises(ValidationError):
            service.change_pin(self.user, '000001', OTHER_PIN)
        with self.assertRaises(ValidationError):
            service.change_pin(self.user, GOOD_PIN, GOOD_PIN)
        service.change_pin(self.user, GOOD_PIN, OTHER_PIN)
        self.assertTrue(service.verify_pin(self.user, OTHER_PIN))
        self.assertFalse(service.verify_pin(self.user, GOOD_PIN))

    def test_set_pin_twice_refused(self):
        service.set_pin(self.user, GOOD_PIN)
        with self.assertRaises(ValidationError):
            service.set_pin(self.user, OTHER_PIN)

    def test_session_unlock_global_mode(self):
        service.set_pin(self.user, GOOD_PIN)
        request = self._request()
        self.assertFalse(service.is_unlocked(request, 'projects'))
        self.assertFalse(service.unlock(request, '000001', 'projects'))
        self.assertTrue(service.unlock(request, GOOD_PIN, 'projects'))
        self.assertTrue(service.is_unlocked(request, 'projects'))
        self.assertTrue(service.is_unlocked(request, 'other'))  # global mode
        service.lock(request)
        self.assertFalse(service.is_unlocked(request, 'projects'))

    def test_session_unlock_per_scope(self):
        settings = PinSettings.load()
        settings.scope_mode = PinScopeMode.PER_SCOPE
        settings.save()
        service.set_pin(self.user, GOOD_PIN)
        request = self._request()
        service.unlock(request, GOOD_PIN, 'projects')
        self.assertTrue(service.is_unlocked(request, 'projects'))
        self.assertFalse(service.is_unlocked(request, 'other'))
        service.lock(request, 'projects')
        self.assertFalse(service.is_unlocked(request, 'projects'))

    def test_unlock_expires(self):
        service.set_pin(self.user, GOOD_PIN)
        request = self._request()
        service.unlock(request, GOOD_PIN)
        data = request.session[service.SESSION_KEY]
        data['unlocks'] = {k: 1 for k in data['unlocks']}
        self.assertFalse(service.is_unlocked(request))

    def test_reset_invalidates_unlock(self):
        service.set_pin(self.user, GOOD_PIN)
        request = self._request()
        service.unlock(request, GOOD_PIN)
        admin = User.objects.create_superuser('admin')
        service.reset_pin(self.user, actor=admin)
        self.assertFalse(service.has_pin(self.user))
        self.assertFalse(service.is_unlocked(request))
        event = PinEvent.objects.get(action=PinEventAction.RESET)
        self.assertEqual((event.username, event.actor_username), ('alice', 'admin'))

    def test_expired_pin(self):
        settings = PinSettings.load()
        settings.max_age_days = 30
        settings.save()
        service.set_pin(self.user, GOOD_PIN)
        self.assertFalse(service.pin_expired(self.user))
        UserPin.objects.filter(user=self.user).update(changed=timezone.now() - timedelta(days=31))
        self.assertTrue(service.pin_expired(self.user))

    def test_events_are_append_only_and_secret_free(self):
        service.set_pin(self.user, GOOD_PIN)
        service.verify_pin(self.user, '000001')
        event = PinEvent.objects.first()
        with self.assertRaises(RuntimeError):
            event.save()
        with self.assertRaises(RuntimeError):
            event.delete()
        for event in PinEvent.objects.all():
            self.assertNotIn(GOOD_PIN, event.detail)
            self.assertNotIn('000001', event.detail)


class ViewTest(PinTestCase):

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user('alice', password='pw')
        self.client.force_login(self.user)

    def test_protected_page_flow(self):
        test_url = reverse('plugins:netbox_user_pin:test')
        # no PIN yet -> set PIN
        response = self.client.get(test_url)
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('plugins:netbox_user_pin:set_pin'), response.url)

        response = self.client.post(reverse('plugins:netbox_user_pin:set_pin'), {
            'new_pin': GOOD_PIN, 'confirm_pin': GOOD_PIN, 'next': test_url,
        })
        self.assertRedirects(response, test_url, fetch_redirect_response=False)

        # PIN set but locked -> unlock page
        response = self.client.get(test_url)
        self.assertIn(reverse('plugins:netbox_user_pin:unlock'), response.url)

        response = self.client.post(reverse('plugins:netbox_user_pin:unlock'), {
            'pin': '000001', 'next': test_url, 'scope': 'test',
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Wrong PIN')

        response = self.client.post(reverse('plugins:netbox_user_pin:unlock'), {
            'pin': GOOD_PIN, 'next': test_url, 'scope': 'test',
        })
        self.assertRedirects(response, test_url, fetch_redirect_response=False)
        self.assertEqual(self.client.get(test_url).status_code, 200)

        self.client.post(reverse('plugins:netbox_user_pin:lock'))
        self.assertEqual(self.client.get(test_url).status_code, 302)

    def test_open_redirect_blocked(self):
        service.set_pin(self.user, GOOD_PIN)
        response = self.client.post(reverse('plugins:netbox_user_pin:unlock'), {
            'pin': GOOD_PIN, 'next': 'https://evil.example.com/',
        })
        self.assertEqual(response.url, reverse('plugins:netbox_user_pin:my_pin'))

    def test_htmx_redirect(self):
        response = self.client.get(reverse('plugins:netbox_user_pin:test'), HTTP_HX_REQUEST='true')
        self.assertIn('HX-Redirect', response)

    def test_pages_render(self):
        service.set_pin(self.user, GOOD_PIN)
        for name in ('my_pin', 'change_pin', 'unlock'):
            self.assertEqual(self.client.get(reverse(f'plugins:netbox_user_pin:{name}')).status_code, 200, name)

    def test_admin_pages_require_permission(self):
        for name in ('user_list', 'event_list', 'settings'):
            self.assertEqual(self.client.get(reverse(f'plugins:netbox_user_pin:{name}')).status_code, 403, name)
        response = self.client.post(
            reverse('plugins:netbox_user_pin:user_action', kwargs={'pk': self.user.pk, 'action': 'reset'})
        )
        self.assertEqual(response.status_code, 403)

    def test_admin_pages(self):
        service.set_pin(self.user, GOOD_PIN)
        admin = User.objects.create_superuser('admin', password='pw')
        admin_login(self.client, admin)
        for name in ('user_list', 'event_list', 'settings', 'delegates'):
            self.assertEqual(self.client.get(reverse(f'plugins:netbox_user_pin:{name}')).status_code, 200, name)
        # a PIN reset needs the user's 2FA, the administrator cannot reset alone
        self.client.post(reverse('plugins:netbox_user_pin:user_action', kwargs={'pk': self.user.pk, 'action': 'reset'}))
        self.assertTrue(service.has_pin(self.user))
        self.assertEqual(UserPin.objects.get(user=self.user).reset_pending, '')

        data = {
            'language': 'en', 'access_mode': 'all', 'pin_length': 8, 'block_weak_pins': 'on', 'blocked_pins': '', 'max_age_days': 180,
            'warn_days': 14, 'unlock_minutes': 10, 'sliding_unlock': 'on', 'scope_mode': 'global',
            'max_attempts': 5, 'lockout_minutes': 30, 'require_2fa_admin': 'on', 'step_up_minutes': 5,
            'reset_valid_hours': 24, 'approval_valid_minutes': 1440,
        }
        self.client.post(reverse('plugins:netbox_user_pin:settings'), data)
        self.assertEqual(PinSettings.load().pin_length, 8)
        event = PinEvent.objects.get(action=PinEventAction.SETTINGS_CHANGED)
        self.assertIn('pin_length: 6 -> 8', event.detail)

    def test_admin_pages_need_pin_unlock_and_step_up(self):
        admin = User.objects.create_superuser('admin2', password='pw')
        self.client.force_login(admin)
        # no PIN yet -> set PIN first
        response = self.client.get(reverse('plugins:netbox_user_pin:user_list'))
        self.assertIn(reverse('plugins:netbox_user_pin:set_pin'), response.url)
        service.set_pin(admin, GOOD_PIN)
        self.client.post(reverse('plugins:netbox_user_pin:unlock'), {'pin': GOOD_PIN, 'scope': 'user-pin-admin'})
        self.assertEqual(self.client.get(reverse('plugins:netbox_user_pin:user_list')).status_code, 200)
        # actions need a step-up
        url = reverse('plugins:netbox_user_pin:user_action', kwargs={'pk': self.user.pk, 'action': 'deny'})
        response = self.client.post(url)
        self.assertIn(reverse('plugins:netbox_user_pin:step_up'), response.url)
        self.assertTrue(service.is_allowed(self.user))


class ConfigTest(PinTestCase):

    def test_fingerprint_is_stable_and_not_the_key(self):
        from netbox.plugins import get_plugin_config
        key = get_plugin_config('netbox_user_pin', 'encryption_keys')['k1']
        fp = crypto.fingerprint()
        self.assertEqual(fp, crypto.fingerprint('k1'))
        self.assertNotIn(fp.replace(':', ''), key.upper())


class KeyRotationTest(PinTestCase):

    def test_rotate_to_new_key(self):
        from django.conf import settings as dj_settings
        from django.core.management import call_command

        user = User.objects.create_user('carol')
        service.set_pin(user, GOOD_PIN)
        old = dict(dj_settings.PLUGINS_CONFIG['netbox_user_pin'])
        new_config = {**old, 'encryption_keys': {**old['encryption_keys'], 'k2': crypto.generate_key()},
                      'active_key_id': 'k2'}
        with override_settings(PLUGINS_CONFIG={**dj_settings.PLUGINS_CONFIG, 'netbox_user_pin': new_config}):
            call_command('userpin_rotate_key', stdout=open('/dev/null', 'w'))
            self.assertTrue(UserPin.objects.get(user=user).pin_hash.startswith('k2:'))
            self.assertTrue(service.verify_pin(user, GOOD_PIN))
            call_command('userpin_check', stdout=open('/dev/null', 'w'))
        self.assertTrue(PinEvent.objects.filter(action=PinEventAction.KEY_ROTATED).exists())


class KeyFormatTest(PinTestCase):

    def test_passphrase_and_base64_keys(self):
        from django.conf import settings as dj_settings
        from django.core.exceptions import ImproperlyConfigured

        base = dict(dj_settings.PLUGINS_CONFIG['netbox_user_pin'])
        passphrase = ')0)+jM*!7#(1KsRywI+MonRTHpfzPx^w*aTkGD^3JkgFOD@pbtHtlVu9(+1aA^GP'
        for keys, ok in (({'k1': passphrase}, True), ({'k1': crypto.generate_key()}, True),
                         ({'k1': 'too-short'}, False)):
            config = {**base, 'encryption_keys': keys, 'active_key_id': 'k1'}
            with override_settings(PLUGINS_CONFIG={**dj_settings.PLUGINS_CONFIG, 'netbox_user_pin': config}):
                if ok:
                    self.assertEqual(crypto.decrypt(crypto.encrypt('x', b'a'), b'a'), 'x')
                else:
                    with self.assertRaises(ImproperlyConfigured):
                        crypto.validate_configuration()


class AccessTest(PinTestCase):

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user('dave', password='pw')
        self.admin = User.objects.create_superuser('boss', password='pw')

    def test_denied_user(self):
        service.set_pin(self.user, GOOD_PIN)
        service.set_access(self.user, PinAccess.DENIED, actor=self.admin)
        self.assertFalse(service.is_allowed(self.user))
        self.assertEqual(service.verify_pin(self.user, GOOD_PIN).status, service.VerifyStatus.NOT_ALLOWED)
        self.client.force_login(self.user)
        self.assertEqual(self.client.get(reverse('plugins:netbox_user_pin:test')).status_code, 403)
        self.assertEqual(self.client.get(reverse('plugins:netbox_user_pin:unlock')).status_code, 403)
        event = PinEvent.objects.get(action=PinEventAction.ACCESS_CHANGED)
        self.assertEqual((event.username, event.actor_username, event.detail), ('dave', 'boss', 'default -> denied'))

    def test_allowed_only_mode(self):
        settings = PinSettings.load()
        settings.access_mode = PinAccessMode.ALLOWED_ONLY
        settings.save()
        with self.assertRaises(ValidationError):
            service.set_pin(self.user, GOOD_PIN)
        service.set_access(self.user, PinAccess.ALLOWED, actor=self.admin)
        service.set_pin(self.user, GOOD_PIN)
        self.assertTrue(service.verify_pin(self.user, GOOD_PIN))

    def test_admin_actions_and_list(self):
        admin_login(self.client, self.admin)
        url = reverse('plugins:netbox_user_pin:user_action', kwargs={'pk': self.user.pk, 'action': 'deny'})
        self.client.post(url)
        self.assertFalse(service.is_allowed(self.user))
        response = self.client.get(reverse('plugins:netbox_user_pin:user_list') + '?status=not_allowed')
        self.assertContains(response, 'dave')
        self.assertEqual(response.context['summary']['not_allowed'], 1)
        url = reverse('plugins:netbox_user_pin:user_action', kwargs={'pk': self.user.pk, 'action': 'default'})
        self.client.post(url)
        self.assertTrue(service.is_allowed(self.user))

    def test_default_mode_only_allowed_and_superusers(self):
        settings = PinSettings.load()
        settings.access_mode = PinAccessMode.ALLOWED_ONLY
        settings.save()
        self.assertFalse(service.is_allowed(self.user))
        self.assertTrue(service.is_allowed(self.admin))


class TwoFactorTest(PinTestCase):

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user('erik', password='pw')
        service.set_pin(self.user, GOOD_PIN)

    def test_enrollment_via_views(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse('plugins:netbox_user_pin:totp_setup'))
        self.assertContains(response, '<svg')
        secret = self.client.session[service.ENROLL_SESSION_KEY]['secret']
        response = self.client.post(reverse('plugins:netbox_user_pin:totp_setup'), {'otp': '000000'})
        self.assertContains(response, 'not correct')
        response = self.client.post(reverse('plugins:netbox_user_pin:totp_setup'), {'otp': current_code(secret)})
        self.assertEqual(len(response.context['codes']), 10)
        user_pin = UserPin.objects.get(user=self.user)
        self.assertTrue(user_pin.has_2fa)
        self.assertNotIn(secret, user_pin.totp_secret)

    def test_totp_replay_and_backup_codes(self):
        secret = enable_2fa(self.user)
        code = current_code(secret)
        self.assertTrue(service.verify_second_factor(self.user, code))
        # the same code cannot be used twice
        self.assertEqual(service.verify_second_factor(self.user, code).status, service.VerifyStatus.WRONG_2FA)
        codes = service.new_backup_codes(self.user)
        self.assertTrue(service.verify_second_factor(self.user, codes[0].lower()))
        self.assertFalse(service.verify_second_factor(self.user, codes[0]))
        self.assertEqual(service.backup_codes_left(self.user), 9)

    def test_wrong_codes_lock_out(self):
        enable_2fa(self.user)
        settings = PinSettings.load()
        settings.max_attempts = 2
        settings.save()
        service.verify_second_factor(self.user, '000000')
        result = service.verify_second_factor(self.user, '000000')
        self.assertEqual(result.status, service.VerifyStatus.LOCKED_OUT)

    def test_disable_needs_pin_and_code(self):
        secret = enable_2fa(self.user)
        self.client.force_login(self.user)
        url = reverse('plugins:netbox_user_pin:totp_manage', kwargs={'action': 'disable'})
        self.client.post(url, {'pin': '000001', 'otp': current_code(secret)})
        self.assertTrue(service.has_2fa(self.user))
        self.client.post(url, {'pin': GOOD_PIN, 'otp': current_code(secret)})
        self.assertFalse(service.has_2fa(self.user))

    def test_require_2fa_on_unlock(self):
        settings = PinSettings.load()
        settings.require_2fa_unlock = True
        settings.save()
        secret = enable_2fa(self.user)
        request = RequestFactory().get('/')
        from django.contrib.sessions.backends.db import SessionStore
        request.user, request.session = self.user, SessionStore()
        self.assertFalse(service.unlock(request, GOOD_PIN, otp='000000'))
        self.assertTrue(service.unlock(request, GOOD_PIN, otp=current_code(secret)))


class RotationTest(PinTestCase):

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user('fero', password='pw')
        service.set_pin(self.user, GOOD_PIN)
        self.client.force_login(self.user)

    def test_default_rotation_180_days(self):
        self.assertEqual(PinSettings.load().max_age_days, 180)
        UserPin.objects.filter(user=self.user).update(changed=timezone.now() - timedelta(days=181))
        self.assertTrue(service.pin_expired(self.user))

    def test_test_rotation_button_forces_change(self):
        self.client.post(reverse('plugins:netbox_user_pin:test_rotation'))
        response = self.client.get(reverse('plugins:netbox_user_pin:test'))
        self.assertIn(reverse('plugins:netbox_user_pin:change_pin'), response.url)
        self.client.post(reverse('plugins:netbox_user_pin:change_pin'), {
            'current_pin': GOOD_PIN, 'new_pin': OTHER_PIN, 'confirm_pin': OTHER_PIN,
        })
        self.assertFalse(service.pin_expired(self.user))
        self.assertTrue(PinEvent.objects.filter(action=PinEventAction.FORCE_CHANGE).exists())

    @override_settings(EMAIL={'SERVER': 'localhost', 'FROM_EMAIL': 'netbox@firma.sk'})
    def test_expiry_warning_mail_once(self):
        allow_domains('firma.sk')
        self.user.email = 'fero@firma.sk'
        self.user.save()
        UserPin.objects.filter(user=self.user).update(changed=timezone.now() - timedelta(days=170))
        mail.outbox.clear()
        service.maybe_warn_expiry(self.user)
        service.maybe_warn_expiry(self.user)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn('expires soon', mail.outbox[0].subject)


@override_settings(EMAIL={'SERVER': 'localhost', 'FROM_EMAIL': 'netbox@firma.sk'})
class RecoveryTest(PinTestCase):

    def setUp(self):
        super().setUp()
        allow_domains('firma.sk', 'firma.com')
        self.user = User.objects.create_user('gabo', password='pw', email='gabo@firma.sk')
        service.set_pin(self.user, GOOD_PIN)
        self.secret = enable_2fa(self.user)
        self.client.force_login(self.user)
        mail.outbox.clear()

    def _email_code(self):
        return next(w for w in mail.outbox[-1].body.split() if w.isdigit() and len(w) == 8)

    def test_email_status(self):
        self.assertEqual(service.email_status(self.user), 'ok')
        self.user.email = 'gabo@gmail.com'
        self.assertEqual(service.email_status(self.user), 'domain')
        self.user.email = ''
        self.assertEqual(service.email_status(self.user), 'missing')

    def test_recovery_needs_email_code_and_2fa(self):
        url = reverse('plugins:netbox_user_pin:recover')
        self.client.post(url, {'action': 'send'})
        self.assertEqual(len(mail.outbox), 1)
        code = self._email_code()
        self.assertNotIn(code, UserPin.objects.get(user=self.user).recovery_code)
        # right e-mail code, wrong 2FA
        self.client.post(url, {'email_code': code, 'otp': '000000', 'new_pin': OTHER_PIN, 'confirm_pin': OTHER_PIN})
        self.assertTrue(service.verify_pin(self.user, GOOD_PIN))
        # wrong e-mail code, right 2FA
        self.client.post(url, {'email_code': '00000000', 'otp': current_code(self.secret), 'new_pin': OTHER_PIN,
                               'confirm_pin': OTHER_PIN})
        self.assertTrue(service.verify_pin(self.user, GOOD_PIN))
        # both right
        response = self.client.post(url, {'email_code': code, 'otp': current_code(self.secret, 1),
                                          'new_pin': OTHER_PIN, 'confirm_pin': OTHER_PIN})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(service.verify_pin(self.user, OTHER_PIN))
        self.assertTrue(PinEvent.objects.filter(action=PinEventAction.RECOVERY_OK).exists())
        self.assertIn('recovered', mail.outbox[-1].subject)

    def test_code_single_use_and_attempt_limit(self):
        service.start_recovery(self.user)
        for _ in range(5):
            with self.assertRaises(ValidationError):
                service.complete_recovery(self.user, '00000000', current_code(self.secret), OTHER_PIN)
        code = self._email_code()
        with self.assertRaises(ValidationError):
            service.complete_recovery(self.user, code, current_code(self.secret), OTHER_PIN)

    def test_blocked_without_allowed_domain_or_2fa(self):
        self.user.email = 'gabo@gmail.com'
        self.user.save()
        self.assertIn('email_domain', service.recovery_blockers(self.user))
        with self.assertRaises(ValidationError):
            service.start_recovery(self.user)
        self.assertEqual(len(mail.outbox), 0)
        service.reset_totp(self.user, actor=self.user)
        self.assertIn('no_2fa', service.recovery_blockers(self.user))

    def test_resend_throttled(self):
        service.start_recovery(self.user)
        with self.assertRaises(ValidationError):
            service.start_recovery(self.user)


class DelegationTest(PinTestCase):

    def setUp(self):
        super().setUp()
        self.master = User.objects.create_superuser('master', password='pw')
        self.delegate = User.objects.create_user('deleg', password='pw')
        self.other_delegate = User.objects.create_user('deleg2', password='pw')
        self.user = User.objects.create_user('plain', password='pw')

    def _add_delegates(self, can_edit_settings=False):
        from netbox_user_pin import delegation
        PinDelegate.objects.create(user=self.delegate, can_edit_settings=can_edit_settings, status='active')
        PinDelegate.objects.create(user=self.other_delegate, status='active')
        delegation.sync_permissions()
        for user in (self.delegate, self.other_delegate):
            for attr in ('_perm_cache', '_user_perm_cache', '_group_perm_cache', '_object_perm_cache'):
                if hasattr(user, attr):
                    delattr(user, attr)

    @override_settings(EMAIL={'SERVER': 'localhost', 'FROM_EMAIL': 'netbox@firma.sk'})
    def test_master_adds_delegate_via_view(self):
        import re
        allow_domains('firma.sk')
        User.objects.filter(pk=self.delegate.pk).update(email='deleg@firma.sk')
        admin_login(self.client, self.master)
        self.client.post(reverse('plugins:netbox_user_pin:delegates'), {'action': 'invite', 'user': self.delegate.pk,
                                                                         'hours': 24})
        role = PinDelegate.objects.get(user=self.delegate)
        self.assertEqual(role.status, 'pending')
        self.assertFalse(User.objects.get(pk=self.delegate.pk).has_perm('netbox_user_pin.change_userpin'))
        code = re.search(r'(\d{8})', mail.outbox[-1].body).group(1)
        service.set_pin(self.delegate, GOOD_PIN)
        secret = enable_2fa(self.delegate)
        from netbox_user_pin import roles
        roles.accept(role, self.delegate, code, GOOD_PIN, current_code(secret))
        delegate = User.objects.get(pk=self.delegate.pk)
        self.assertTrue(delegate.has_perm('netbox_user_pin.change_userpin'))
        self.assertTrue(delegate.has_perm('netbox_user_pin.view_pinevent'))
        self.assertTrue(delegate.has_perm('netbox_user_pin.view_pinsettings'))
        self.assertFalse(delegate.has_perm('netbox_user_pin.change_pinsettings'))
        self.assertFalse(delegate.has_perm('netbox_user_pin.add_pinsettings'))
        self.assertTrue(PinEvent.objects.filter(action=PinEventAction.ROLE_ACCEPTED).exists())

    def test_separation_of_duties(self):
        self._add_delegates()
        delegate = User.objects.get(pk=self.delegate.pk)
        self.assertTrue(service.can_manage(delegate, self.user))
        self.assertFalse(service.can_manage(delegate, self.master))
        self.assertFalse(service.can_manage(delegate, self.other_delegate))
        self.assertFalse(service.can_manage(delegate, delegate))
        self.assertTrue(service.can_manage(self.master, delegate))
        self.assertFalse(service.can_manage(self.master, self.master))
        self.assertFalse(service.can_manage(self.user, self.user))

    def test_delegate_views(self):
        self._add_delegates()
        delegate = User.objects.get(pk=self.delegate.pk)
        admin_login(self.client, delegate)
        self.assertEqual(self.client.get(reverse('plugins:netbox_user_pin:user_list')).status_code, 200)
        self.assertEqual(self.client.get(reverse('plugins:netbox_user_pin:event_list')).status_code, 200)
        response = self.client.get(reverse('plugins:netbox_user_pin:settings'))
        self.assertContains(response, 'Read-only view')
        self.assertEqual(self.client.post(reverse('plugins:netbox_user_pin:settings'), {}).status_code, 403)
        self.assertEqual(self.client.get(reverse('plugins:netbox_user_pin:delegates')).status_code, 403)
        # may manage a plain user, not the master
        url = reverse('plugins:netbox_user_pin:user_action', kwargs={'pk': self.user.pk, 'action': 'allow'})
        self.client.post(url)
        self.assertEqual(UserPin.objects.get(user=self.user).access, PinAccess.ALLOWED)
        url = reverse('plugins:netbox_user_pin:user_action', kwargs={'pk': self.master.pk, 'action': 'reset'})
        self.assertEqual(self.client.post(url).status_code, 403)

    def test_plain_user_sees_only_my_pin(self):
        self.client.force_login(self.user)
        for name in ('user_list', 'event_list', 'settings', 'delegates'):
            self.assertEqual(self.client.get(reverse(f'plugins:netbox_user_pin:{name}')).status_code, 403, name)
        self.assertEqual(self.client.get(reverse('plugins:netbox_user_pin:my_pin')).status_code, 200)


class AdminResetTest(PinTestCase):
    """An administrator alone can only suspend; resets are confirmed by the user in their own session."""

    def setUp(self):
        super().setUp()
        self.admin = User.objects.create_superuser('boss2', password='pw')
        self.user = User.objects.create_user('hana', password='pw')
        service.set_pin(self.user, GOOD_PIN)
        self.secret = enable_2fa(self.user)

    def _action(self, action):
        return self.client.post(
            reverse('plugins:netbox_user_pin:user_action', kwargs={'pk': self.user.pk, 'action': action})
        )

    def test_suspend_blocks_immediately(self):
        from django.contrib.sessions.backends.db import SessionStore
        request = RequestFactory().get('/')
        request.user, request.session = self.user, SessionStore()
        service.unlock(request, GOOD_PIN)
        self.assertTrue(service.is_unlocked(request))
        admin_login(self.client, self.admin)
        self._action('suspend')
        self.assertFalse(service.is_unlocked(request))
        self.assertEqual(service.verify_pin(self.user, GOOD_PIN).status, service.VerifyStatus.SUSPENDED)
        self._action('unsuspend')
        self.assertTrue(service.verify_pin(self.user, GOOD_PIN))

    def test_pin_reset_confirmed_by_user_with_2fa(self):
        admin_login(self.client, self.admin)
        # forgotten PIN usually means a lockout
        UserPin.objects.filter(user=self.user).update(locked_until=timezone.now() + timedelta(minutes=30))
        self._action('reset')
        user_pin = UserPin.objects.get(user=self.user)
        self.assertEqual(user_pin.reset_pending, 'pin')
        self.assertIsNone(user_pin.locked_until)
        self.assertTrue(service.verify_pin(self.user, GOOD_PIN))  # old PIN still valid until confirmed

        self.client.force_login(self.user)
        url = reverse('plugins:netbox_user_pin:reset_confirm')
        self.assertContains(self.client.get(url), 'boss2')
        self.client.post(url, {'otp': '000000', 'new_pin': OTHER_PIN, 'confirm_pin': OTHER_PIN})
        self.assertTrue(service.verify_pin(self.user, GOOD_PIN))
        response = self.client.post(url, {'otp': current_code(self.secret), 'new_pin': OTHER_PIN,
                                          'confirm_pin': OTHER_PIN})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(service.verify_pin(self.user, OTHER_PIN))
        self.assertEqual(UserPin.objects.get(user=self.user).reset_pending, '')
        event = PinEvent.objects.get(action=PinEventAction.RESET_COMPLETED)
        self.assertIn('boss2', event.detail)

    def test_2fa_reset_confirmed_by_user_with_pin(self):
        admin_login(self.client, self.admin)
        self._action('reset-2fa')
        self.client.force_login(self.user)
        url = reverse('plugins:netbox_user_pin:reset_confirm')
        self.client.post(url, {'pin': '000001'})
        self.assertTrue(service.has_2fa(self.user))
        response = self.client.post(url, {'pin': GOOD_PIN})
        self.assertIn(reverse('plugins:netbox_user_pin:totp_setup'), response.url)
        self.assertFalse(service.has_2fa(self.user))

    def test_reset_expires_and_cancel(self):
        service.request_reset(self.user, 'pin', actor=self.admin)
        UserPin.objects.filter(user=self.user).update(pending_reset_expires=timezone.now() - timedelta(seconds=1))
        with self.assertRaises(ValidationError):
            service.complete_pin_reset(self.user, current_code(self.secret), OTHER_PIN)
        service.request_reset(self.user, 'pin', actor=self.admin)
        service.cancel_reset(self.user, actor=self.admin)
        self.assertEqual(UserPin.objects.get(user=self.user).reset_pending, '')

    def test_reset_needs_user_2fa(self):
        plain = User.objects.create_user('no2fa', password='pw')
        service.set_pin(plain, GOOD_PIN)
        with self.assertRaises(ValidationError):
            service.request_reset(plain, 'pin', actor=self.admin)


@override_settings(EMAIL={'SERVER': 'localhost', 'FROM_EMAIL': 'netbox@firma.sk'})
class MailPageTest(PinTestCase):

    def setUp(self):
        super().setUp()
        allow_domains('firma.sk')
        self.admin = User.objects.create_superuser('mailadmin', password='pw', email='mailadmin@firma.sk')
        self.ok_user = User.objects.create_user('okuser', password='pw', email='ok@firma.sk')
        self.gmail = User.objects.create_user('gmail', password='pw', email='x@gmail.com')
        self.denied = User.objects.create_user('denied', password='pw', email='d@firma.sk')
        service.set_access(self.denied, PinAccess.DENIED, actor=self.admin)

    def test_test_mail_recipients_and_default(self):
        admin_login(self.client, self.admin)
        response = self.client.get(reverse('plugins:netbox_user_pin:mail'))
        recipients = set(response.context['test_form'].fields['recipient'].queryset.values_list('username', flat=True))
        self.assertEqual(recipients, {'mailadmin', 'okuser'})
        self.assertEqual(response.context['test_form'].initial['recipient'], self.admin.pk)
        mail.outbox.clear()
        self.client.post(reverse('plugins:netbox_user_pin:mail'), {'action': 'test-mail',
                                                                   'recipient': self.ok_user.pk})
        self.assertEqual(mail.outbox[-1].to, ['ok@firma.sk'])
        # not eligible recipient is rejected
        self.client.post(reverse('plugins:netbox_user_pin:mail'), {'action': 'test-mail', 'recipient': self.gmail.pk})
        self.assertEqual(len(mail.outbox), 1)



@override_settings(EMAIL={'SERVER': 'localhost', 'FROM_EMAIL': 'netbox@firma.sk'})
class BackupCodesViewTest(PinTestCase):

    def setUp(self):
        super().setUp()
        allow_domains('firma.sk')
        self.user = User.objects.create_user('ivan', password='pw', email='ivan@firma.sk')
        service.set_pin(self.user, GOOD_PIN)
        self.client.force_login(self.user)
        # enroll through the service so the codes are stored encrypted
        self.client.get(reverse('plugins:netbox_user_pin:totp_setup'))
        self.secret = self.client.session[service.ENROLL_SESSION_KEY]['secret']
        response = self.client.post(reverse('plugins:netbox_user_pin:totp_setup'), {'otp': current_code(self.secret)})
        self.codes = response.context['codes']
        mail.outbox.clear()

    def test_codes_stored_encrypted(self):
        stored = UserPin.objects.get(user=self.user).backup_codes_encrypted
        self.assertTrue(stored)
        for code in self.codes:
            self.assertNotIn(code, stored)

    def test_show_with_pin_and_email_code(self):
        url = reverse('plugins:netbox_user_pin:backup_codes')
        self.client.post(url, {'action': 'send-email'})
        email_code = next(w for w in mail.outbox[-1].body.split() if w.isdigit() and len(w) == 8)
        self.assertNotIn(self.codes[0], mail.outbox[-1].body)   # codes are never e-mailed
        service.verify_second_factor(self.user, self.codes[0])   # use one code
        response = self.client.post(url, {'action': 'show', 'pin': GOOD_PIN, 'email_code': email_code})
        shown = response.context['codes']
        self.assertEqual([c for c, _ in shown], self.codes)
        self.assertEqual([used for _, used in shown].count(True), 1)
        self.assertTrue(PinEvent.objects.filter(action=PinEventAction.BACKUP_CODES_VIEWED).exists())
        self.assertIn('viewed', mail.outbox[-1].subject)
        # the e-mail code is single use
        response = self.client.post(url, {'action': 'show', 'pin': GOOD_PIN, 'email_code': email_code})
        self.assertIsNone(response.context['codes'])

    def test_show_with_pin_and_2fa_and_wrong_pin(self):
        url = reverse('plugins:netbox_user_pin:backup_codes')
        response = self.client.post(url, {'action': 'show', 'pin': '000001', 'otp': current_code(self.secret)})
        self.assertIsNone(response.context['codes'])
        response = self.client.post(url, {'action': 'show', 'pin': GOOD_PIN, 'otp': current_code(self.secret, 1)})
        self.assertEqual(len(response.context['codes']), 10)
        # regenerate within the verified window
        response = self.client.post(url, {'action': 'regenerate'})
        self.assertTrue(response.context['renewed'])
        self.assertNotEqual([c for c, _ in response.context['codes']], self.codes)

    def test_legacy_user_gets_new_codes(self):
        UserPin.objects.filter(user=self.user).update(backup_codes_encrypted='')
        codes, renewed = service.show_backup_codes(self.user, GOOD_PIN, otp=current_code(self.secret, 1))
        self.assertTrue(renewed)
        self.assertEqual(len(codes), 10)


class FourEyesTest(PinTestCase):

    def setUp(self):
        super().setUp()
        self.peter = User.objects.create_superuser('peter', password='pw')
        self.martin = User.objects.create_superuser('martin', password='pw')
        self.plain = User.objects.create_user('plain2', password='pw')
        self.secrets = {}
        for user in (self.peter, self.martin):
            service.set_pin(user, GOOD_PIN)
            self.secrets[user.pk] = enable_2fa(user)
        settings = PinSettings.load()
        settings.four_eyes = True
        settings.save()

    def _vote(self, client, req, user, action='confirm', offset=0, reason=''):
        return client.post(reverse('plugins:netbox_user_pin:approval', kwargs={'pk': req.pk}), {
            'action': action, 'pin': GOOD_PIN, 'otp': current_code(self.secrets[user.pk], offset), 'reason': reason,
        })

    def test_enable_needs_two_approvers(self):
        from netbox_user_pin.forms import PinSettingsForm
        settings = PinSettings.load()
        settings.four_eyes = False
        settings.save()
        UserPin.objects.filter(user=self.martin).update(totp_secret='')
        form = PinSettingsForm({**{f: getattr(settings, f) for f in PinSettingsForm.Meta.fields}, 'four_eyes': True},
                               instance=settings)
        self.assertFalse(form.is_valid())
        self.assertIn('four_eyes', form.errors)

    @override_settings(EMAIL={'SERVER': 'localhost', 'FROM_EMAIL': 'netbox@firma.sk'})
    def test_live_flow_add_delegate(self):
        from django.test import Client
        allow_domains('firma.sk')
        User.objects.filter(pk=self.plain.pk).update(email='plain2@firma.sk')
        peter_client, martin_client = Client(), Client()
        admin_login(peter_client, self.peter, secret=self.secrets[self.peter.pk])
        response = peter_client.post(reverse('plugins:netbox_user_pin:delegates'),
                                     {'action': 'invite', 'user': self.plain.pk, 'hours': 24})
        req = ApprovalRequest.objects.get()
        self.assertRedirects(response, req.get_absolute_url(), fetch_redirect_response=False)
        self.assertFalse(PinDelegate.objects.exists())

        self._vote(peter_client, req, self.peter, offset=1, reason='new colleague')
        req.refresh_from_db()
        self.assertEqual(req.status, ApprovalStatus.PENDING)
        self.assertEqual(req.reason, 'new colleague')
        # peter cannot confirm twice
        self.assertFalse(approvals.can_vote(req, self.peter))

        # martin sees it live (status partial) and confirms in his own session
        martin_client.force_login(self.martin)
        martin_client.post(reverse('plugins:netbox_user_pin:unlock'), {'pin': GOOD_PIN, 'scope': 'user-pin-admin'})
        status_url = reverse('plugins:netbox_user_pin:approval_status', kwargs={'pk': req.pk}) + '?open=1'
        self.assertContains(martin_client.get(status_url), 'confirmed')
        self._vote(martin_client, req, self.martin)
        req.refresh_from_db()
        self.assertEqual(req.status, ApprovalStatus.EXECUTED)
        # executed = the invitation was sent; the role starts when plain2 accepts it
        self.assertEqual(PinDelegate.objects.get(user=self.plain).status, 'pending')
        self.assertEqual(martin_client.get(status_url)['HX-Refresh'], 'true')
        self.assertTrue(PinEvent.objects.filter(action=PinEventAction.APPROVAL_EXECUTED).exists())

    def test_notification_for_second_person(self):
        from extras.models import Notification
        req = approvals.create('delegate_add', {'user_id': self.plain.pk, 'group_id': None, 'can_edit': False},
                               'Add delegate plain2', self.peter)
        self.assertTrue(Notification.objects.filter(user=self.martin, object_id=req.pk).exists())
        self.assertFalse(Notification.objects.filter(user=self.peter, object_id=req.pk).exists())

    def test_reject_and_wrong_codes(self):
        req = approvals.create('access', {'user_id': self.plain.pk, 'access': 'allowed'}, 'Allow plain2', self.peter)
        with self.assertRaises(ValidationError):
            approvals.vote(req, self.martin, True, '000001', current_code(self.secrets[self.martin.pk]))
        approvals.vote(req, self.martin, False, GOOD_PIN, current_code(self.secrets[self.martin.pk], 1))
        req.refresh_from_db()
        self.assertEqual(req.status, ApprovalStatus.REJECTED)
        self.assertFalse(service.is_allowed(self.plain) and UserPin.objects.filter(
            user=self.plain, access='allowed').exists())

    def test_settings_change_needs_approval(self):
        admin_login(self.client, self.peter, secret=self.secrets[self.peter.pk])
        data = {f: getattr(PinSettings.load(), f) for f in (
            'language', 'access_mode', 'pin_length', 'blocked_pins', 'max_age_days', 'warn_days', 'unlock_minutes', 'scope_mode',
            'max_attempts', 'lockout_minutes', 'step_up_minutes', 'reset_valid_hours', 'approval_valid_minutes')}
        data.update({'pin_length': 8, 'block_weak_pins': 'on', 'sliding_unlock': 'on', 'require_2fa_admin': 'on',
                     'four_eyes': 'on', 'four_eyes_delegates': 'on', 'four_eyes_settings': 'on'})
        self.client.post(reverse('plugins:netbox_user_pin:settings'), data)
        self.assertEqual(PinSettings.load().pin_length, 6)
        req = ApprovalRequest.objects.get()
        approvals.vote(req, self.peter, True, GOOD_PIN, current_code(self.secrets[self.peter.pk], 1))
        approvals.vote(req, self.martin, True, GOOD_PIN, current_code(self.secrets[self.martin.pk]))
        self.assertEqual(PinSettings.load().pin_length, 8)

    def test_expired_request(self):
        req = approvals.create('access', {'user_id': self.plain.pk, 'access': 'allowed'}, 'Allow plain2', self.peter)
        ApprovalRequest.objects.filter(pk=req.pk).update(expires=timezone.now() - timedelta(seconds=1))
        req.refresh_from_db()
        with self.assertRaises(ValidationError):
            approvals.vote(req, self.martin, True, GOOD_PIN, current_code(self.secrets[self.martin.pk]))
        self.assertEqual(req.status, ApprovalStatus.EXPIRED)

    @override_settings(EMAIL={'SERVER': 'localhost', 'FROM_EMAIL': 'netbox@firma.sk'})
    def test_break_glass(self):
        req = approvals.create('access', {'user_id': self.plain.pk, 'access': 'allowed'}, 'Allow plain2', self.peter)
        with self.assertRaises(ValidationError):   # off by default
            approvals.break_glass(req, self.peter, 'urgent', GOOD_PIN, current_code(self.secrets[self.peter.pk]))
        settings = PinSettings.load()
        settings.break_glass = True
        settings.save()
        with self.assertRaises(ValidationError):   # reason required
            approvals.break_glass(req, self.peter, '', GOOD_PIN, current_code(self.secrets[self.peter.pk]))
        approvals.break_glass(req, self.peter, 'server down', GOOD_PIN, current_code(self.secrets[self.peter.pk], 1))
        req.refresh_from_db()
        self.assertEqual(req.status, ApprovalStatus.EXECUTED)
        self.assertTrue(req.break_glass)
        self.assertTrue(PinEvent.objects.filter(action=PinEventAction.BREAK_GLASS).exists())


class CliCommandTest(PinTestCase):

    def test_command_shown(self):
        user = User.objects.create_user("o'hara", password='pw')
        service.set_pin(user, GOOD_PIN)
        enable_2fa(user)
        command = service.cli_reset_2fa_command(user)
        self.assertIn('userpin_reset_2fa', command)
        self.assertTrue(command.startswith("sudo bash -c '"))
        self.client.force_login(user)
        self.assertContains(self.client.get(reverse('plugins:netbox_user_pin:my_pin')), 'userpin_reset_2fa')



@override_settings(EMAIL={})
class SmtpAndDomainTest(PinTestCase):

    def setUp(self):
        super().setUp()
        self.admin = User.objects.create_superuser('smtpadmin', password='pw', email='smtpadmin@firma.sk')
        self.secret = admin_login(self.client, self.admin)

    def _save_mail(self, **extra):
        data = {'action': 'save', 'mail_from_name': 'NetBox', 'mail_from_address': 'netbox@firma.sk',
                'smtp_server': 'mail.firma.sk', 'smtp_port': 587, 'smtp_timeout': 10, 'smtp_security': 'starttls',
                'smtp_username': 'svc_netbox', 'new_smtp_password': 'S3cret!', 'recovery_minutes': 15,
                'smtp_auth': 'on', 'notify_email': 'on', 'self_recovery': 'on'}
        data.update(extra)
        return self.client.post(reverse('plugins:netbox_user_pin:mail'), data)

    def test_smtp_settings_saved_with_encrypted_password(self):
        from netbox_user_pin import mail as pin_mail
        self._save_mail()
        settings = PinSettings.load()
        self.assertEqual(settings.smtp_server, 'mail.firma.sk')
        self.assertNotIn('S3cret!', settings.smtp_password)
        self.assertEqual(pin_mail.decrypt_password(settings.smtp_password), 'S3cret!')
        event = PinEvent.objects.filter(action=PinEventAction.SETTINGS_CHANGED).latest('pk')
        self.assertNotIn('S3cret!', event.detail)
        # leaving the password empty keeps it
        self._save_mail(new_smtp_password='', smtp_port=25)
        settings = PinSettings.load()
        self.assertEqual(settings.smtp_port, 25)
        self.assertEqual(pin_mail.decrypt_password(settings.smtp_password), 'S3cret!')

    def test_sending_through_own_smtp(self):
        from unittest import mock
        self._save_mail()
        allow_domains('firma.sk')
        with mock.patch('smtplib.SMTP') as smtp:
            connection = smtp.return_value
            connection.has_extn.return_value = True
            self.assertTrue(service.send_user_mail(self.admin, 'Hello', 'Body'))
        smtp.assert_called_once_with('mail.firma.sk', 587, timeout=10)
        connection.starttls.assert_called_once()
        connection.login.assert_called_once_with('svc_netbox', 'S3cret!')
        message = connection.send_message.call_args[0][0]
        self.assertEqual(message['To'], 'smtpadmin@firma.sk')
        self.assertIn('NetBox <netbox@firma.sk>', message['From'])

    def test_domain_must_be_verified(self):
        from unittest import mock
        from netbox_user_pin.models import AllowedDomain
        self._save_mail()
        self.client.post(reverse('plugins:netbox_user_pin:mail'), {'action': 'add-domain', 'domain': '@Firma.SK'})
        domain = AllowedDomain.objects.get(domain='firma.sk')
        self.assertFalse(domain.is_verified)
        self.assertEqual(service.email_status(self.admin), 'domain')   # not verified yet
        # the address must be in the domain
        self.client.post(reverse('plugins:netbox_user_pin:mail'), {'action': 'send-domain-code', 'pk': domain.pk,
                                                                   'address': 'x@gmail.com'})
        domain.refresh_from_db()
        self.assertFalse(domain.code)
        with mock.patch('smtplib.SMTP') as smtp:
            self.client.post(reverse('plugins:netbox_user_pin:mail'), {
                'action': 'send-domain-code', 'pk': domain.pk, 'address': 'peter@firma.sk'})
        body = smtp.return_value.send_message.call_args[0][0].get_content()
        code = next(w.strip('.') for w in body.split() if w.strip('.').isdigit() and len(w.strip('.')) == 8)
        self.client.post(reverse('plugins:netbox_user_pin:mail'), {'action': 'verify-domain', 'pk': domain.pk,
                                                                   'code': '00000000'})
        self.assertFalse(AllowedDomain.objects.get(pk=domain.pk).is_verified)
        self.client.post(reverse('plugins:netbox_user_pin:mail'), {'action': 'verify-domain', 'pk': domain.pk,
                                                                   'code': code})
        domain.refresh_from_db()
        self.assertTrue(domain.is_verified)
        self.assertEqual(domain.verified_email, 'peter@firma.sk')
        self.assertEqual(service.email_status(self.admin), 'ok')

    def test_test_connection_reports_errors(self):
        from unittest import mock
        self._save_mail()
        with mock.patch('smtplib.SMTP', side_effect=OSError('connection refused')):
            response = self.client.post(reverse('plugins:netbox_user_pin:mail'), {'action': 'test-connection'},
                                        follow=True)
        self.assertContains(response, 'connection refused')


class StepUpPopupAndLanguageTest(PinTestCase):

    def setUp(self):
        super().setUp()
        self.admin = User.objects.create_superuser('popup', password='pw')
        service.set_pin(self.admin, GOOD_PIN)
        self.secret = enable_2fa(self.admin)
        self.client.force_login(self.admin)
        self.client.post(reverse('plugins:netbox_user_pin:unlock'), {'pin': GOOD_PIN, 'scope': 'user-pin-admin'})

    def test_ajax_step_up(self):
        url = reverse('plugins:netbox_user_pin:step_up')
        response = self.client.post(url, {'pin': '000001', 'otp': current_code(self.secret)},
                                    HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        self.assertFalse(response.json()['ok'])
        self.assertTrue(response.json()['errors'])
        response = self.client.post(url, {'pin': GOOD_PIN, 'otp': current_code(self.secret, 1)},
                                    HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        self.assertTrue(response.json()['ok'])
        # after the pop-up the held form is submitted and goes through
        self.client.post(reverse('plugins:netbox_user_pin:mail'), {'action': 'add-domain', 'domain': '@Firma.sk'})
        from netbox_user_pin.models import AllowedDomain
        self.assertTrue(AllowedDomain.objects.filter(domain='firma.sk').exists())

    def test_tests_need_no_step_up(self):
        response = self.client.post(reverse('plugins:netbox_user_pin:mail'), {'action': 'test-connection'})
        self.assertEqual(response.url, reverse('plugins:netbox_user_pin:mail'))
        response = self.client.post(reverse('plugins:netbox_user_pin:mail'), {'action': 'add-domain',
                                                                               'domain': 'x.sk'})
        self.assertIn(reverse('plugins:netbox_user_pin:step_up'), response.url)

    def test_slovak_language(self):
        settings = PinSettings.load()
        settings.language = 'sk'
        settings.save()
        response = self.client.get(reverse('plugins:netbox_user_pin:my_pin'))
        self.assertContains(response, 'Môj PIN')
        self.assertContains(response, 'Dvojfaktorové overenie a obnova')
        response = self.client.post(reverse('plugins:netbox_user_pin:unlock'), {'pin': '000001'})
        self.assertContains(response, 'Nesprávny PIN')
        # the rest of NetBox keeps its language
        from django.utils.translation import get_language
        self.assertNotEqual(get_language(), 'sk')


class SettingsPinOnlyAndDomainPopupTest(PinTestCase):

    def setUp(self):
        super().setUp()
        self.admin = User.objects.create_superuser('dom', password='pw', email='dom@firma.sk')
        service.set_pin(self.admin, GOOD_PIN)
        self.secret = enable_2fa(self.admin)
        self.client.force_login(self.admin)
        self.client.post(reverse('plugins:netbox_user_pin:unlock'), {'pin': GOOD_PIN, 'scope': 'user-pin-admin'})
        self.ajax = {'HTTP_X_REQUESTED_WITH': 'XMLHttpRequest'}

    def test_pin_only_for_settings_but_2fa_for_users(self):
        # without confirmation an AJAX call asks for the pop-up
        response = self.client.post(reverse('plugins:netbox_user_pin:mail'), {'action': 'add-domain',
                                                                               'domain': 'a.sk'}, **self.ajax)
        self.assertEqual(response.status_code, 403)
        self.assertTrue(response.json()['step_up'])
        response = self.client.post(reverse('plugins:netbox_user_pin:step_up'),
                                    {'pin': GOOD_PIN, 'level': 'settings'}, **self.ajax)
        self.assertTrue(response.json()['ok'])
        response = self.client.post(reverse('plugins:netbox_user_pin:mail'), {'action': 'add-domain',
                                                                               'domain': '@firma.sk'})
        from netbox_user_pin.models import AllowedDomain
        domain = AllowedDomain.objects.get(domain='firma.sk')
        self.assertIn(f'verify={domain.pk}', response.url)
        # actions on other users still need PIN + 2FA
        other = User.objects.create_user('other', password='pw')
        url = reverse('plugins:netbox_user_pin:user_action', kwargs={'pk': other.pk, 'action': 'allow'})
        self.assertIn(reverse('plugins:netbox_user_pin:step_up'), self.client.post(url).url)
        # and when 'Require 2FA also for settings' is on, the PIN-only window is not enough
        settings = PinSettings.load()
        settings.require_2fa_settings = True
        settings.save()
        self.assertFalse(service.has_step_up(self.client.request().wsgi_request, 'settings'))

    def test_domain_popup_flow(self):
        from unittest import mock
        from netbox_user_pin.models import AllowedDomain
        from netbox_user_pin import mail as pin_mail
        settings = PinSettings.load()
        settings.smtp_server, settings.mail_from_address = 'mail.firma.sk', 'nb@firma.sk'
        settings.save()
        domain = AllowedDomain.objects.create(domain='firma.sk')
        self.client.post(reverse('plugins:netbox_user_pin:step_up'), {'pin': GOOD_PIN, 'level': 'settings'},
                         **self.ajax)
        url = reverse('plugins:netbox_user_pin:mail')
        response = self.client.post(url, {'action': 'send-domain-code', 'pk': domain.pk, 'address': 'x@other.sk'},
                                    **self.ajax)
        self.assertFalse(response.json()['ok'])
        with mock.patch('smtplib.SMTP') as smtp:
            response = self.client.post(url, {'action': 'send-domain-code', 'pk': domain.pk,
                                              'address': 'dom@firma.sk'}, **self.ajax)
        self.assertTrue(response.json()['ok'])
        body = smtp.return_value.send_message.call_args[0][0].get_content()
        code = next(w.strip('.') for w in body.split() if w.strip('.').isdigit() and len(w.strip('.')) == 8)
        response = self.client.post(url, {'action': 'verify-domain', 'pk': domain.pk, 'code': '1'}, **self.ajax)
        self.assertFalse(response.json()['ok'])
        response = self.client.post(url, {'action': 'verify-domain', 'pk': domain.pk, 'code': code}, **self.ajax)
        self.assertTrue(response.json()['ok'])
        self.assertTrue(AllowedDomain.objects.get(pk=domain.pk).is_verified)
        self.assertIsNotNone(pin_mail)

    def test_exact_domain_match(self):
        allow_domains('firma.sk')
        for email, expected in (('a@firma.sk', 'ok'), ('a@FIRMA.SK', 'ok'), ('a@mail.firma.sk', 'domain'),
                                ('a@xfirma.sk', 'domain'), ('a@firma.sk.evil.com', 'domain')):
            self.admin.email = email
            self.assertEqual(service.email_status(self.admin), expected, email)


class FullNamesAndReverifyTest(PinTestCase):

    def setUp(self):
        super().setUp()
        self.admin = User.objects.create_superuser('boss9', password='pw', email='boss9@firma.sk',
                                                   first_name='Peter', last_name='Knotek')
        self.jana = User.objects.create_user('jana', password='pw', email='jana@firma.sk',
                                             first_name='Jana', last_name='Malá')
        allow_domains('firma.sk')
        admin_login(self.client, self.admin)

    def test_names_on_users_delegates_and_test_mail(self):
        response = self.client.get(reverse('plugins:netbox_user_pin:user_list') + '?q=mal')
        self.assertContains(response, 'Jana Malá')
        from netbox_user_pin import delegation
        PinDelegate.objects.create(user=self.jana, status='active')
        delegation.sync_permissions()
        self.assertContains(self.client.get(reverse('plugins:netbox_user_pin:delegates')), 'Jana Malá')
        service.set_access(self.jana, PinAccess.ALLOWED, actor=self.admin)
        response = self.client.get(reverse('plugins:netbox_user_pin:mail'))
        self.assertContains(response, 'boss9 (Peter Knotek) – boss9@firma.sk')
        self.assertContains(response, 'jana (Jana Malá) – jana@firma.sk')
        settings = PinSettings.load()
        settings.show_full_names = False
        settings.save()
        self.assertNotContains(self.client.get(reverse('plugins:netbox_user_pin:user_list')), 'Jana Malá')

    def test_verified_domain_can_be_verified_again(self):
        from netbox_user_pin.models import AllowedDomain
        response = self.client.get(reverse('plugins:netbox_user_pin:mail'))
        self.assertContains(response, 'Verify again')
        self.assertTrue(AllowedDomain.objects.get(domain='firma.sk').is_verified)


@override_settings(EMAIL={'SERVER': 'localhost', 'FROM_EMAIL': 'netbox@firma.sk'})
class RolesTest(PinTestCase):
    """CORE deputies, departments, invitations, resignations, hand-overs and moves."""

    def setUp(self):
        super().setUp()
        allow_domains('firma.sk')
        self.secrets = {}
        self.boss = self.person('boss', superuser=True)

    def person(self, name, superuser=False, ready=True):
        create = User.objects.create_superuser if superuser else User.objects.create_user
        user = create(name, password='pw', email=f'{name}@firma.sk', first_name=name.title(), last_name='Test')
        if ready:
            service.set_pin(user, GOOD_PIN)
            self.secrets[user.pk] = enable_2fa(user)
        return user

    def otp(self, user):
        UserPin.objects.filter(user=user).update(totp_last_step=0)
        return current_code(self.secrets[user.pk])

    def code_for(self, user):
        import re
        for message in reversed(mail.outbox):
            if user.email in message.to and 'Code:' in message.body:
                return re.search(r'Code: (\d{8})', message.body).group(1)
        self.fail(f'no invitation for {user}')

    def accept(self, role, user=None):
        from netbox_user_pin import roles
        user = user or role.user
        return roles.accept(role, user, self.code_for(user), GOOD_PIN, self.otp(user))

    def make_core(self, *names):
        from netbox_user_pin import roles
        result = []
        for name in names:
            user = self.person(name)
            self.accept(roles.invite(user, 'core', self.boss))
            result.append(user)
        return result

    def make_department(self, name='IT', head='head', delegates=('del1', 'del2'), members=('m1',)):
        from netbox_user_pin import roles
        department = roles.create_department(name, self.boss)
        head_user = self.person(f'{head}')
        self.accept(roles.invite(head_user, 'head', self.boss, department=department))
        delegate_users = []
        for name_ in delegates:
            user = self.person(name_)
            self.accept(roles.invite(user, 'delegate', head_user, department=department))
            delegate_users.append(user)
        member_users = []
        for name_ in members:
            user = self.person(name_, ready=False)
            roles.add_member(user, department, self.boss)
            member_users.append(user)
        return department, head_user, delegate_users, member_users

    def fresh(self, user):
        return User.objects.get(pk=user.pk)

    def test_invitation_flow(self):
        from netbox_user_pin import roles
        jozef = self.person('jozef', ready=False)
        role = roles.invite(jozef, 'core', self.boss, hours=12)
        self.assertEqual(role.status, 'pending')
        body = mail.outbox[-1].body
        self.assertIn('CORE', mail.outbox[-1].subject)
        self.assertIn('Your responsibility', body)
        self.assertIn('other plugins', body)
        self.assertIn(reverse('plugins:netbox_user_pin:invitation', kwargs={'pk': role.pk}), body)
        # invited users may set a PIN even in "allowed only" mode
        settings = PinSettings.load()
        settings.access_mode = PinAccessMode.ALLOWED_ONLY
        settings.save()
        self.assertTrue(service.is_allowed(jozef))
        self.client.force_login(jozef)
        response = self.client.get(reverse('plugins:netbox_user_pin:invitation', kwargs={'pk': role.pk}))
        self.assertContains(response, 'Set your PIN')
        service.set_pin(jozef, GOOD_PIN)
        self.secrets[jozef.pk] = enable_2fa(jozef)
        with self.assertRaises(ValidationError):
            roles.accept(role, jozef, '00000000', GOOD_PIN, self.otp(jozef))
        url = reverse('plugins:netbox_user_pin:invitation', kwargs={'pk': role.pk})
        response = self.client.post(url, {'code': self.code_for(jozef), 'pin': GOOD_PIN, 'otp': self.otp(jozef),
                                          'understand': 'on'})
        self.assertRedirects(response, reverse('plugins:netbox_user_pin:my_roles'), fetch_redirect_response=False)
        role.refresh_from_db()
        self.assertEqual(role.status, 'active')
        self.assertTrue(roles.is_core(jozef))
        self.assertTrue(self.fresh(jozef).has_perm('netbox_user_pin.change_userpin'))

    def test_invitation_needs_email_and_expires(self):
        from netbox_user_pin import roles
        nomail = self.person('nomail')
        User.objects.filter(pk=nomail.pk).update(email='nomail@gmail.com')
        with self.assertRaises(ValidationError):
            roles.invite(self.fresh(nomail), 'core', self.boss)
        with self.assertRaises(ValidationError):
            roles.invite(self.person('x1'), 'core', self.boss, hours=5)
        role = roles.invite(self.person('late'), 'core', self.boss)
        PinDelegate.objects.filter(pk=role.pk).update(invite_expires=timezone.now() - timedelta(minutes=1))
        roles.process_due()
        role.refresh_from_db()
        self.assertEqual(role.status, 'expired')
        self.assertIn('did not accept', mail.outbox[-1].body)
        roles.resend(role, self.boss, hours=48)
        role.refresh_from_db()
        self.assertEqual(role.status, 'pending')
        self.accept(role)

    def test_four_eyes_rules(self):
        from netbox_user_pin import roles
        from netbox_user_pin.forms import PinSettingsForm
        settings = PinSettings.load()
        fields = {f: getattr(settings, f) for f in PinSettingsForm.Meta.fields}
        self.assertFalse(PinSettingsForm({**fields, 'four_eyes': True}, instance=settings).is_valid())
        anna, jan = self.make_core('anna', 'jan')
        self.assertTrue(PinSettingsForm({**fields, 'four_eyes': True}, instance=settings).is_valid())
        settings.four_eyes = True
        settings.save()
        department = roles.create_department('Sales', self.boss)
        form = PinSettingsForm({**fields, 'four_eyes': False}, instance=PinSettings.load())
        self.assertFalse(form.is_valid())
        self.assertIn('department', str(form.errors['four_eyes']))
        roles.delete_department(department, self.boss)
        # switching off needs two people and ends the CORE delegation
        admin_login(self.client, self.boss, secret=self.secrets[self.boss.pk])
        data = {**{f: v for f, v in fields.items() if not isinstance(v, bool)}, 'block_weak_pins': 'on',
                'sliding_unlock': 'on', 'require_2fa_admin': 'on', 'four_eyes_delegates': 'on',
                'four_eyes_settings': 'on', 'show_full_names': 'on'}
        self.client.post(reverse('plugins:netbox_user_pin:settings'), data)
        self.assertTrue(PinSettings.load().four_eyes)
        req = ApprovalRequest.objects.get()
        approvals.vote(req, self.boss, True, GOOD_PIN, self.otp(self.boss))
        approvals.vote(req, anna, True, GOOD_PIN, self.otp(anna))
        self.assertFalse(PinSettings.load().four_eyes)
        self.assertFalse(roles.is_core(anna))
        self.assertTrue(any('switched off' in m.subject and jan.email in m.to for m in mail.outbox))

    def test_core_minimum_and_resignation(self):
        from netbox_user_pin import roles
        anna, jan = self.make_core('anna', 'jan')
        settings = PinSettings.load()
        settings.four_eyes = True
        settings.save()
        role = PinDelegate.objects.get(user=anna)
        self.assertEqual(roles.resign(role, anna, 'leaving', GOOD_PIN, self.otp(anna)), 'resigning')
        self.assertTrue(roles.is_core(anna))   # stays until a replacement accepts
        with self.assertRaises(ValidationError):
            roles.remove_role(PinDelegate.objects.get(user=jan), self.boss)
        eva = self.person('eva')
        self.accept(roles.invite(eva, 'core', self.boss))
        self.assertFalse(roles.is_core(anna))
        self.assertEqual(PinDelegate.objects.get(user=anna).status, 'ended')
        # replacement: the old one stays until the new one accepts
        new = roles.remove_role(PinDelegate.objects.get(user=jan), self.boss, replacement=self.person('fero'))
        self.assertTrue(roles.is_core(jan))
        self.accept(new)
        self.assertFalse(roles.is_core(jan))

    def test_department_scope(self):
        from netbox_user_pin import roles
        department, head, (del1, del2), (m1,) = self.make_department()
        other, head2, _d, (m2,) = self.make_department('HR', 'head2', ('d3', 'd4'), ('m2',))
        self.assertTrue(roles.can_manage(head, m1))
        self.assertTrue(roles.can_manage(head, del1))
        self.assertFalse(roles.can_manage(head, m2))
        self.assertTrue(roles.can_manage(del1, m1))
        self.assertFalse(roles.can_manage(del1, del2))
        self.assertFalse(roles.can_manage(del1, head))
        self.assertFalse(roles.can_manage(head, self.boss))
        self.assertEqual(set(roles.visible_users(head)), {head, del1, del2, m1})
        # the head sees the users list only after PIN + 2FA and only the own department
        self.client.force_login(head)
        self.client.post(reverse('plugins:netbox_user_pin:unlock'), {'pin': GOOD_PIN, 'scope': 'user-pin-admin'})
        response = self.client.get(reverse('plugins:netbox_user_pin:user_list'))
        self.assertIn(reverse('plugins:netbox_user_pin:step_up'), response.url)
        self.client.post(reverse('plugins:netbox_user_pin:step_up'), {'pin': GOOD_PIN, 'otp': self.otp(head)})
        response = self.client.get(reverse('plugins:netbox_user_pin:user_list'))
        self.assertContains(response, 'm1')
        self.assertNotContains(response, 'm2')
        self.assertEqual(self.client.get(reverse('plugins:netbox_user_pin:department',
                                                 kwargs={'pk': other.pk})).status_code, 403)
        self.assertContains(self.client.get(reverse('plugins:netbox_user_pin:department',
                                                    kwargs={'pk': department.pk})), 'Temporary hand-over')
        self.assertEqual(self.client.get(reverse('plugins:netbox_user_pin:delegates')).status_code, 403)
        # the head may allow PIN use of a member
        url = reverse('plugins:netbox_user_pin:user_action', kwargs={'pk': m1.pk, 'action': 'allow'})
        self.client.post(url)
        self.assertEqual(UserPin.objects.get(user=m1).access, PinAccess.ALLOWED)
        url = reverse('plugins:netbox_user_pin:user_action', kwargs={'pk': m2.pk, 'action': 'allow'})
        self.assertEqual(self.client.post(url).status_code, 403)

    def test_delegate_minimum(self):
        from netbox_user_pin import roles
        department, head, (del1, del2), (m1,) = self.make_department()
        role = PinDelegate.objects.get(user=del1, department=department)
        self.assertEqual(roles.resign(role, del1, 'too busy', GOOD_PIN, self.otp(del1)), 'resigning')
        self.assertTrue(any('too busy' in m.body and head.email in m.to for m in mail.outbox))
        with self.assertRaises(ValidationError):   # cannot leave the department without a replacement
            roles.remove_member(del2, self.boss)
        service.set_pin(m1, GOOD_PIN)
        self.secrets[m1.pk] = enable_2fa(m1)
        self.accept(roles.invite(m1, 'delegate', head, department=department))
        role.refresh_from_db()
        self.assertEqual(role.status, 'ended')
        self.assertEqual(roles.department_delegates(department).count(), 2)

    def test_temporary_hand_over(self):
        from netbox_user_pin import roles
        department, head, (del1, del2), (m1,) = self.make_department()
        until = timezone.now() + timedelta(days=7)
        temp = roles.hand_over(department, del1, until, head, reason='holiday')
        self.assertIn('temporary', mail.outbox[-1].body)
        self.accept(temp)
        self.assertEqual(roles.effective_head(department).user, del1)
        self.assertEqual(PinDelegate.objects.get(user=head, department=department).status, 'on_leave')
        self.assertFalse(roles.can_manage(head, m1))
        self.assertTrue(roles.can_manage(del1, m1))
        notice = [m for m in mail.outbox if m1.email in m.to and 'New head' in m.subject]
        self.assertTrue(notice and 'rights end' in notice[-1].body)
        # the job reminds a day before and returns the rights after the date
        PinDelegate.objects.filter(pk=temp.pk).update(temporary_until=timezone.now() + timedelta(hours=5))
        roles.process_due()
        self.assertTrue(any('ends tomorrow' in m.subject.lower() or 'tomorrow' in m.subject for m in mail.outbox))
        PinDelegate.objects.filter(pk=temp.pk).update(temporary_until=timezone.now() - timedelta(minutes=1))
        roles.process_due()
        self.assertEqual(roles.effective_head(department).user, head)
        self.assertTrue(any(m1.email in m.to and 'Rights returned' in m.subject for m in mail.outbox))
        self.assertTrue(PinEvent.objects.filter(action=PinEventAction.ROLE_RETURNED).exists())

    def test_two_delegates_hand_over_without_head(self):
        from netbox_user_pin import roles
        department, head, (del1, del2), (m1,) = self.make_department()
        until = timezone.now() + timedelta(days=5)
        UserPin.objects.filter(user=del1).update(totp_last_step=0)
        admin_login(self.client, del1, secret=self.secrets[del1.pk])
        response = self.client.post(reverse('plugins:netbox_user_pin:department', kwargs={'pk': department.pk}), {
            'action': 'hand-over', 'user': del2.pk, 'until': timezone.localtime(until).strftime('%Y-%m-%dT%H:%M'),
            'hours': 24, 'reason': 'head is ill'})
        req = ApprovalRequest.objects.get()
        self.assertRedirects(response, req.get_absolute_url(), fetch_redirect_response=False)
        self.assertEqual(req.department, department)
        self.assertIn(del2, approvals.eligible_approvers(department=department))
        approvals.vote(req, del1, True, GOOD_PIN, self.otp(del1))
        approvals.vote(req, del2, True, GOOD_PIN, self.otp(del2))
        req.refresh_from_db()
        self.assertEqual(req.status, ApprovalStatus.EXECUTED, req.result)
        temp = PinDelegate.objects.get(user=del2, role='head')
        self.accept(temp)
        self.assertEqual(roles.effective_head(department).user, del2)
        # at most 30 days for two delegates
        with self.assertRaises(ValidationError):
            roles.hand_over(department, m1, timezone.now() + timedelta(days=40), del1)

    def test_move_between_departments(self):
        from netbox_user_pin import roles
        it, head, _dels, (m1,) = self.make_department()
        hr, head2, _dels2, _members = self.make_department('HR', 'head2', ('d3', 'd4'), ())
        transfer = roles.request_transfer(m1, hr, head)
        self.assertEqual(transfer.approving_department, hr)
        self.assertFalse(roles.can_decide_transfer(transfer, head))
        self.assertTrue(roles.can_decide_transfer(transfer, head2))
        with self.assertRaises(ValidationError):
            roles.decide_transfer(transfer, head, True)
        roles.decide_transfer(transfer, head2, True)
        self.assertEqual(roles.department_of(m1), hr)
        self.assertTrue(any(m1.email in m.to and 'Department change' in m.subject for m in mail.outbox))
        # a head cannot be moved away without a new head
        with self.assertRaises(ValidationError):
            roles.move_member(head, hr, self.boss)

    def test_pages_and_slovak(self):
        department, head, _dels, _m = self.make_department()
        admin_login(self.client, self.boss, secret=self.secrets[self.boss.pk])
        for name, kwargs in (('delegates', {}), ('department_list', {}), ('department', {'pk': department.pk}),
                             ('my_roles', {})):
            self.assertEqual(self.client.get(reverse(f'plugins:netbox_user_pin:{name}', kwargs=kwargs)).status_code,
                             200, name)
        settings = PinSettings.load()
        settings.language = 'sk'
        settings.save()
        self.assertContains(self.client.get(reverse('plugins:netbox_user_pin:department_list')), 'Oddelenia')
        self.client.force_login(head)
        self.assertContains(self.client.get(reverse('plugins:netbox_user_pin:my_roles')), 'Vzdať sa')

    def test_head_invites_only_members(self):
        department, head, _dels, (m1,) = self.make_department()
        outsider = self.person('outsider')
        UserPin.objects.filter(user=head).update(totp_last_step=0)
        admin_login(self.client, head, secret=self.secrets[head.pk])
        url = reverse('plugins:netbox_user_pin:department', kwargs={'pk': department.pk})
        response = self.client.post(url, {'action': 'invite-delegate', 'user': outsider.pk, 'hours': 24})
        self.assertContains(response, 'is not a member')
        self.assertFalse(PinDelegate.objects.filter(user=outsider).exists())
        self.client.post(url, {'action': 'invite-delegate', 'user': m1.pk, 'hours': 36})
        role = PinDelegate.objects.get(user=m1)
        self.assertEqual((role.status, role.invite_hours), ('pending', 36))
