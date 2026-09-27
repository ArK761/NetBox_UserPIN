import time
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core import mail
from django.core.exceptions import ValidationError
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from netbox_user_pin import crypto, service, totp
from netbox_user_pin.models import (
    PinAccess, PinAccessMode, PinDelegate, PinEvent, PinEventAction, PinScopeMode, PinSettings, UserPin,
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


def admin_login(client, user, pin=GOOD_PIN):
    """Log in, set PIN + 2FA, unlock the admin area and perform a step-up."""
    if not service.has_pin(user):
        service.set_pin(user, pin)
    secret = enable_2fa(user) if not service.has_2fa(user) else None
    client.force_login(user)
    client.post(reverse('plugins:netbox_user_pin:unlock'), {'pin': pin, 'scope': 'user-pin-admin'})
    response = client.post(reverse('plugins:netbox_user_pin:step_up'), {'pin': pin, 'otp': current_code(secret)})
    assert response.status_code == 302, response.content[:500]
    return secret


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
        self.client.post(reverse('plugins:netbox_user_pin:user_action', kwargs={'pk': self.user.pk, 'action': 'reset'}))
        self.assertFalse(service.has_pin(self.user))

        data = {
            'access_mode': 'all', 'pin_length': 8, 'block_weak_pins': 'on', 'blocked_pins': '', 'max_age_days': 180,
            'warn_days': 14, 'unlock_minutes': 10, 'sliding_unlock': 'on', 'scope_mode': 'global',
            'max_attempts': 5, 'lockout_minutes': 30, 'require_2fa_admin': 'on', 'step_up_minutes': 5,
            'self_recovery': 'on', 'recovery_minutes': 15, 'allowed_email_domains': 'firma.sk', 'notify_email': 'on',
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
        settings = PinSettings.load()
        settings.allowed_email_domains = 'firma.sk'
        settings.save()
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
        settings = PinSettings.load()
        settings.allowed_email_domains = 'firma.sk\nfirma.com'
        settings.save()
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
        PinDelegate.objects.create(user=self.delegate, can_edit_settings=can_edit_settings)
        PinDelegate.objects.create(user=self.other_delegate)
        delegation.sync_permissions()
        for user in (self.delegate, self.other_delegate):
            for attr in ('_perm_cache', '_user_perm_cache', '_group_perm_cache', '_object_perm_cache'):
                if hasattr(user, attr):
                    delattr(user, attr)

    def test_master_adds_delegate_via_view(self):
        admin_login(self.client, self.master)
        self.client.post(reverse('plugins:netbox_user_pin:delegates'), {'user': self.delegate.pk})
        delegate = User.objects.get(pk=self.delegate.pk)
        self.assertTrue(delegate.has_perm('netbox_user_pin.change_userpin'))
        self.assertTrue(delegate.has_perm('netbox_user_pin.view_pinevent'))
        self.assertTrue(delegate.has_perm('netbox_user_pin.view_pinsettings'))
        self.assertFalse(delegate.has_perm('netbox_user_pin.change_pinsettings'))
        self.assertFalse(delegate.has_perm('netbox_user_pin.add_pinsettings'))
        self.assertTrue(PinEvent.objects.filter(action=PinEventAction.DELEGATE_ADDED).exists())

    def test_separation_of_duties(self):
        self._add_delegates()
        delegate = User.objects.get(pk=self.delegate.pk)
        self.assertTrue(service.can_manage(delegate, self.user))
        self.assertFalse(service.can_manage(delegate, self.master))
        self.assertFalse(service.can_manage(delegate, self.other_delegate))
        self.assertFalse(service.can_manage(delegate, delegate))
        self.assertTrue(service.can_manage(self.master, delegate))
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
