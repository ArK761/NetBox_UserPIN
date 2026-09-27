from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from netbox_user_pin import crypto, service
from netbox_user_pin.models import PinEvent, PinEventAction, PinScopeMode, PinSettings, UserPin
from netbox_user_pin.policy import is_weak_pin

User = get_user_model()
GOOD_PIN = '482915'
OTHER_PIN = '730461'


class PolicyTest(TestCase):

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


class CryptoTest(TestCase):

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


class ServiceTest(TestCase):

    def setUp(self):
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


class ViewTest(TestCase):

    def setUp(self):
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
        self.client.force_login(admin)
        for name in ('user_list', 'event_list', 'settings'):
            self.assertEqual(self.client.get(reverse(f'plugins:netbox_user_pin:{name}')).status_code, 200, name)
        self.client.post(reverse('plugins:netbox_user_pin:user_action', kwargs={'pk': self.user.pk, 'action': 'reset'}))
        self.assertFalse(service.has_pin(self.user))

        data = {
            'pin_length': 8, 'block_weak_pins': 'on', 'blocked_pins': '', 'max_age_days': 0,
            'unlock_minutes': 10, 'sliding_unlock': 'on', 'scope_mode': 'global',
            'max_attempts': 5, 'lockout_minutes': 30,
        }
        self.client.post(reverse('plugins:netbox_user_pin:settings'), data)
        self.assertEqual(PinSettings.load().pin_length, 8)
        event = PinEvent.objects.get(action=PinEventAction.SETTINGS_CHANGED)
        self.assertIn('pin_length: 6 -> 8', event.detail)


@override_settings()
class ConfigTest(TestCase):

    def test_fingerprint_is_stable_and_not_the_key(self):
        from netbox.plugins import get_plugin_config
        key = get_plugin_config('netbox_user_pin', 'encryption_keys')['k1']
        fp = crypto.fingerprint()
        self.assertEqual(fp, crypto.fingerprint('k1'))
        self.assertNotIn(fp.replace(':', ''), key.upper())


class KeyRotationTest(TestCase):

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


class KeyFormatTest(TestCase):

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
