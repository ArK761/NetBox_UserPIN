from datetime import timedelta

from django.contrib.auth import get_user_model
from django.db.models import Q
from django.core.exceptions import PermissionDenied, ValidationError
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone

from netbox_user_pin import area_guard, areas
from netbox_user_pin.forms import PinSettingsForm
from netbox_user_pin.models import (
    AreaGrant, AreaProfile, AreaRequest, AreaRequestStatus, PinEvent, PinEventAction, PinSettings, ProtectedArea,
)

from netbox_user_pin import service

from .test_pin import GOOD_PIN, PinTestCase, admin_login, current_code, enable_2fa

User = get_user_model()
DEVICES = '/dcim/devices/'


class AreaTestCase(PinTestCase):
    def setUp(self):
        super().setUp()
        areas.clear_cache()
        from django.core.cache import cache
        cache.clear()  # the throttle of the refusal log lives there
        self.master = User.objects.create_superuser('master', 'm@example.com', 'x')
        self.owner1 = User.objects.create_user('owner1', 'o1@example.com')
        self.owner2 = User.objects.create_user('owner2', 'o2@example.com')
        # owners hold a PIN role above a plain user: a head and a delegate of a department
        from netbox_user_pin.models import Department, PinDelegate, RoleKind, RoleStatus
        department = Department.objects.create(name='Network')
        PinDelegate.objects.create(user=self.owner1, role=RoleKind.HEAD, department=department,
                                   status=RoleStatus.ACTIVE)
        PinDelegate.objects.create(user=self.owner2, role=RoleKind.DELEGATE, department=department,
                                   status=RoleStatus.ACTIVE)
        self.appadmin = User.objects.create_superuser('appadmin', 'a@example.com', 'x')  # superuser, not a network man
        settings = PinSettings.load()
        settings.areas_enabled = True
        settings.save()

    def make_area(self, targets=('dcim.device',), owners=True, max_hours=24):
        area = areas.create_area('Network', list(targets), [], self.master, 'network devices', max_hours)
        if owners:
            areas.add_owner(area, self.owner1, self.master)
            areas.add_owner(area, self.owner2, self.owner1)
        return area

    def profile(self, area, name='Read'):
        return area.profiles.get(name=name)

    def login(self, user, unlock=True):
        """Log in; a user who holds access has to unlock the PIN to enter an area."""
        self.client.force_login(user)
        if unlock:
            if not service.has_pin(user):
                service.set_pin(user, GOOD_PIN)
            self.client.post(reverse('plugins:netbox_user_pin:unlock'), {'pin': GOOD_PIN})


class GuardTest(AreaTestCase):
    def test_superuser_is_blocked_without_a_grant(self):
        self.make_area()
        self.login(self.appadmin)
        response = self.client.get(DEVICES)
        self.assertEqual(response.status_code, 403)
        self.assertContains(response, 'Request access', status_code=403)
        self.assertContains(response, 'owner1', status_code=403)  # who manages the access is named

    def test_denied_page_speaks_the_plugin_language(self):
        self.make_area()
        settings = PinSettings.load()
        settings.language = 'sk'
        settings.save()
        self.login(self.appadmin)
        self.assertContains(self.client.get(DEVICES), 'Táto oblasť je chránená', status_code=403)

    def test_nothing_changes_while_the_switch_is_off(self):
        self.make_area()
        settings = PinSettings.load()
        settings.areas_enabled = False
        settings.save()
        self.login(self.appadmin)
        self.assertEqual(self.client.get(DEVICES).status_code, 200)

    def test_other_objects_stay_open(self):
        self.make_area()
        self.login(self.appadmin)
        self.assertEqual(self.client.get('/dcim/sites/').status_code, 200)

    def test_grant_opens_it_and_expiry_closes_it(self):
        area = self.make_area()
        self.login(self.appadmin)
        grant = areas.grant_access(area, self.appadmin, self.profile(area), 4, self.owner1)
        self.assertEqual(self.client.get(DEVICES).status_code, 200)
        AreaGrant.objects.filter(pk=grant.pk).update(expires=timezone.now() - timedelta(minutes=1))
        self.assertEqual(self.client.get(DEVICES).status_code, 403)

    def test_revoke(self):
        area = self.make_area()
        self.login(self.appadmin)
        grant = areas.grant_access(area, self.appadmin, self.profile(area), None, self.owner1)
        self.assertEqual(self.client.get(DEVICES).status_code, 200)
        areas.revoke_grant(grant, self.owner2)
        self.assertEqual(self.client.get(DEVICES).status_code, 403)

    def test_read_profile_does_not_allow_changes(self):
        area = self.make_area()
        self.login(self.appadmin)
        areas.grant_access(area, self.appadmin, self.profile(area, 'Read'), None, self.owner1)
        self.assertEqual(self.client.get(DEVICES).status_code, 200)
        self.assertEqual(self.client.post('/dcim/devices/add/', {}).status_code, 403)
        areas.grant_access(area, self.appadmin, self.profile(area, 'Edit'), None, self.owner1)
        self.assertNotEqual(self.client.post('/dcim/devices/add/', {}).status_code, 403)
        self.assertEqual(self.client.post('/dcim/devices/delete/', {}).status_code, 403)  # needs "delete"

    def test_rest_api_is_guarded_too(self):
        area = self.make_area()
        self.login(self.appadmin)
        response = self.client.get('/api/dcim/devices/', HTTP_ACCEPT='application/json')
        self.assertEqual(response.status_code, 403)
        self.assertIn('protected area', response.json()['detail'])
        areas.grant_access(area, self.appadmin, self.profile(area), None, self.owner1)
        self.assertEqual(self.client.get('/api/dcim/devices/', HTTP_ACCEPT='application/json').status_code, 200)

    def test_the_door_stays_visible_but_the_key_is_needed(self):
        area = self.make_area()
        self.login(self.appadmin)
        html = self.client.get('/dcim/sites/').content.decode()
        self.assertIn('href="/dcim/devices/"', html)  # menu entry visible for everybody
        self.assertEqual(self.client.get(DEVICES).status_code, 403)  # entering is refused
        areas.grant_access(area, self.appadmin, self.profile(area), None, self.owner1)
        self.assertEqual(self.client.get(DEVICES).status_code, 200)

    def test_a_user_with_access_must_unlock_the_pin(self):
        area = self.make_area()
        user = self.appadmin
        areas.grant_access(area, user, self.profile(area), None, self.owner1)
        self.login(user, unlock=False)
        response = self.client.get(DEVICES)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/user-pin/set/', response['Location'])  # no PIN yet: set one first
        service.set_pin(user, GOOD_PIN)
        response = self.client.get(DEVICES)
        self.assertIn('/user-pin/unlock/', response['Location'])
        self.client.post(reverse('plugins:netbox_user_pin:unlock'), {'pin': GOOD_PIN})
        self.assertEqual(self.client.get(DEVICES).status_code, 200)

    def test_pin_replaces_the_netbox_permissions_of_a_normal_user(self):
        area = self.make_area()
        normal = User.objects.create_user('normal', 'n@example.com')  # no NetBox permissions at all
        areas.grant_access(area, normal, self.profile(area), None, self.owner1)
        self.login(normal)
        self.assertEqual(self.client.get(DEVICES).status_code, 200)
        self.assertEqual(self.client.get('/dcim/sites/').status_code, 403)  # NetBox says no outside the area

    def test_master_keeps_access_until_owners_exist(self):
        area = self.make_area(owners=False)
        self.login(self.master)
        self.assertEqual(self.client.get(DEVICES).status_code, 200)
        self.login(self.appadmin)
        self.assertEqual(self.client.get(DEVICES).status_code, 200)  # also a superuser: bootstrap = the masters
        areas.add_owner(area, self.owner1, self.master)
        self.assertEqual(self.client.get(DEVICES).status_code, 403)
        self.login(self.master)
        self.assertEqual(self.client.get(DEVICES).status_code, 403)

    def test_the_pin_plugin_cannot_be_protected(self):
        with self.assertRaises(ValidationError):
            areas.parse_targets('netbox_user_pin')
        with self.assertRaises(ValidationError):
            areas.parse_targets('nonsense.model')
        self.assertEqual(areas.parse_targets('dcim\nusers.user, dcim'), ['dcim', 'users.user'])

    def test_refusals_are_audited_once(self):
        self.make_area()
        self.login(self.appadmin)
        self.client.get(DEVICES)
        self.client.get(DEVICES)
        self.assertEqual(PinEvent.objects.filter(action=PinEventAction.AREA_BLOCKED, user=self.appadmin).count(), 1)

    def test_anonymous_goes_to_login(self):
        self.make_area()
        response = self.client.get(DEVICES)
        self.assertEqual(response.status_code, 302)


class WholeAppAndUsersTest(AreaTestCase):
    def test_whole_app_and_the_users_of_netbox(self):
        self.make_area(targets=('users.user',))
        self.login(self.appadmin)
        self.assertEqual(self.client.get('/users/users/').status_code, 403)  # the user list, superuser or not
        self.assertEqual(self.client.get('/dcim/devices/').status_code, 200)
        self.assertEqual(self.client.get('/user/profile/').status_code, 200)  # own profile / login are not objects


    def test_protecting_a_whole_core_app_does_not_lock_the_login(self):
        self.make_area(targets=('users',))
        self.assertEqual(self.client.get('/login/').status_code, 200)
        self.login(self.appadmin)
        self.assertEqual(self.client.get('/user/profile/').status_code, 200)
        self.assertEqual(self.client.get('/users/users/').status_code, 403)


class OwnerRulesTest(AreaTestCase):
    def test_master_cannot_change_owners_once_they_exist(self):
        area = self.make_area()
        with self.assertRaises(PermissionDenied):
            areas.add_owner(area, self.appadmin, self.master)
        with self.assertRaises(PermissionDenied):
            areas.remove_owner(area, self.owner2, self.master)
        with self.assertRaises(PermissionDenied):
            areas.grant_access(area, self.appadmin, self.profile(area), 1, self.master)
        with self.assertRaises(PermissionDenied):
            areas.update_area(area, self.master, name='Mine now')
        with self.assertRaises(PermissionDenied):
            areas.delete_area(area, self.master)

    def test_owners_manage_owners_but_not_down_to_zero(self):
        area = self.make_area()
        areas.remove_owner(area, self.owner2, self.owner1)
        with self.assertRaises(ValidationError):
            areas.remove_owner(area, self.owner1, self.owner1)

    def test_nobody_grants_themselves_or_decides_on_their_own_request(self):
        area = self.make_area()
        with self.assertRaises(ValidationError):
            areas.grant_access(area, self.owner1, self.profile(area), 1, self.owner1)
        outsider = User.objects.create_user('outsider', 'x@example.com')
        with self.assertRaises(PermissionDenied):
            areas.grant_access(area, outsider, self.profile(area), 1, outsider)

    def test_temporary_access_is_limited_by_the_area(self):
        area = self.make_area(max_hours=8)
        with self.assertRaises(ValidationError):
            areas.grant_access(area, self.appadmin, self.profile(area), 9, self.owner1)
        areas.grant_access(area, self.appadmin, self.profile(area), 8, self.owner1)

    def test_switch_cannot_be_turned_off_while_owned_areas_are_active(self):
        self.make_area()
        settings = PinSettings.load()
        data = {name: getattr(settings, name) for name in PinSettingsForm.Meta.fields}
        data['areas_enabled'] = False
        form = PinSettingsForm(data, instance=settings)
        self.assertFalse(form.is_valid())
        self.assertIn('areas_enabled', form.errors)
        ProtectedArea.objects.update(enabled=False)  # the owners deactivated the area
        self.assertTrue(PinSettingsForm(data, instance=PinSettings.load()).is_valid())

    def test_emergency_reset_of_owners_is_audited(self):
        area = self.make_area()
        areas.reset_owners(area, [self.appadmin], 'test')
        self.assertEqual([o.user for o in area.owners.all()], [self.appadmin])
        self.assertTrue(PinEvent.objects.filter(action=PinEventAction.AREA_CHANGED, detail__contains='OWNERS RESET').exists())


class RequestFlowTest(AreaTestCase):
    def test_request_notify_decide(self):
        area = self.make_area()
        self.login(self.appadmin)
        response = self.client.post(reverse('plugins:netbox_user_pin:area_request', kwargs={'key': area.key}),
                                    {'note': 'need the devices', 'scope': 'tenant group X'})
        self.assertEqual(response.status_code, 302)
        req = AreaRequest.objects.get(user=self.appadmin)
        self.assertEqual((req.note, req.scope), ('need the devices', 'tenant group X'))
        self.assertEqual(req.status, AreaRequestStatus.PENDING)
        self.assertEqual(areas.pending_requests_for(self.owner1).count(), 1)
        self.assertEqual(areas.pending_requests_for(self.appadmin).count(), 0)
        # asking again does not create a second request
        self.client.post(reverse('plugins:netbox_user_pin:area_request', kwargs={'key': area.key}), {})
        self.assertEqual(AreaRequest.objects.filter(user=self.appadmin).count(), 1)

        with self.assertRaises(PermissionDenied):
            areas.decide_request(req, self.master, True, self.profile(area), 1)  # the master is no owner
        owner_client = self.client_class()
        admin_login(owner_client, self.owner1)
        response = owner_client.post(reverse('plugins:netbox_user_pin:area', kwargs={'pk': area.pk}), {
            'action': 'approve', 'pk': req.pk, 'rights': ['view'], 'target': 'dcim.device', 'hours': 4})
        self.assertEqual(response.status_code, 302, response.content[:300])
        req.refresh_from_db()
        self.assertEqual(req.status, AreaRequestStatus.GRANTED)
        self.assertEqual(self.client.get(DEVICES).status_code, 200)

    def test_decision_needs_step_up(self):
        area = self.make_area()
        areas.request_access(area, self.appadmin, 'I need the devices')
        req = AreaRequest.objects.get()
        service.set_pin(self.owner1, GOOD_PIN)
        secret = enable_2fa(self.owner1)
        self.login(self.owner1)
        self.client.post(reverse('plugins:netbox_user_pin:unlock'), {'pin': GOOD_PIN, 'scope': 'user-pin-admin'})
        response = self.client.post(reverse('plugins:netbox_user_pin:area', kwargs={'pk': area.pk}), {
            'action': 'deny', 'pk': req.pk})
        self.assertEqual(response.status_code, 302)
        self.assertIn('/2fa-confirm/', response['Location'])  # the PIN is unlocked; only the 2FA code is asked
        req.refresh_from_db()
        self.assertEqual(req.status, AreaRequestStatus.PENDING)
        # one valid code opens the window: no further PIN or code for the next changes
        response = self.client.post(reverse('plugins:netbox_user_pin:twofa_confirm'), {'otp': current_code(secret)})
        self.assertEqual(response.status_code, 302)
        response = self.client.post(reverse('plugins:netbox_user_pin:area', kwargs={'pk': area.pk}), {
            'action': 'deny', 'pk': req.pk})
        self.assertNotIn('/2fa-confirm/', response['Location'])
        req.refresh_from_db()
        self.assertEqual(req.status, AreaRequestStatus.DENIED)


class CustomGrantTest(AreaTestCase):
    def test_access_per_user_and_object_type_with_chosen_rights(self):
        area = self.make_area(targets=('dcim.device', 'dcim.site'))
        normal = User.objects.create_user('normal', 'n@example.com')
        areas.grant_custom(area, normal, 'dcim.device', ['view', 'change'], None, self.owner1)
        self.assertTrue(areas.can(normal, area, 'change', 'dcim.device'))
        self.assertFalse(areas.can(normal, area, 'delete', 'dcim.device'))
        self.assertFalse(areas.can(normal, area, 'view', 'dcim.site'))  # another type of the area: no key
        self.assertIsNone(areas.row_filter(normal, area, 'dcim', 'site'))
        self.assertEqual(areas.row_filter(normal, area, 'dcim', 'device'), Q())
        # nothing on the page names a profile
        admin_login(self.client, self.owner1)
        html = self.client.get(reverse('plugins:netbox_user_pin:area', kwargs={'pk': area.pk})).content.decode()
        self.assertNotIn('Save profile', html)

    def test_rows_and_update(self):
        area = self.make_area()
        normal = User.objects.create_user('normal', 'n@example.com')
        grant = areas.grant_custom(area, normal, 'dcim.device', ['view'], None, self.owner1,
                                   filters=areas.parse_filters('dcim.device: name__istartswith=PRINTER', area))
        self.assertNotEqual(areas.row_filter(normal, area, 'dcim', 'device'), Q())
        areas.update_grant(grant, ['view', 'add'], self.owner1)
        areas.clear_cache()
        self.assertEqual(areas.row_filter(normal, area, 'dcim', 'device'), Q())
        with self.assertRaises(ValidationError):
            areas.grant_custom(area, normal, 'dcim.device', [], None, self.owner1)
        with self.assertRaises(PermissionDenied):
            areas.grant_custom(area, normal, 'dcim.device', ['view'], None, normal)

    def test_grant_form_on_the_page(self):
        area = self.make_area()
        normal = User.objects.create_user('normal', 'n@example.com')
        admin_login(self.client, self.owner1)
        response = self.client.post(reverse('plugins:netbox_user_pin:area', kwargs={'pk': area.pk}), {
            'action': 'grant', 'user': normal.pk, 'target': 'dcim.device', 'rights': ['view', 'change'],
            'rows': 'name__istartswith=PRINTER', 'hours': 0})
        self.assertEqual(response.status_code, 302, response.content[:300])
        grant = AreaGrant.objects.get(user=normal)
        self.assertEqual(grant.target, 'dcim.device')
        self.assertEqual(grant.profile.filters, {'dcim.device': {'name__istartswith': 'PRINTER'}})


class TwoFactorWindowTest(AreaTestCase):
    def test_window_expires_with_the_setting(self):
        from datetime import timedelta
        admin_login(self.client, self.owner1)
        request = self.client.get(reverse('plugins:netbox_user_pin:areas')).wsgi_request
        self.assertTrue(service.has_recent_2fa(request))
        session = self.client.session
        data = session[service.TWOFA_SESSION_KEY]
        data['at'] = data['at'] - int(timedelta(hours=9).total_seconds())
        session[service.TWOFA_SESSION_KEY] = data
        session.save()
        response = self.client.get(reverse('plugins:netbox_user_pin:areas'))
        self.assertEqual(response.status_code, 302)
        self.assertIn('/2fa-confirm/', response['Location'])

    def test_deny_and_cancel(self):
        area = self.make_area()
        req = areas.request_access(area, self.appadmin, 'I need the devices')
        areas.decide_request(req, self.owner1, False)
        self.assertEqual(AreaRequest.objects.get(pk=req.pk).status, AreaRequestStatus.DENIED)
        req2 = areas.request_access(area, self.appadmin, 'I need the devices')
        areas.cancel_request(req2, self.appadmin)
        self.assertEqual(AreaRequest.objects.get(pk=req2.pk).status, AreaRequestStatus.CANCELLED)

    def test_no_owners_no_request(self):
        area = self.make_area(owners=False)
        with self.assertRaises(ValidationError):
            areas.request_access(area, self.appadmin, 'I need the devices')

    def test_user_can_end_their_own_access(self):
        area = self.make_area()
        grant = areas.grant_access(area, self.appadmin, self.profile(area), None, self.owner1)
        self.login(self.appadmin)
        self.client.post(reverse('plugins:netbox_user_pin:my_access'), {'action': 'end', 'pk': grant.pk})
        self.assertEqual(self.client.get(DEVICES).status_code, 403)


class PluginAreaTest(AreaTestCase):
    def setUp(self):
        super().setUp()
        self.flag = {'on': False}
        areas.register('testplugin', 'Test plugin', targets=['dcim.site'], rights={'secret': 'Secrets'},
                       profiles=[('Basic', ['view']), ('Secrets', ['view', 'secret'])],
                       enabled=lambda: self.flag['on'])
        self.addCleanup(lambda: (areas._registry.pop('testplugin', None), areas.clear_cache()))
        settings = PinSettings.load()
        settings.areas_enabled = False  # the global switch is off: a plugin protects on its own
        settings.save()

    def test_plugin_switch_alone_activates_the_area(self):
        self.login(self.appadmin)
        self.assertEqual(self.client.get('/dcim/sites/').status_code, 200)
        self.flag['on'] = True
        areas.clear_cache()
        self.assertEqual(self.client.get('/dcim/sites/').status_code, 200)  # no owners yet: superusers keep access
        area = ProtectedArea.objects.get(key='testplugin')
        areas.add_owner(area, self.owner1, self.master)
        self.assertEqual(self.client.get('/dcim/sites/').status_code, 403)

    def test_plugin_rights(self):
        self.flag['on'] = True
        areas.clear_cache()
        areas.sync_plugin_areas()
        area = ProtectedArea.objects.get(key='testplugin')
        areas.add_owner(area, self.owner1, self.master)
        areas.grant_access(area, self.appadmin, area.profiles.get(name='Basic'), None, self.owner1)
        self.assertTrue(areas.can(self.appadmin, 'testplugin', 'view'))
        self.assertFalse(areas.can(self.appadmin, 'testplugin', 'secret'))
        areas.grant_access(area, self.appadmin, area.profiles.get(name='Secrets'), None, self.owner1)
        self.assertTrue(areas.can(User.objects.get(pk=self.appadmin.pk), 'testplugin', 'secret'))
        self.assertTrue(areas.can(self.owner1, 'testplugin', 'secret'))  # owners hold everything

    def test_inactive_area_allows_everything(self):
        self.assertTrue(areas.can(self.appadmin, 'testplugin', 'secret'))

    def test_has_perm_follows_the_pin_for_a_plugin_area(self):
        self.flag['on'] = True
        areas.clear_cache()
        areas.sync_plugin_areas()
        area = ProtectedArea.objects.get(key='testplugin')
        areas.add_owner(area, self.owner1, self.master)
        user = User.objects.get(pk=self.appadmin.pk)
        area_guard.arm_user(user)
        self.assertTrue(user.has_perm('dcim.view_site'))  # no key at all: the door is visible
        areas.grant_access(area, self.appadmin, area.profiles.get(name='Basic'), None, self.owner1)
        user = User.objects.get(pk=self.appadmin.pk)
        area_guard.arm_user(user)
        self.assertTrue(user.has_perm('dcim.view_site'))
        self.assertFalse(user.has_perm('dcim.delete_site'))
        self.assertFalse(user.has_perm('dcim.secret_site'))  # a permission named after a right of the plugin
        areas.grant_access(area, self.appadmin, area.profiles.get(name='Secrets'), None, self.owner1)
        user = User.objects.get(pk=self.appadmin.pk)
        area_guard.arm_user(user)
        self.assertTrue(user.has_perm('dcim.secret_site'))
        self.assertEqual(areas.API_VERSION, 1)


class PagesTest(AreaTestCase):
    def test_pages_render(self):
        area = self.make_area()
        admin_login(self.client, self.owner1)
        for name, kwargs in (('areas', {}), ('area', {'pk': area.pk}), ('my_access', {})):
            response = self.client.get(reverse(f'plugins:netbox_user_pin:{name}', kwargs=kwargs))
            self.assertEqual(response.status_code, 200, name)
        self.assertContains(self.client.get(reverse('plugins:netbox_user_pin:area', kwargs={'pk': area.pk})), 'Create group')

    def test_a_stranger_does_not_see_the_area_page(self):
        area = self.make_area()
        admin_login(self.client, self.appadmin)
        self.assertEqual(self.client.get(reverse('plugins:netbox_user_pin:area', kwargs={'pk': area.pk})).status_code, 200
                         if areas.can_see(self.appadmin, area) else 403)
        stranger = User.objects.create_user('stranger', 's@example.com')
        admin_login(self.client, stranger)
        self.assertEqual(self.client.get(reverse('plugins:netbox_user_pin:area', kwargs={'pk': area.pk})).status_code, 403)

    def test_create_area_from_the_page(self):
        admin_login(self.client, self.master)
        response = self.client.post(reverse('plugins:netbox_user_pin:areas'), {
            'action': 'create', 'name': 'IPAM', 'target': 'ipam', 'max_hours': 12})
        self.assertEqual(response.status_code, 302, response.content[:300])
        self.assertTrue(ProtectedArea.objects.filter(name='IPAM', targets=['ipam']).exists())


class CommandTest(AreaTestCase):
    def test_emergency_owner_reset_command(self):
        from io import StringIO

        from django.core.management import call_command
        area = self.make_area()
        out = StringIO()
        call_command('userpin_area_owners', area.key, '--set', 'appadmin', stdout=out)
        self.assertEqual([o.user.username for o in area.owners.all()], ['appadmin'])
        out = StringIO()
        call_command('userpin_area_owners', area.key, stdout=out)
        self.assertIn('appadmin', out.getvalue())


class BuildBadgeTest(AreaTestCase):
    def test_version_and_commit_badge_on_the_pages(self):
        from unittest import mock

        from netbox_user_pin import build
        info = {'version': '9.9.9', 'commit': 'c' * 40, 'short': 'ccccccc'}
        with mock.patch.object(build, 'plugin_build', return_value=info), \
                mock.patch('netbox_user_pin.templatetags.userpin_tags.plugin_build', return_value=info):
            admin_login(self.client, self.owner1)
            html = self.client.get(reverse('plugins:netbox_user_pin:my_pin')).content.decode()
        self.assertIn('User PIN v9.9.9 · ' + 'c' * 40, html)

    def test_commit_is_read_from_pip_metadata(self):
        from unittest import mock

        from netbox_user_pin import build

        class Dist:
            version = '1.2.3'

            def read_text(self, name):
                return '{"vcs_info": {"vcs": "git", "commit_id": "abcdef1234567890"}}'

        build.plugin_build.cache_clear()
        try:
            with mock.patch('importlib.metadata.distribution', return_value=Dist()):
                from netbox_user_pin import __version__
                self.assertEqual(build.plugin_build(),  # the version is the one of the code, the commit is pip's record
                                 {'version': __version__, 'commit': 'abcdef1234567890', 'short': 'abcdef1'})
        finally:
            build.plugin_build.cache_clear()


class RowsAndReasonTest(AreaTestCase):
    def setUp(self):
        super().setUp()
        from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site
        role = DeviceRole.objects.create(name='r', slug='r')
        site = Site.objects.create(name='s', slug='s')
        kind = DeviceType.objects.create(manufacturer=Manufacturer.objects.create(name='m', slug='m'), model='t', slug='t')
        for name in ('PRINTER_A', 'PRINTER_B', 'SWITCH_A'):
            Device.objects.create(name=name, role=role, site=site, device_type=kind)
        self.area = self.make_area()
        self.profile_printers = areas.save_profile(
            self.area, 'Printers', ['view'], self.owner1,
            filters=areas.parse_filters('dcim.device: name__istartswith=PRINTER', self.area))

    def test_only_the_rows_of_the_profile_are_shown(self):
        areas.grant_access(self.area, self.appadmin, self.profile_printers, None, self.owner1)
        self.login(self.appadmin)
        html = self.client.get(DEVICES).content.decode()
        self.assertIn('PRINTER_A', html)
        self.assertNotIn('SWITCH_A', html)
        api = self.client.get('/api/dcim/devices/', HTTP_ACCEPT='application/json').json()
        self.assertEqual(api['count'], 2)
        self.assertEqual({d['name'] for d in api['results']}, {'PRINTER_A', 'PRINTER_B'})

    def test_a_profile_without_a_filter_shows_everything(self):
        areas.grant_access(self.area, self.appadmin, self.profile(self.area), None, self.owner1)
        self.login(self.appadmin)
        self.assertEqual(self.client.get('/api/dcim/devices/', HTTP_ACCEPT='application/json').json()['count'], 3)

    def test_owners_see_everything_and_outsiders_nothing_in_the_drop_downs(self):
        self.login(self.owner1)
        self.assertEqual(self.client.get('/api/dcim/devices/', HTTP_ACCEPT='application/json').json()['count'], 3)
        self.login(self.appadmin)
        self.assertEqual(self.client.get('/api/dcim/devices/?q=prin', HTTP_ACCEPT='application/json').status_code, 403)

    def test_filters_are_validated(self):
        for bad in ('dcim.device name=1', 'dcim.device: nonsense_field=1', 'ipam.prefix: prefix=1', 'dcim.device: name'):
            with self.assertRaises(ValidationError, msg=bad):
                areas.parse_filters(bad, self.area)
        self.assertEqual(areas.parse_filters('dcim.device: name__istartswith=PRINTER & status=active', self.area),
                         {'dcim.device': {'name__istartswith': 'PRINTER', 'status': 'active'}})
        self.assertEqual(areas.format_filters({'dcim.device': {'name__istartswith': 'P'}}),
                         'dcim.device: name__istartswith=P')

    def test_a_reason_is_required(self):
        with self.assertRaises(ValidationError):
            areas.request_access(self.area, self.appadmin, '')
        self.login(self.appadmin)
        self.client.post(reverse('plugins:netbox_user_pin:area_request', kwargs={'key': self.area.key}), {'note': 'x'})
        self.assertFalse(AreaRequest.objects.exists())

    def test_grantees_may_use_a_pin(self):
        from netbox_user_pin.models import PinAccess, PinAccessMode
        settings = PinSettings.load()
        settings.access_mode = PinAccessMode.ALLOWED_ONLY
        settings.save()
        normal = User.objects.create_user('normal2', 'n2@example.com')
        self.assertFalse(service.is_allowed(normal))
        areas.grant_access(self.area, normal, self.profile(self.area), 1, self.owner1)
        self.assertTrue(service.is_allowed(normal))
        denied = User.objects.create_user('denied', 'd@example.com')
        service.set_access(denied, PinAccess.DENIED, self.master)
        with self.assertRaises(ValidationError):
            areas.grant_access(self.area, denied, self.profile(self.area), 1, self.owner1)


class ProfileViewTest(AreaTestCase):
    def test_profiles_can_be_edited_and_deleted_on_the_page(self):
        area = self.make_area(owners=False)  # only the master manages it
        admin_login(self.client, self.master)
        url = reverse('plugins:netbox_user_pin:area', kwargs={'pk': area.pk})
        read = self.profile(area, 'Read')
        response = self.client.post(url, {'action': 'profile-save', 'pk': read.pk, 'name': 'Read', 'rights': ['view', 'add']})
        self.assertEqual(response.status_code, 302, response.content[:400])
        read.refresh_from_db()
        self.assertEqual(sorted(read.rights), ['add', 'view'])
        response = self.client.post(url, {'action': 'profile-delete', 'pk': self.profile(area, 'Full').pk})
        self.assertEqual(response.status_code, 302)
        self.assertFalse(area.profiles.filter(name='Full').exists())



class DefaultDenyTest(AreaTestCase):
    def setUp(self):
        super().setUp()
        self.keeper = User.objects.create_superuser('keeper', 'k@example.com', 'x')  # exempt from the default deny; NetBox decides for it
        service.set_pin(self.keeper, GOOD_PIN)
        enable_2fa(self.keeper)
        self.plain = User.objects.create_user('plain', 'p@example.com')

    def add_keeper(self):
        return areas.add_keeper(self.keeper, self.master)

    def test_keeper_needs_pin_and_2fa(self):
        with self.assertRaises(ValidationError):
            areas.add_keeper(self.plain, self.master)
        self.add_keeper()

    def test_only_keepers_manage_keepers_and_the_switch(self):
        with self.assertRaises(ValidationError):
            areas.set_default_deny(True, self.master)  # no keeper yet
        self.add_keeper()
        with self.assertRaises(PermissionDenied):
            areas.set_default_deny(False, self.master)  # the master is no keeper
        with self.assertRaises(PermissionDenied):
            areas.add_keeper(self.plain, self.master)
        areas.set_default_deny(True, self.keeper)
        self.assertTrue(PinSettings.load().default_deny)
        areas.set_default_deny(False, self.keeper)
        self.assertFalse(PinSettings.load().default_deny)

    def test_the_last_keeper_stays_and_cannot_drop_2fa(self):
        self.add_keeper()
        with self.assertRaises(ValidationError):
            areas.remove_keeper(self.keeper, self.keeper)
        with self.assertRaises(ValidationError):
            service.disable_totp(self.keeper)
        other = User.objects.create_user('keeper2', 'k2@example.com')
        service.set_pin(other, GOOD_PIN)
        enable_2fa(other)
        areas.add_keeper(other, self.keeper)
        areas.remove_keeper(self.keeper, other)  # another keeper takes over
        self.assertEqual([k.username for k in areas.keepers()], ['keeper2'])

    def test_what_no_area_allows_is_denied_except_for_keepers(self):
        self.add_keeper()
        areas.set_default_deny(True, self.keeper)
        self.login(self.appadmin)
        response = self.client.get('/dcim/sites/')
        self.assertContains(response, 'Access denied', status_code=403)
        self.assertEqual(self.client.get('/api/dcim/sites/', HTTP_ACCEPT='application/json').status_code, 403)
        self.assertEqual(self.client.get('/user/profile/').status_code, 200)  # own account stays open
        self.assertEqual(self.client.get('/user/notifications/').status_code, 200)
        self.login(self.keeper)
        self.assertEqual(self.client.get('/dcim/sites/').status_code, 200)  # exempt
        self.client.logout()
        self.assertEqual(self.client.get('/login/').status_code, 200)

    def test_areas_still_decide_inside_their_objects_while_default_deny_is_on(self):
        area = self.make_area(targets=('dcim.site',))
        self.add_keeper()
        areas.set_default_deny(True, self.keeper)
        self.login(self.appadmin)
        self.assertEqual(self.client.get('/dcim/sites/').status_code, 403)
        areas.grant_access(area, self.appadmin, self.profile(area), None, self.owner1)
        self.assertEqual(self.client.get('/dcim/sites/').status_code, 200)
        self.assertEqual(self.client.get('/dcim/devices/').status_code, 403)  # not in any area: default deny

    def test_off_means_off_and_the_command_can_switch_it_off(self):
        from io import StringIO

        from django.core.management import call_command
        self.add_keeper()
        areas.set_default_deny(True, self.keeper)
        out = StringIO()
        call_command('userpin_default_deny', '--off', stdout=out)
        self.assertFalse(PinSettings.load().default_deny)
        areas.clear_cache()
        self.login(self.appadmin)
        self.assertEqual(self.client.get('/dcim/sites/').status_code, 200)
        call_command('userpin_default_deny', stdout=out)
        self.assertIn('off', out.getvalue())

    def test_keepers_page_actions(self):
        admin_login(self.client, self.master)
        url = reverse('plugins:netbox_user_pin:areas')
        response = self.client.post(url, {'action': 'keeper-add', 'user': self.keeper.pk})
        self.assertEqual(response.status_code, 302, response.content[:300])
        self.assertEqual([k.username for k in areas.keepers()], ['keeper'])


class TargetsAndToolsTest(AreaTestCase):
    def test_targets_are_added_and_removed_one_by_one(self):
        area = self.make_area(owners=False)
        admin_login(self.client, self.master)
        url = reverse('plugins:netbox_user_pin:area', kwargs={'pk': area.pk})
        self.assertEqual(self.client.post(url, {'action': 'target-add', 'target': 'dcim.site'}).status_code, 302)
        area.refresh_from_db()
        self.assertEqual(area.targets, ['dcim.device', 'dcim.site'])
        self.client.post(url, {'action': 'target-remove', 'target': 'dcim.device'})
        area.refresh_from_db()
        self.assertEqual(area.targets, ['dcim.site'])
        with self.assertRaises(ValidationError):
            areas.remove_target(area, 'dcim.site', self.master)  # the last one stays
        with self.assertRaises(ValidationError):
            areas.add_target(area, 'netbox_user_pin', self.master)

    def test_search_and_sort_helpers_are_on_the_pages(self):
        area = self.make_area()
        admin_login(self.client, self.owner1)
        html = self.client.get(reverse('plugins:netbox_user_pin:areas')).content.decode()
        self.assertIn('pin-filter', html)
        self.assertIn('pin-sortable', html)
        html = self.client.get(reverse('plugins:netbox_user_pin:area', kwargs={'pk': area.pk})).content.decode()
        self.assertIn('pin-searchable', html)
        self.assertIn('table_tools'.replace('table_tools', 'pin-sortable'), html)


class RequestFromDeniedPageTest(AreaTestCase):
    def setUp(self):
        super().setUp()
        self.keeper = User.objects.create_superuser('keeper', 'k@example.com', 'x')
        service.set_pin(self.keeper, GOOD_PIN)
        enable_2fa(self.keeper)
        self.plain = User.objects.create_user('plain', 'p@example.com')
        areas.add_keeper(self.keeper, self.master)
        areas.set_default_deny(True, self.keeper)
        areas.clear_cache()

    def ask(self, rights, note='I need the sites'):
        self.login(self.plain)
        return self.client.post(reverse('plugins:netbox_user_pin:request_access'), {
            'target': 'dcim.site', 'rights': rights, 'note': note, 'next': '/dcim/sites/'})

    def test_page_names_what_is_blocked_and_offers_the_rights(self):
        self.login(self.plain)
        response = self.client.get('/dcim/sites/')
        self.assertEqual(response.status_code, 403)
        self.assertContains(response, 'name="rights"', status_code=403)
        self.assertContains(response, 'value="dcim.site"', status_code=403)

    def test_request_goes_to_the_keepers_and_approving_creates_the_area(self):
        self.assertEqual(self.ask(['view', 'change']).status_code, 302)
        req = AreaRequest.objects.get(user=self.plain)
        self.assertIsNone(req.area)
        self.assertEqual((req.target, sorted(req.rights)), ('dcim.site', ['change', 'view']))
        self.assertEqual(list(areas.pending_requests_for(self.keeper)), [req])
        self.assertEqual(areas.pending_requests_for(self.master).count(), 0)
        # nobody else than a keeper decides
        outsider = self.client_class()
        admin_login(outsider, self.master)
        self.assertEqual(outsider.get(reverse('plugins:netbox_user_pin:request_decide', kwargs={'pk': req.pk})
                                      ).status_code, 403)
        keeper_client = self.client_class()
        admin_login(keeper_client, self.keeper)
        url = reverse('plugins:netbox_user_pin:request_decide', kwargs={'pk': req.pk})
        page = keeper_client.get(url)
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, 'I need the sites')
        response = keeper_client.post(url, {'action': 'approve', 'rights': ['view'], 'hours': 0})
        self.assertEqual(response.status_code, 302, response.content[:300])
        req.refresh_from_db()
        self.assertEqual(req.status, AreaRequestStatus.GRANTED)
        area = ProtectedArea.objects.get(targets=['dcim.site'])
        self.assertEqual(area.owners.count(), 0)  # the owners are appointed by hand
        grant = AreaGrant.objects.get(user=self.plain)
        self.assertEqual((grant.area, grant.target, grant.profile.rights), (area, 'dcim.site', ['view']))
        self.login(self.plain)
        self.assertEqual(self.client.get('/dcim/sites/').status_code, 200)

    def test_request_for_an_existing_area_goes_to_its_owners(self):
        area = self.make_area(targets=('dcim.site',))
        self.assertEqual(self.ask(['view']).status_code, 302)
        req = AreaRequest.objects.get(user=self.plain)
        self.assertEqual(req.area, area)
        self.assertEqual(areas.pending_requests_for(self.owner1).count(), 1)
        self.assertEqual(areas.pending_requests_for(self.keeper).count(), 0)
        grant = areas.decide_request(req, self.owner1, True, hours=None)
        self.assertEqual((grant.area, grant.target), (area, 'dcim.site'))

    def test_validation(self):
        self.ask([])  # no right chosen
        self.ask(['view'], note='x')  # no reason
        self.assertFalse(AreaRequest.objects.exists())
        self.ask(['view'])
        self.ask(['view'])  # asking again keeps one waiting request
        self.assertEqual(AreaRequest.objects.count(), 1)

    def test_ownerless_area_is_seen_by_the_keepers_only(self):
        area = self.make_area(targets=('dcim.device',), owners=False)
        self.login(self.master)  # a superuser nobody defined anywhere
        self.assertEqual(self.client.get(DEVICES).status_code, 403)
        self.assertFalse(areas.can(self.master, area, 'view', 'dcim.device'))
        self.login(self.keeper)
        self.assertEqual(self.client.get(DEVICES).status_code, 200)


class TabsTest(AreaTestCase):
    def setUp(self):
        super().setUp()
        from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site
        site = Site.objects.create(name='S1', slug='s1')
        maker = Manufacturer.objects.create(name='M1', slug='m1')
        dtype = DeviceType.objects.create(manufacturer=maker, model='T1', slug='t1')
        role = DeviceRole.objects.create(name='R1', slug='r1', color='ff0000')
        self.device = Device.objects.create(name='AGG_01', site=site, device_type=dtype, role=role)
        self.main = f'/dcim/devices/{self.device.pk}/'
        self.interfaces = f'/dcim/devices/{self.device.pk}/interfaces/'
        self.normal = User.objects.create_user('normal', 'n@example.com')

    def test_the_tabs_of_a_device_are_listed(self):
        names = {t['name']: t for t in areas.tabs_of('dcim.device')}
        self.assertIn('interfaces', names)
        self.assertIn('changelog', names)
        self.assertFalse(names['interfaces']['plugin'])

    def test_a_system_tab_must_be_allowed_and_its_objects_too(self):
        area = self.make_area(targets=('dcim.device', 'dcim.interface'))
        grant = areas.grant_custom(area, self.normal, 'dcim.device', ['view'], None, self.owner1)
        self.assertEqual(grant.profile.tabs, [])
        self.login(self.normal)
        self.assertEqual(self.client.get(self.main).status_code, 200)
        self.assertEqual(self.client.get(self.interfaces).status_code, 403)  # the tab is not allowed
        areas.set_grant_tabs(grant, ['interfaces', 'nonsense'], self.owner1)
        grant.profile.refresh_from_db()
        self.assertEqual(grant.profile.tabs, ['interfaces'])
        areas.clear_cache()
        self.assertEqual(self.client.get(self.interfaces).status_code, 403)  # allowed, but no right on interfaces
        areas.grant_custom(area, self.normal, 'dcim.interface', ['view'], None, self.owner1)
        areas.clear_cache()
        self.assertEqual(self.client.get(self.interfaces).status_code, 200)

    def test_owners_and_the_page_that_saves_tabs(self):
        area = self.make_area(targets=('dcim.device', 'dcim.interface'))
        grant = areas.grant_custom(area, self.normal, 'dcim.device', ['view'], None, self.owner1)
        admin_login(self.client, self.owner1)
        self.assertEqual(self.client.get(self.interfaces).status_code, 200)  # an owner opens every tab
        url = reverse('plugins:netbox_user_pin:area_fields', kwargs={'pk': area.pk})
        html = self.client.get(f'{url}?grant={grant.pk}&target=dcim.device').content.decode()
        self.assertIn('name="tab__interfaces"', html)
        self.assertIn('pin-bulk', html)  # set all shown fields at once
        response = self.client.post(url, {'action': 'tabs', 'grant': grant.pk, 'target': 'dcim.device',
                                          'tab__changelog': 'on'})
        self.assertEqual(response.status_code, 302, response.content[:300])
        grant.profile.refresh_from_db()
        self.assertEqual(grant.profile.tabs, ['changelog'])
        with self.assertRaises(PermissionDenied):
            areas.set_grant_tabs(grant, [], self.normal)

    def test_default_deny_blocks_the_listed_objects_of_a_tab(self):
        keeper = User.objects.create_superuser('keeper', 'k@example.com', 'x')
        service.set_pin(keeper, GOOD_PIN)
        enable_2fa(keeper)
        areas.add_keeper(keeper, self.master)
        areas.set_default_deny(True, keeper)
        area = self.make_area(targets=('dcim.device',))
        grant = areas.grant_custom(area, self.normal, 'dcim.device', ['view'], None, self.owner1)
        areas.set_grant_tabs(grant, ['interfaces'], self.owner1)
        areas.clear_cache()
        self.login(self.normal)
        self.assertEqual(self.client.get(self.main).status_code, 200)
        self.assertEqual(self.client.get(self.interfaces).status_code, 403)  # interfaces are in no area: denied

    def test_generic_tabs_changelog_journal_contacts_are_closed_too(self):
        area = self.make_area(targets=('dcim.device', 'dcim.interface'))
        grant = areas.grant_custom(area, self.normal, 'dcim.device', ['view'], None, self.owner1)
        self.login(self.normal)
        for name in ('changelog', 'journal', 'contacts', 'image-attachments'):
            url = f'/dcim/devices/{self.device.pk}/{name}/'
            self.assertEqual(self.client.get(url).status_code, 403, name)
        self.assertContains(self.client.get(f'/dcim/devices/{self.device.pk}/changelog/'), 'history.back()',
                            status_code=403)
        areas.set_grant_tabs(grant, ['changelog'], self.owner1)
        areas.clear_cache()
        self.assertEqual(self.client.get(f'/dcim/devices/{self.device.pk}/changelog/').status_code, 200)
        self.assertEqual(self.client.get(f'/dcim/devices/{self.device.pk}/journal/').status_code, 403)

    def test_a_hidden_fixed_field_is_gone_from_the_detail_page(self):
        from dcim.models import Platform
        platform = Platform.objects.create(name='PLATFORM_X', slug='platform-x')
        self.device.platform = platform
        self.device.save()
        area = self.make_area(targets=('dcim.device',))
        areas.grant_custom(area, self.normal, 'dcim.device', ['view'], None, self.owner1)
        self.login(self.normal)
        self.assertContains(self.client.get(self.main), 'PLATFORM_X')
        profile = area.profiles.get(name='Read')
        grant = AreaGrant.objects.get(user=self.normal)
        areas.save_field_rules(area, grant.profile, 'dcim.device', {'platform': ('hidden', '')}, self.owner1)
        areas.clear_cache()
        self.assertNotContains(self.client.get(self.main), 'PLATFORM_X')
        self.device.refresh_from_db()
        self.assertEqual(self.device.platform, platform)  # only the page changed, never the data


class NoPinYetTest(AreaTestCase):
    def test_a_user_with_access_but_without_a_pin_is_sent_to_create_one(self):
        area = self.make_area()
        normal = User.objects.create_user('normal', 'n@example.com')
        areas.grant_custom(area, normal, 'dcim.device', ['view'], None, self.owner1)
        self.assertFalse(service.has_pin(normal))
        self.client.force_login(normal)
        response = self.client.get(DEVICES)
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('plugins:netbox_user_pin:set_pin'), response['Location'])
        self.assertIn('next=', response['Location'])
        followed = self.client.get(response['Location'])
        self.assertContains(followed, 'you need a PIN')


class OwnerRoleTest(AreaTestCase):
    def test_only_a_pin_role_above_a_plain_user_may_own_an_area(self):
        area = self.make_area(owners=False)
        plain = User.objects.create_user('plain', 'p@example.com')
        with self.assertRaises(ValidationError):
            areas.add_owner(area, plain, self.master)
        areas.add_owner(area, self.owner1, self.master)  # a department head
        areas.add_owner(area, self.master, self.owner1)  # CORE (superuser)
        from netbox_user_pin import roles
        names = set(roles.manager_users().values_list('username', flat=True))
        self.assertIn('owner1', names)
        self.assertIn('owner2', names)
        self.assertNotIn('plain', names)


class TreeTest(AreaTestCase):
    def test_the_tree_lists_object_types_and_protecting_one_needs_no_name(self):
        admin_login(self.client, self.master)
        url = reverse('plugins:netbox_user_pin:areas')
        html = self.client.get(url).content.decode()
        self.assertIn('value="dcim.device"', html)
        self.assertNotIn('name="name"', html)  # no area is named by hand any more
        response = self.client.post(url, {'action': 'protect', 'target': 'dcim.device'})
        self.assertEqual(response.status_code, 302, response.content[:300])
        area = ProtectedArea.objects.get(targets=['dcim.device'])
        self.assertIn('Device', area.name)
        self.assertEqual(area.owners.count(), 0)
        self.client.post(url, {'action': 'protect', 'target': 'dcim.device'})  # again: the same area
        self.assertEqual(ProtectedArea.objects.filter(targets=['dcim.device']).count(), 1)
        html = self.client.get(url).content.decode()
        self.assertIn('no owner yet', html)

    def test_only_core_protects(self):
        self.login(self.owner1)
        response = self.client.post(reverse('plugins:netbox_user_pin:areas'), {'action': 'protect',
                                                                            'target': 'dcim.site'})
        self.assertNotEqual(response.status_code, 200)
        self.assertFalse(ProtectedArea.objects.exists())


class GroupsTest(AreaTestCase):
    def setUp(self):
        super().setUp()
        self.area = self.make_area(targets=('dcim.device',))
        self.user = User.objects.create_user('usera', 'a@example.com')

    def test_writing_brings_reading_a_user_is_in_one_group_and_leaving_the_last_means_no_access(self):
        reading = areas.create_group(self.area, 'dcim.device', 'Reading', ['view'], self.owner1)
        writing = areas.create_group(self.area, 'dcim.device', 'Writing', ['change'], self.owner1)
        self.assertEqual(writing.rights, ['view', 'change'])  # who writes reads
        areas.add_member(reading, self.user, None, self.owner1)
        self.assertTrue(areas.can(self.user, self.area, 'view', 'dcim.device'))
        self.assertFalse(areas.can(self.user, self.area, 'change', 'dcim.device'))
        areas.add_member(writing, self.user, None, self.owner1)
        areas.clear_cache()
        self.user = User.objects.get(pk=self.user.pk)  # a fresh object: a request would have one
        self.assertTrue(areas.can(self.user, self.area, 'change', 'dcim.device'))
        self.assertEqual(areas.group_members(reading), [])  # moved: no need to stay in the reading group
        self.assertEqual([g.user for g in areas.group_members(writing)], [self.user])
        areas.revoke_grant(areas.group_members(writing)[0], self.owner1)  # out of the writing group
        areas.clear_cache()
        self.user = User.objects.get(pk=self.user.pk)
        self.assertFalse(areas.can(self.user, self.area, 'view', 'dcim.device'))  # not recorded anywhere: no access

    def test_group_rules(self):
        with self.assertRaises(ValidationError):
            areas.create_group(self.area, 'dcim.device', '', ['view'], self.owner1)
        with self.assertRaises(ValidationError):
            areas.create_group(self.area, 'dcim.device', 'X', [], self.owner1)
        with self.assertRaises(ValidationError):
            areas.create_group(self.area, 'dcim.site', 'X', ['view'], self.owner1)  # not protected by the area
        with self.assertRaises(PermissionDenied):
            areas.create_group(self.area, 'dcim.device', 'X', ['view'], self.user)
        group = areas.create_group(self.area, 'dcim.device', 'Reading', ['view'], self.owner1)
        with self.assertRaises(ValidationError):
            areas.create_group(self.area, 'dcim.device', 'Reading', ['view'], self.owner1)
        areas.add_member(group, self.user, None, self.owner1)
        with self.assertRaises(ValidationError):
            areas.delete_group(group, self.owner1)  # it has members
        areas.update_group(group, self.owner1, rights=['change'])
        group.refresh_from_db()
        self.assertEqual(group.rights, ['view', 'change'])

    def test_the_page_creates_a_group_and_adds_users(self):
        admin_login(self.client, self.owner1)
        url = reverse('plugins:netbox_user_pin:area', kwargs={'pk': self.area.pk})
        response = self.client.post(url, {'action': 'group-create', 'target': 'dcim.device', 'name': 'Technici',
                                          'rights': ['view', 'change']})
        self.assertEqual(response.status_code, 302, response.content[:300])
        group = AreaProfile.objects.get(name='Technici')
        self.assertEqual((group.target, group.private), ('dcim.device', False))
        response = self.client.post(url, {'action': 'member-add', 'pk': group.pk, 'user': self.user.pk})
        self.assertEqual(response.status_code, 302)
        self.assertEqual([g.user for g in areas.group_members(group)], [self.user])
        html = self.client.get(url).content.decode()
        self.assertIn('Technici', html)
        self.assertIn('usera', html)

    def test_approving_a_request_puts_the_user_into_a_group_or_creates_it(self):
        req = areas.request_target_access(self.user, 'dcim.device', ['view'], 'I need the devices')
        admin_login(self.client, self.owner1)
        url = reverse('plugins:netbox_user_pin:request_decide', kwargs={'pk': req.pk})
        self.assertContains(self.client.get(url), 'A new group')
        response = self.client.post(url, {'action': 'approve', 'group': '', 'group_name': 'Cteni', 'rights': ['view'],
                                          'hours': 0})
        self.assertEqual(response.status_code, 302, response.content[:300])
        group = AreaProfile.objects.get(name='Cteni')
        self.assertEqual([g.user for g in areas.group_members(group)], [self.user])
        # the second user goes into the existing group
        other = User.objects.create_user('userb', 'b@example.com')
        req2 = areas.request_target_access(other, 'dcim.device', ['view'], 'I need the devices too')
        url2 = reverse('plugins:netbox_user_pin:request_decide', kwargs={'pk': req2.pk})
        self.assertContains(self.client.get(url2), 'Cteni')
        self.client.post(url2, {'action': 'approve', 'group': group.pk, 'hours': 0})
        self.assertEqual({g.user for g in areas.group_members(group)}, {self.user, other})


class FirstKeeperTest(AreaTestCase):
    def test_the_first_keeper_switches_the_global_protection_on(self):
        keeper = User.objects.create_superuser('keeper', 'k@example.com', 'x')
        service.set_pin(keeper, GOOD_PIN)
        enable_2fa(keeper)
        self.assertFalse(PinSettings.load().default_deny)
        areas.add_keeper(keeper, self.master)
        self.assertTrue(PinSettings.load().default_deny)
