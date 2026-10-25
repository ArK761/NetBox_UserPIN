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
    AreaFieldRule, AreaGrant, AreaProfile, AreaRequest, AreaRequestStatus, PinEvent, PinEventAction, PinSettings, ProtectedArea,
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
        for owner in (self.owner1, self.owner2):  # an owner decides with a PIN and 2FA
            service.set_pin(owner, GOOD_PIN)
            enable_2fa(owner)
        self.appadmin = User.objects.create_superuser('appadmin', 'a@example.com', 'x')  # superuser, not a network man
        settings = PinSettings.load()
        settings.areas_enabled = True
        settings.save()

    def make_area(self, targets=('dcim.device',), owners=True, max_hours=24):
        areas.clear_cache()
        kept = areas.keepers()
        area = areas.create_area('Network', list(targets), [], kept[0] if kept else self.master, 'network devices',
                                 max_hours)
        if owners:
            areas.add_owner(area, self.owner1, kept[0] if kept else self.master)
            areas.add_owner(area, self.owner2, self.owner1)
        return area

    def profile(self, area, name='Read'):
        """A profile of the old kind (plugins register them): made on demand, areas of their own do not have any."""
        from netbox_user_pin.models import AreaProfile
        rights = dict(areas.DEFAULT_PROFILES).get(name, ('view',))
        return AreaProfile.objects.get_or_create(area=area, name=name, target='', defaults={'rights': list(rights)})[0]

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
        self.make_area()
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
        self.assertContains(self.client.get(reverse('plugins:netbox_user_pin:area', kwargs={'pk': area.pk})), 'Create the group')

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

    def test_default_deny_reaches_queries_permissions_and_system_pages(self):
        self.add_keeper()
        areas.clear_cache()
        master = User.objects.get(pk=self.master.pk)
        from netbox_user_pin import area_guard
        area_guard.arm_user(master)
        self.assertEqual(User.objects.restrict(master, 'view').count(), 0)  # GraphQL, search, widgets ...
        self.assertEqual(User.objects.restrict(self.keeper, 'view').count(), User.objects.count())
        self.assertFalse(master.has_perm('users.view_user'))  # no menu item, no button
        self.login(master, unlock=False)
        self.assertEqual(self.client.get('/core/background-queues/').status_code, 403)

    def test_nobody_special_gets_no_pin_prompt_and_keeps_the_doors(self):
        self.add_keeper()
        areas.clear_cache()
        plain = User.objects.create_user('plainsu', 'ps@example.com', is_superuser=True)
        from netbox_user_pin import area_guard
        plain = User.objects.get(pk=plain.pk)
        area_guard.arm_user(plain)
        self.assertTrue(plain.has_perm('dcim.view_site'))  # the door stays: the page behind it explains and offers a request
        self.assertFalse(plain.has_perm('dcim.add_site'))
        self.assertFalse(plain.has_perm('netbox_user_pin.view_userpin'))  # no administration of PIN for him
        self.login(plain, unlock=False)
        response = self.client.get(reverse('plugins:netbox_user_pin:areas'))
        self.assertRedirects(response, reverse('plugins:netbox_user_pin:my_access'), fetch_redirect_response=False)

    def test_the_server_test_command_reports_what_a_user_gets(self):
        from io import StringIO

        from django.core.management import call_command
        self.add_keeper()
        areas.clear_cache()
        out = StringIO()
        call_command('userpin_access_test', 'master', stdout=out)
        text = out.getvalue()
        self.assertIn('Users (admin)', text)
        self.assertIn('DENIED', text)
        self.assertIn('users.token', text)
        self.assertRegex(text, r'Change password\s+/user/password/\s+OPEN')

    def test_the_server_test_command_walks_every_page(self):
        from io import StringIO

        from django.core.management import call_command
        self.add_keeper()
        areas.clear_cache()
        users_before = User.objects.count()
        out = StringIO()
        call_command('userpin_access_test', 'master', '--all', '--writes', stdout=out)
        text = out.getvalue()
        self.assertIn('EVERY object type', text)
        self.assertIn('WHAT THE USER CAN DO', text)
        self.assertIn('Object types:', text)
        self.assertEqual(User.objects.count(), users_before)  # nothing was saved

    def test_owner_cannot_take_sensitive_or_foreign_types_and_master_cannot_manage_with_keepers(self):
        area = self.make_area(targets=('dcim.device',))
        other = self.make_area(targets=('ipam',), owners=False)
        with self.assertRaises(ValidationError):
            areas.add_target(area, 'users.user', self.owner1)
        with self.assertRaises(ValidationError):
            areas.add_target(area, 'ipam.prefix', self.owner1)
        self.add_keeper()
        areas.clear_cache()
        with self.assertRaises(PermissionDenied):
            areas.delete_area(other, self.master)  # a superuser is no keeper
        areas.add_target(other, 'users.user', self.keeper)  # the keeper sets up what has no owner yet
        areas.delete_area(other, self.keeper)

    def test_nothing_but_the_password_is_left_open_and_scripts_with_a_token_are_not_touched(self):
        from django.test import RequestFactory
        from netbox_user_pin import area_guard
        from users.models import Token
        self.add_keeper()
        areas.clear_cache()
        self.assertEqual(Token.objects.restrict(self.master, 'view').count(), 0)  # tokens: a group that allows them
        factory = RequestFactory()
        self.assertTrue(area_guard._is_token_request(factory.get('/api/dcim/devices/', HTTP_AUTHORIZATION='Token abc')))
        self.assertTrue(area_guard._is_token_request(factory.get('/graphql/', HTTP_AUTHORIZATION='Bearer nbt_x.y')))
        self.assertFalse(area_guard._is_token_request(factory.get('/api/dcim/devices/')))  # a browser session
        self.assertFalse(area_guard._is_token_request(factory.get('/dcim/devices/', HTTP_AUTHORIZATION='Token abc')))
        self.login(self.master, unlock=False)
        self.assertEqual(self.client.get('/user/password/').status_code, 200)  # the one thing that always works
        self.assertEqual(self.client.get('/user/preferences/').status_code, 403)
        self.assertEqual(self.client.get('/user/profile/').status_code, 403)
        self.assertEqual(self.client.get('/user/api-tokens/').status_code, 403)
        self.assertEqual(self.client.get('/user/preferences/').status_code, 403)
        self.assertEqual(self.client.get('/user/profile/').status_code, 403)

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
        self.assertEqual(self.client.get('/user/profile/').status_code, 403)  # only the password change stays open
        self.assertEqual(self.client.get('/user/notifications/').status_code, 403)
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
        from dcim.models import Interface
        Interface.objects.create(device=self.device, name='eth-visible', type='1000base-t')
        self.assertEqual(self.client.get(self.main).status_code, 200)
        response = self.client.get(self.interfaces)  # the allowed tab is the permission: its rows of this device show
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'eth-visible')
        areas.set_grant_tabs(grant, [], self.owner1)
        areas.clear_cache()
        self.assertEqual(self.client.get(self.interfaces).status_code, 403)  # tab not allowed: denied

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
        with self.assertRaises(ValidationError):
            areas.add_owner(area, self.master, self.owner1)  # a superuser decides nothing about himself
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
        reading = areas.create_group(self.area, 'dcim.device', 'Reading', ['view'], self.owner1, records='all')
        writing = areas.create_group(self.area, 'dcim.device', 'Writing', ['change'], self.owner1, records='all')
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
        self.assertEqual(areas.create_group(self.area, 'dcim.device', 'Default', [], self.owner1).rights, ['view'])
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
        response = self.client.post(url, {'action': 'group-create', 'target': 'dcim.device', 'name': 'Technici'})
        self.assertEqual(response.status_code, 302, response.content[:300])
        group = AreaProfile.objects.get(name='Technici')
        self.assertEqual((group.target, group.private, group.rights), ('dcim.device', False, ['view']))
        group_url = reverse('plugins:netbox_user_pin:group', kwargs={'pk': self.area.pk, 'gid': group.pk})
        self.assertEqual(response['Location'], group_url)  # straight into the group
        html = self.client.get(group_url).content.decode()
        self.assertIn('Technici', html)
        self.assertIn('name="tabv__interfaces"', html)
        self.assertIn('name="mode__description"', html)
        self.assertIn('pin-bulk', html)
        # inside the group: rights, tabs, fields and users
        response = self.client.post(group_url, {'action': 'rights', 'name': 'Technici', 'rights': ['change'],
                                                'tab__interfaces': 'on'})
        self.assertEqual(response.status_code, 302)
        group.refresh_from_db()
        self.assertEqual((group.rights, group.tabs), (['view', 'change'], ['interfaces']))
        self.client.post(group_url, {'action': 'fields', 'mode__description': 'hidden', 'mode__name': 'default'})
        self.assertEqual(AreaFieldRule.objects.get(profile=group, field='description').mode, 'hidden')
        other = User.objects.create_user('userb', 'b@example.com')
        response = self.client.post(group_url, {'action': 'member-add', 'users': [self.user.pk, other.pk]})
        self.assertEqual(response.status_code, 302)
        self.assertEqual({g.user for g in areas.group_members(group)}, {self.user, other})  # several at once
        self.assertIn('usera', self.client.get(group_url).content.decode())
        self.assertIn('Technici', self.client.get(url).content.decode())

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


class UnprotectAndOwnersTest(AreaTestCase):
    def test_a_keeper_removes_the_protection_and_an_ineligible_last_owner(self):
        keeper = User.objects.create_superuser('keeper', 'k@example.com', 'x')
        service.set_pin(keeper, GOOD_PIN)
        enable_2fa(keeper)
        areas.add_keeper(keeper, self.master)
        area = self.make_area(owners=False)
        from netbox_user_pin.models import AreaOwner
        AreaOwner.objects.create(area=area, user=keeper)  # a hyperadmin owner (as before the rule existed)
        areas.remove_owner(area, keeper, keeper)  # the last one, but he must not own it
        self.assertFalse(area.owners.exists())
        admin_login(self.client, keeper)
        response = self.client.post(reverse('plugins:netbox_user_pin:areas'), {'action': 'unprotect', 'pk': area.pk})
        self.assertEqual(response.status_code, 302)
        self.assertFalse(ProtectedArea.objects.filter(pk=area.pk).exists())


class SeveralOwnersTest(AreaTestCase):
    def test_several_owners_at_once_and_only_the_eligible_ones(self):
        area = self.make_area(owners=False)
        admin_login(self.client, self.master)
        url = reverse('plugins:netbox_user_pin:area', kwargs={'pk': area.pk})
        plain = User.objects.create_user('plain', 'p@example.com')
        response = self.client.post(url, {'action': 'owner-add', 'users': [self.owner1.pk, self.owner2.pk, plain.pk]})
        self.assertEqual(response.status_code, 302)
        self.assertEqual({o.username for o in areas.owners(area)}, {'owner1', 'owner2'})  # the plain user was refused
        admin_login(self.client, self.owner1)  # an owner sees the owners' form with the list of everybody
        html = self.client.get(url).content.decode()
        self.assertIn('name="users"', html)
        self.assertIn('Has no PIN yet', html)  # the red ones show what blocks them
        self.assertIn('Has 2FA', html)
        self.assertNotIn('Fields hidden from everybody', html)


class KeeperRemovesOwnersTest(AreaTestCase):
    def test_a_keeper_removes_any_owner_even_the_last(self):
        keeper = User.objects.create_superuser('keeper', 'k@example.com', 'x')
        service.set_pin(keeper, GOOD_PIN)
        enable_2fa(keeper)
        areas.add_keeper(keeper, self.master)
        area = self.make_area(owners=False)
        areas.add_owner(area, self.owner1, keeper)
        with self.assertRaises(ValidationError):
            areas.remove_owner(area, self.owner1, self.owner1)  # an owner never removes the last one
        admin_login(self.client, keeper)
        response = self.client.post(reverse('plugins:netbox_user_pin:area', kwargs={'pk': area.pk}),
                                    {'action': 'owner-remove', 'pk': self.owner1.pk})
        self.assertEqual(response.status_code, 302)
        self.assertFalse(area.owners.exists())


class OwnerRequirementsTest(AreaTestCase):
    def test_what_blocks_an_owner_is_listed_and_enforced(self):
        area = self.make_area(owners=False)
        from netbox_user_pin.models import Department, PinDelegate, RoleKind, RoleStatus
        head = User.objects.create_user('head', 'h@example.com')
        PinDelegate.objects.create(user=head, role=RoleKind.HEAD, department=Department.objects.first(),
                                   status=RoleStatus.ACTIVE)
        checks = dict((str(text), ok) for text, ok in areas.owner_requirements(head))
        self.assertEqual(checks['Is a department head, a delegate or a CORE deputy'], True)
        self.assertEqual(checks['Has no PIN yet'], False)
        self.assertEqual(checks['Has no 2FA yet'], False)
        with self.assertRaises(ValidationError):
            areas.add_owner(area, head, self.master)  # no PIN and no 2FA yet
        service.set_pin(head, GOOD_PIN)
        enable_2fa(head)
        areas.add_owner(area, head, self.master)
        self.assertEqual([u.username for u in areas.owners(area)], ['head'])


class DeniedOverviewTest(AreaTestCase):
    def test_the_refusal_says_what_the_user_is_allowed_and_why_the_linked_type_is_closed(self):
        from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site
        area = self.make_area(targets=('dcim.device',))
        user = User.objects.create_user('usera', 'a@example.com')
        group = areas.create_group(area, 'dcim.device', 'Technici', ['view'], self.owner1, records='all')
        areas.add_member(group, user, None, self.owner1)
        fields = {'name': ('hidden', ''), 'description': ('hidden', ''), 'comments': ('hidden', '')}
        areas.save_field_rules(area, group, 'dcim.device', {**fields, 'role': ('read', '')}, self.owner1)
        areas.clear_cache()
        # the Device role is no area of any kind: with the default deny on it is refused
        keeper = User.objects.create_superuser('keeper', 'k@example.com', 'x')
        service.set_pin(keeper, GOOD_PIN)
        enable_2fa(keeper)
        areas.add_keeper(keeper, self.master)
        areas.clear_cache()
        role = DeviceRole.objects.create(name='R1', slug='r1', color='ff0000')
        self.login(user)
        response = self.client.get(f'/dcim/device-roles/{role.pk}/')
        self.assertEqual(response.status_code, 403)
        html = response.content.decode()
        self.assertIn('What you are allowed', html)
        self.assertIn('Technici', html)
        self.assertIn('Role', html)  # the field that is allowed
        self.assertIn('is not allowed to you', html)  # Device role is only the value of the Role field
        self.assertIn('Ask the administrator', html)
        self.assertIn('Show DCIM &gt; Device role', html)  # offered in the request
        self.assertLess(html.index('What you are allowed'), html.index('Access denied'))  # the overview is on top


class RowConditionsTest(AreaTestCase):
    def setUp(self):
        super().setUp()
        from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site
        site = Site.objects.create(name='S1', slug='s1')
        maker = Manufacturer.objects.create(name='M1', slug='m1')
        dtype = DeviceType.objects.create(manufacturer=maker, model='T1', slug='t1')
        self.role1 = DeviceRole.objects.create(name='Switch', slug='switch', color='ff0000')
        self.role2 = DeviceRole.objects.create(name='Router', slug='router', color='00ff00')
        self.Device = Device
        Device.objects.create(name='AGG_01', site=site, device_type=dtype, role=self.role1)
        Device.objects.create(name='AGG_02', site=site, device_type=dtype, role=self.role2)
        Device.objects.create(name='PRINTER_1', site=site, device_type=dtype, role=self.role1)
        self.area = self.make_area(targets=('dcim.device',))
        self.group = areas.create_group(self.area, 'dcim.device', 'Technici', ['view'], self.owner1, records='all')
        self.user = User.objects.create_user('usera', 'a@example.com')
        areas.add_member(self.group, self.user, None, self.owner1)

    def names(self):
        areas.clear_cache()
        user = User.objects.get(pk=self.user.pk)
        query = areas.row_filter(user, self.area, 'dcim', 'device')
        if query is None:
            return []
        return sorted(self.Device.objects.filter(query).values_list('name', flat=True))

    def test_allowed_and_denied_records_never_conflict_and_a_deny_wins(self):
        areas.add_group_condition(self.group, self.owner1, 'name', 'contains', ['agg'])
        self.assertEqual(self.names(), ['AGG_01', 'AGG_02'])
        with self.assertRaises(ValidationError):  # the same value cannot be allowed and denied
            areas.add_group_condition(self.group, self.owner1, 'name', 'contains', ['AGG'], deny=True)
        areas.add_group_condition(self.group, self.owner1, 'name', 'contains', ['_02'], deny=True)
        self.assertEqual(self.names(), ['AGG_01'])  # the deny hides what the allowance lets in
        with self.assertRaises(ValidationError):
            areas.add_group_condition(self.group, self.owner1, 'name', 'contains', ['_02'])  # denied already
        self.assertEqual([t for _i, t, _f in areas.group_deny_conditions(self.group)], ['Name contains _02'])
        areas.set_group_records(self.group, self.owner1, 'all')
        self.assertEqual(self.names(), ['AGG_01', 'PRINTER_1'])  # a deny works with "all records" as well
        areas.remove_group_condition(self.group, self.owner1, 0, deny=True)
        self.assertEqual(self.names(), ['AGG_01', 'AGG_02', 'PRINTER_1'])

    def test_a_group_that_is_not_set_sees_no_record_and_a_deny_of_an_operation_wins(self):
        fresh = areas.create_group(self.area, 'dcim.device', 'Nova', ['view'], self.owner1)  # no records chosen
        other = User.objects.create_user('userz', 'z@example.com')
        areas.add_member(fresh, other, None, self.owner1)
        areas.clear_cache()
        other = User.objects.get(pk=other.pk)
        self.assertEqual((fresh.records, areas.row_filter(other, self.area, 'dcim', 'device')), ('unset', None))
        areas.set_group_records(fresh, self.owner1, 'all')
        areas.update_group(fresh, self.owner1, rights=['view', 'change', 'delete'], denied=['delete'])
        areas.clear_cache()
        self.assertEqual(areas.rights_of(other, self.area, 'dcim.device'), {'view', 'change'})  # the deny wins
        self.assertIsNotNone(areas.row_filter(other, self.area, 'dcim', 'device'))
        self.assertIsNone(areas.row_filter(other, self.area, 'dcim', 'device', 'delete'))
        areas.update_group(fresh, self.owner1, denied=['view'])  # who may not read, may not do anything
        areas.clear_cache()
        self.assertEqual(areas.rights_of(other, self.area, 'dcim.device'), set())

    def test_without_a_right_only_the_door_stays_not_the_buttons(self):
        stranger = User.objects.create_user('stranger', 's@example.com')
        areas.clear_cache()
        stranger = User.objects.get(pk=stranger.pk)
        area_guard.arm_user(stranger)
        self.assertTrue(stranger.has_perm('dcim.view_device'))  # the menu item: the request page is behind it
        for action in ('add', 'change', 'delete'):
            self.assertFalse(stranger.has_perm(f'dcim.{action}_device'), action)

    def test_two_is_conditions_of_one_field_are_alternatives_not_an_empty_set(self):
        areas.add_group_condition(self.group, self.owner1, 'role', 'eq', [str(self.role1.pk)])
        areas.add_group_condition(self.group, self.owner1, 'role', 'eq', [str(self.role2.pk)])  # Switch OR Router
        self.group.refresh_from_db()
        spec = self.group.filters['dcim.device']
        self.assertEqual((len(spec), spec[0]['op']), (1, 'in'))
        self.assertEqual(self.names(), ['AGG_01', 'AGG_02', 'PRINTER_1'])
        areas.remove_group_condition(self.group, self.owner1, 0)
        areas.add_group_condition(self.group, self.owner1, 'role', 'ne', [str(self.role1.pk)])
        areas.add_group_condition(self.group, self.owner1, 'role', 'ne', [str(self.role2.pk)])  # neither of them
        self.group.refresh_from_db()
        self.assertEqual((len(self.group.filters['dcim.device']), self.group.filters['dcim.device'][0]['op']),
                         (1, 'nin'))
        self.assertEqual(self.names(), [])

    def test_migration_repairs_conditions_saved_as_two(self):
        import importlib

        from django.apps import apps as django_apps
        self.group.filters = {'dcim.device': [
            {'op': 'eq', 'field': 'role', 'value': str(self.role1.pk)},
            {'op': 'eq', 'field': 'role', 'value': str(self.role2.pk)},
            {'op': 'contains', 'field': 'name', 'value': 'agg'}]}
        self.group.records = 'filtered'
        self.group.save()
        self.assertEqual(self.names(), [])  # the situation of the user: two "is" conditions see nothing
        importlib.import_module('netbox_user_pin.migrations.0024_merge_same_field_conditions').merge(django_apps, None)
        self.group.refresh_from_db()
        self.assertEqual(len(self.group.filters['dcim.device']), 2)
        self.assertEqual(self.names(), ['AGG_01', 'AGG_02'])  # (Switch or Router) and name contains agg

    def test_values_of_one_condition_are_alternatives_and_the_group_page_sets_the_access(self):
        from dcim.models import Device
        site = Device.objects.first().site
        Device.objects.create(name='CORE_X', site=site, device_type=Device.objects.first().device_type,
                              role=self.role1)
        areas.add_group_condition(self.group, self.owner1, 'name', 'contains', ['agg'])
        areas.add_group_condition(self.group, self.owner1, 'name', 'contains', ['core'])  # one more value, not a rule
        self.group.refresh_from_db()
        self.assertEqual(len(self.group.filters['dcim.device']), 1)
        self.assertEqual(self.group.filters['dcim.device'][0]['value'], ['agg', 'core'])
        self.assertEqual(self.names(), ['AGG_01', 'AGG_02', 'CORE_X'])  # agg OR core
        self.assertIn('agg / core', areas.format_filters(self.group.filters))
        areas.add_group_condition(self.group, self.owner1, 'role', 'eq', [str(self.role1.pk)])  # another one: AND
        self.assertEqual(self.names(), ['AGG_01', 'CORE_X'])
        # the page of the group: access level, delete, tabs, chips
        admin_login(self.client, self.owner1)
        url = reverse('plugins:netbox_user_pin:group', kwargs={'pk': self.area.pk, 'gid': self.group.pk})
        html = self.client.get(url).content.decode()
        for marker in ('name="access"', 'name="tabv__interfaces"', 'pin-rule-form-allow', 'name="mode__name"',
                       'agg / core'):
            self.assertIn(marker, html)
        self.client.post(url, {'action': 'rights', 'name': 'Technici', 'access': 'write', 'delete': 'on'})
        self.group.refresh_from_db()
        self.assertEqual(self.group.rights, ['view', 'add', 'change', 'delete'])
        self.client.post(url, {'action': 'rights', 'name': 'Technici', 'access': 'read', 'tabv__interfaces': 'yes',
                               'tabv__journal': 'no'})
        self.group.refresh_from_db()
        self.assertEqual((self.group.rights, self.group.tabs), (['view'], ['interfaces']))
        self.client.post(url, {'action': 'rights', 'name': 'Technici', 'access': 'none'})
        self.group.refresh_from_db()
        self.assertEqual(self.group.rights, [])
        html = self.client.get(url).content.decode()
        self.assertNotIn('id="pin-rule-form-allow"', html)  # a group that sees nothing has nothing more to set
        areas.clear_cache()
        self.assertFalse(areas.can(User.objects.get(pk=self.user.pk), self.area, 'view', 'dcim.device'))

    def test_hiding_tags_does_not_break_the_edit_page(self):
        from tenancy.models import Tenant
        keeper = User.objects.create_superuser('keeper4', 'k4@example.com', 'x')
        service.set_pin(keeper, GOOD_PIN)
        enable_2fa(keeper)
        areas.add_keeper(keeper, self.master)
        area = areas.create_area('Tenants', ['tenancy.tenant'], [], keeper)
        areas.add_owner(area, self.owner1, keeper)
        group = areas.create_group(area, 'tenancy.tenant', 'Evidencia', ['view'], self.owner1, records='all')
        areas.update_group(group, self.owner1, rights=['view', 'change', 'add'])
        areas.add_member(group, self.user, None, self.owner1)
        tenant = Tenant.objects.create(name='T2', slug='t2')
        self.login(self.user)
        self.client.raise_request_exception = True
        for hidden in ('tags', 'group', 'description', 'slug', 'comments'):
            areas.save_field_rules(area, group, 'tenancy.tenant', {hidden: ('hidden', '')}, self.owner1)
            areas.clear_cache()
            for url in (f'/tenancy/tenants/{tenant.pk}/edit/', '/tenancy/tenants/add/', f'/tenancy/tenants/{tenant.pk}/'):
                self.assertEqual(self.client.get(url).status_code, 200, (hidden, url))
            areas.save_field_rules(area, group, 'tenancy.tenant', {hidden: ('default', '')}, self.owner1)

    def test_saving_a_tenant_with_custom_fields_and_rules_does_not_fail(self):
        from core.models import ObjectType
        from dcim.models import DeviceType
        from extras.models import CustomField, CustomFieldChoiceSet
        from tenancy.models import Tenant
        keeper = User.objects.create_superuser('keeper3', 'k3@example.com', 'x')
        service.set_pin(keeper, GOOD_PIN)
        enable_2fa(keeper)
        areas.add_keeper(keeper, self.master)
        area = areas.create_area('Tenants', ['tenancy.tenant'], [], keeper)
        areas.add_owner(area, self.owner1, keeper)
        group = areas.create_group(area, 'tenancy.tenant', 'Evidencia', ['view'], self.owner1, records='all')
        areas.update_group(group, self.owner1, rights=['view', 'change'])
        areas.add_member(group, self.user, None, self.owner1)
        tenant_type = ObjectType.objects.get_for_model(Tenant)
        choices = CustomFieldChoiceSet.objects.create(name='CS-t', extra_choices=[['a', 'A']])
        for name, kind, extra in (('hw', 'object', {'related_object_type': ObjectType.objects.get_for_model(DeviceType)}),
                                  ('pw', 'select', {'choice_set': choices}), ('sn', 'text', {})):
            field = CustomField.objects.create(name=name, type=kind, **extra)
            field.object_types.set([tenant_type])
        areas.save_field_rules(area, group, 'tenancy.tenant', {'cf:hw': ('write', 'Print'), 'cf:sn': ('read', ''),
                                                               'group': ('write', 'Z')}, self.owner1)
        areas.clear_cache()
        tenant = Tenant.objects.create(name='T1', slug='t1')
        self.login(self.user)
        self.client.raise_request_exception = True
        page = self.client.get(f'/tenancy/tenants/{tenant.pk}/edit/')
        self.assertEqual(page.status_code, 200)
        response = self.client.post(f'/tenancy/tenants/{tenant.pk}/edit/', {'name': 'T1', 'slug': 't1',
                                                                              'cf_pw': 'a'})
        self.assertIn(response.status_code, (200, 302))
        response = self.client.post(f'/tenancy/tenants/{tenant.pk}/edit/', {})
        self.assertIn(response.status_code, (200, 302))
        # choosing a value of a relation field: the one the rule allows is saved, another is refused - and neither is
        # "not one of the available choices" because of the closed type
        from dcim.models import Manufacturer
        from tenancy.models import TenantGroup
        zeta = TenantGroup.objects.create(name='Zeta', slug='zeta')
        alfa = TenantGroup.objects.create(name='Alfa', slug='alfa')
        maker = Manufacturer.objects.create(name='Mk', slug='mk')
        printer = DeviceType.objects.create(manufacturer=maker, model='Printer 1', slug='printer-1')
        router = DeviceType.objects.create(manufacturer=maker, model='Router 1', slug='router-1')
        url = f'/tenancy/tenants/{tenant.pk}/edit/'
        response = self.client.post(url, {'name': 'T1', 'slug': 't1', 'group': zeta.pk, 'cf_hw': printer.pk})
        self.assertEqual(response.status_code, 302, str(response.context['form'].errors if response.context else ''))
        tenant.refresh_from_db()
        self.assertEqual((tenant.group_id, tenant.custom_field_data.get('hw')), (zeta.pk, printer.pk))
        response = self.client.post(url, {'name': 'T1', 'slug': 't1', 'group': alfa.pk, 'cf_hw': router.pk})
        self.assertEqual(response.status_code, 200)  # refused: the form is shown again with the errors
        tenant.refresh_from_db()
        self.assertEqual((tenant.group_id, tenant.custom_field_data.get('hw')), (zeta.pk, printer.pk))

    def test_picking_in_a_relation_field_opens_only_the_drop_down(self):
        from dcim.models import DeviceRole, Site
        keeper = User.objects.create_superuser('keeper2', 'k2@example.com', 'x')
        service.set_pin(keeper, GOOD_PIN)
        enable_2fa(keeper)
        areas.add_keeper(keeper, self.master)  # the first keeper switches "deny everything not allowed" on
        DeviceRole.objects.create(name='Printer role', slug='printer-role', color='ff0000')
        Site.objects.create(name='S2', slug='s2')
        areas.update_group(self.group, self.owner1, name='Technici', rights=['view', 'change'])
        areas.save_field_rules(self.area, self.group, 'dcim.device', {'role': ('write', 'Print')}, self.owner1)
        areas.clear_cache()
        self.login(self.user)
        api = {'HTTP_ACCEPT': 'application/json'}
        response = self.client.get('/api/dcim/device-roles/?brief=true', **api)
        self.assertEqual(response.status_code, 200)
        names = [r['name'] for r in response.json()['results']]
        self.assertEqual(names, ['Printer role'])  # only what the rule allows to pick (Switch and Router are not)
        self.assertEqual(self.client.get('/api/dcim/device-roles/', **api).status_code, 403)  # not a list of the type
        self.assertEqual(self.client.get('/api/dcim/device-roles/?brief=true&fields=slug', **api).status_code, 403)
        self.assertEqual(self.client.get('/dcim/device-roles/').status_code, 403)  # its pages stay closed
        sites = self.client.get('/api/dcim/sites/?brief=true', **api)  # a relation without a text: all of the type
        self.assertEqual((sites.status_code, sites.json()['count']), (200, Site.objects.count()))
        self.assertEqual(self.client.get('/api/ipam/vlans/?brief=true', **api).status_code, 403)  # not a field of his
        from io import StringIO

        from django.core.management import call_command
        out = StringIO()
        call_command('userpin_access_test', self.user.username, stdout=out)
        report = out.getvalue()
        self.assertIn('What the user may PICK', report)
        self.assertRegex(report, r'dcim.devicerole\s+drop-down: only names containing Print\s+gives 1 of 3')
        # the values of a select custom field he may write fill its drop-down; of one he only reads they do not
        from core.models import ObjectType
        from dcim.models import Device
        from extras.models import CustomField, CustomFieldChoiceSet
        writable = CustomFieldChoiceSet.objects.create(name='CS-write', extra_choices=[['a', 'A'], ['b', 'B']])
        readonly = CustomFieldChoiceSet.objects.create(name='CS-read', extra_choices=[['x', 'X']])
        for name, choice_set in (('pw', writable), ('ro', readonly)):
            field = CustomField.objects.create(name=name, type='select', choice_set=choice_set)
            field.object_types.set([ObjectType.objects.get_for_model(Device)])
        areas.save_field_rules(self.area, self.group, 'dcim.device', {'role': ('write', 'Print'), 'cf:ro': ('read', '')},
                               self.owner1)
        areas.clear_cache()
        values = self.client.get(f'/api/extras/custom-field-choice-sets/{writable.pk}/choices/', **api)
        self.assertEqual(values.status_code, 200)
        self.assertEqual(self.client.get(f'/api/extras/custom-field-choice-sets/{readonly.pk}/choices/', **api).status_code,
                         403)
        self.assertEqual(self.client.get(f'/api/extras/custom-field-choice-sets/{writable.pk}/', **api).status_code, 403)
        # a group that only reads picks nothing
        areas.update_group(self.group, self.owner1, name='Technici', rights=['view'])
        areas.clear_cache()
        self.assertEqual(self.client.get('/api/dcim/device-roles/?brief=true', **api).status_code, 403)

    def test_changelog_hides_rows_of_objects_the_user_may_not_view(self):
        from core.models import ObjectChange
        outsider = User.objects.create_user('outsider', 'x@example.com')
        areas.clear_cache()
        hidden = areas.unseen_objects(outsider, 'core', 'objectchange')
        self.assertIsNotNone(hidden)
        self.assertIn('changed_object_type__app_label', str(hidden))
        self.assertIsNone(areas.unseen_objects(self.user, 'core', 'objectchange'))  # a member sees them
        self.assertEqual(ObjectChange.objects.restrict(self.master, 'view').filter(
            changed_object_type__app_label='dcim', changed_object_type__model='device').count(), 0)

    def test_superuser_member_sees_only_matching_rows_through_restrict(self):
        boss = User.objects.create_user('boss', 'b@example.com', is_superuser=True)
        areas.add_member(self.group, boss, None, self.owner1)
        areas.add_group_condition(self.group, self.owner1, 'name', 'contains', ['agg'])
        areas.clear_cache()
        boss = User.objects.get(pk=boss.pk)
        self.assertEqual(sorted(self.Device.objects.restrict(boss, 'view').values_list('name', flat=True)),
                         ['AGG_01', 'AGG_02'])

    def test_conditions_is_is_not_contains_starts_with_is_one_of(self):
        self.assertEqual(self.names(), ['AGG_01', 'AGG_02', 'PRINTER_1'])  # no condition: everything
        areas.add_group_condition(self.group, self.owner1, 'role', 'eq', [str(self.role1.pk)])
        self.assertEqual(self.names(), ['AGG_01', 'PRINTER_1'])
        areas.add_group_condition(self.group, self.owner1, 'name', 'startswith', ['printer'])  # all must hold
        self.assertEqual(self.names(), ['PRINTER_1'])
        areas.remove_group_condition(self.group, self.owner1, 0)
        areas.remove_group_condition(self.group, self.owner1, 0)
        self.assertEqual(self.names(), [])  # a filter without a condition is nothing, never everything
        areas.set_group_records(self.group, self.owner1, 'all')  # everything has to be chosen
        self.assertEqual(self.names(), ['AGG_01', 'AGG_02', 'PRINTER_1'])
        areas.add_group_condition(self.group, self.owner1, 'role', 'ne', [str(self.role1.pk)])  # must not equal
        self.assertEqual(self.names(), ['AGG_02'])
        areas.remove_group_condition(self.group, self.owner1, 0)
        areas.add_group_condition(self.group, self.owner1, 'name', 'ncontains', ['AGG'])
        self.assertEqual(self.names(), ['PRINTER_1'])
        areas.remove_group_condition(self.group, self.owner1, 0)
        areas.add_group_condition(self.group, self.owner1, 'role', 'in', [str(self.role1.pk), str(self.role2.pk)])
        self.assertEqual(self.names(), ['AGG_01', 'AGG_02', 'PRINTER_1'])
        areas.remove_group_condition(self.group, self.owner1, 0)
        areas.add_group_condition(self.group, self.owner1, 'role', 'nin', [str(self.role1.pk), str(self.role2.pk)])
        self.assertEqual(self.names(), [])
        areas.remove_group_condition(self.group, self.owner1, 0)
        # a relation by a text: the name of the related object, whatever is written
        areas.add_group_condition(self.group, self.owner1, 'role', 'contains', ['swit'])
        self.assertEqual(self.names(), ['AGG_01', 'PRINTER_1'])
        areas.remove_group_condition(self.group, self.owner1, 0)
        areas.add_group_condition(self.group, self.owner1, 'role', 'eq', ['router'])
        self.assertEqual(self.names(), ['AGG_02'])
        self.assertIn('Role is router', [text for _i, text, _f in areas.group_conditions(self.group)])

    def test_texts_ignore_the_case_and_contains_means_anywhere_in_the_name(self):
        areas.add_group_condition(self.group, self.owner1, 'name', 'contains', ['gg_0'])  # in the middle, small letters
        self.assertEqual(self.names(), ['AGG_01', 'AGG_02'])
        areas.remove_group_condition(self.group, self.owner1, 0)
        areas.add_group_condition(self.group, self.owner1, 'name', 'eq', ['agg_01'])
        self.assertEqual(self.names(), ['AGG_01'])
        areas.remove_group_condition(self.group, self.owner1, 0)
        areas.add_group_condition(self.group, self.owner1, 'name', 'in', ['agg_01', 'printer_1'])
        self.assertEqual(self.names(), ['AGG_01', 'PRINTER_1'])

    def test_a_member_with_another_access_without_a_condition_is_marked(self):
        areas.add_group_condition(self.group, self.owner1, 'name', 'contains', ['agg'])
        areas.grant_custom(self.area, self.user, 'dcim.device', ['view'], None, self.owner1)  # sees everything
        self.assertEqual(self.names(), ['AGG_01', 'AGG_02', 'PRINTER_1'])  # one access without a condition shows all
        admin_login(self.client, self.owner1)
        html = self.client.get(reverse('plugins:netbox_user_pin:group', kwargs={
            'pk': self.area.pk, 'gid': self.group.pk})).content.decode()
        self.assertIn('mdi-alert', html)

    def test_an_area_of_the_type_wins_over_one_of_the_whole_app(self):
        broad = areas.create_area('All of DCIM', ['dcim'], [], self.master)
        self.assertEqual(areas.area_for('dcim', 'device', package='dcim'), self.area)  # the type-level one
        self.assertEqual(areas.area_for('dcim', 'site', package='dcim'), broad)

    def test_invalid_conditions_and_permissions(self):
        for field, op, values in (('nonsense', 'eq', ['x']), ('name', 'nonsense', ['x']), ('name', 'eq', []),
                                  ('site', 'startswith', [''])):
            with self.assertRaises(ValidationError):
                areas.add_group_condition(self.group, self.owner1, field, op, values)
        with self.assertRaises(PermissionDenied):
            areas.add_group_condition(self.group, self.user, 'name', 'eq', ['x'])

    def test_the_page_lists_adds_and_removes_conditions(self):
        areas.set_group_records(self.group, self.owner1, 'filtered')
        admin_login(self.client, self.owner1)
        url = reverse('plugins:netbox_user_pin:group', kwargs={'pk': self.area.pk, 'gid': self.group.pk})
        html = self.client.get(url).content.decode()
        self.assertIn('id="pin-rule-form-allow"', html)  # one place for the conditions of the records
        self.assertIn('id="pin-rule-form-deny"', html)
        response = self.client.post(url, {'action': 'rule-add', 'field': 'role', 'op': 'ne', 'values': [self.role1.pk]})
        self.assertEqual(response.status_code, 302, response.content[:300])
        self.assertTrue(response['Location'].endswith('#pin-rule-form'))
        html = self.client.get(url).content.decode()
        self.assertIn('Role is not Switch', html)
        self.assertIn('pin-filter-fields', html)
        self.assertIn('form="rd-0"', html)  # the condition can be removed
        self.client.post(url, {'action': 'rule-delete', 'index': 0})
        self.assertNotIn('Role is not Switch', self.client.get(url).content.decode())


class PluginMenuByRolesTest(AreaTestCase):
    def test_the_administration_follows_the_roles_in_the_pin_not_the_netbox_permissions(self):
        from django.contrib.contenttypes.models import ContentType
        from users.models import ObjectPermission

        from netbox_user_pin.models import UserPin
        user = User.objects.create_user('netboxadmin', 'n@example.com')
        permission = ObjectPermission.objects.create(name='all of the PIN', actions=['view'])
        permission.object_types.add(ContentType.objects.get_for_model(UserPin))
        permission.users.add(user)
        self.assertTrue(user.has_perm('netbox_user_pin.view_userpin'))  # NetBox alone would show the menu
        area_guard.arm_user(user)
        self.assertFalse(user.has_perm('netbox_user_pin.view_userpin'))  # no role in the PIN: no administration
        head = User.objects.get(pk=self.owner1.pk)  # a department head
        area_guard.arm_user(head)
        self.assertTrue(head.has_perm('netbox_user_pin.view_userpin'))
        self.assertFalse(head.has_perm('netbox_user_pin.view_pinsettings'))  # the settings are for CORE
        master = User.objects.get(pk=self.master.pk)
        area_guard.arm_user(master)
        self.assertTrue(master.has_perm('netbox_user_pin.view_pinsettings'))


class HiddenFieldPathsTest(AreaTestCase):
    """Step 1: a hidden or read-only field is protected on every path, not only on the detail page."""

    def setUp(self):
        super().setUp()
        from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site
        from extras.models import CustomField
        from core.models import ObjectType
        site = Site.objects.create(name='S1', slug='s1')
        dtype = DeviceType.objects.create(manufacturer=Manufacturer.objects.create(name='M1', slug='m1'),
                                          model='T1', slug='t1')
        role = DeviceRole.objects.create(name='R1', slug='r1', color='ff0000')
        self.Device = Device
        self.secret = Device.objects.create(name='DEV_A', site=site, device_type=dtype, role=role,
                                            description='TOPSECRET', comments='visible')
        self.other = Device.objects.create(name='DEV_B', site=site, device_type=dtype, role=role,
                                           description='plain')
        field = CustomField.objects.create(name='ro', type='text')
        field.object_types.set([ObjectType.objects.get_for_model(Device)])
        self.area = self.make_area(targets=('dcim.device',))
        self.group = areas.create_group(self.area, 'dcim.device', 'Technici', ['view'], self.owner1, records='all')
        areas.update_group(self.group, self.owner1, rights=['view', 'add', 'change', 'delete'])
        self.user = User.objects.create_user('usera', 'a@example.com')
        areas.add_member(self.group, self.user, None, self.owner1)
        areas.save_field_rules(self.area, self.group, 'dcim.device',
                               {'description': ('hidden', ''), 'comments': ('read', ''), 'cf:ro': ('read', '')},
                               self.owner1)
        areas.clear_cache()
        self.login(self.user)
        self.json = {'HTTP_ACCEPT': 'application/json'}

    def test_bulk_edit_form_has_neither_the_hidden_nor_the_read_only_field(self):
        url = '/dcim/devices/edit/'
        html = self.client.post(url, {'pk': [self.secret.pk, self.other.pk], '_edit': ''}).content.decode()
        self.assertIn('name="status"', html)
        self.assertNotIn('name="description"', html)  # hidden
        self.assertNotIn('name="comments"', html)  # read only: nothing to set for many objects
        self.assertNotIn('cf_ro', html)
        self.client.post(url, {'pk': [self.secret.pk, self.other.pk], '_apply': '', 'description': 'HACKED',
                               'comments': 'HACKED', 'cf_ro': 'HACKED'})
        self.secret.refresh_from_db()
        self.other.refresh_from_db()
        self.assertEqual((self.secret.description, self.other.description), ('TOPSECRET', 'plain'))
        self.assertNotEqual(self.secret.comments, 'HACKED')
        self.assertNotIn('ro', self.secret.custom_field_data or {})

    def test_exports_do_not_show_the_hidden_field(self):
        self.assertEqual(self.client.get('/dcim/devices/?export=').status_code, 403)  # YAML: every field
        self.assertEqual(self.client.get('/dcim/devices/?export=anything').status_code, 403)  # an export template
        response = self.client.get('/dcim/devices/?export=table')
        self.assertEqual(response.status_code, 200)
        body = b''.join(response.streaming_content) if response.streaming else response.content
        self.assertIn(b'DEV_A', body)
        self.assertNotIn(b'TOPSECRET', body)

    def test_lists_cannot_be_filtered_or_searched_by_a_hidden_field(self):
        for query in ('description=TOPSECRET', 'description__ic=secret', 'q=TOPSECRET'):
            html = self.client.get(f'/dcim/devices/?{query}').content.decode()
            self.assertIn('DEV_A', html, query)
            self.assertIn('DEV_B', html, query)  # the filter is ignored, so it tells nothing
        self.assertNotIn('TOPSECRET', self.client.get('/dcim/devices/').content.decode())
        api = self.client.get('/api/dcim/devices/?description=TOPSECRET', **self.json).json()
        self.assertEqual(api['count'], 2)
        self.assertNotIn('description', api['results'][0])

    def test_changelog_and_search_do_not_tell_the_hidden_value(self):
        from netbox.search.backends import search_backend
        from netbox_user_pin import fieldrules
        user = User.objects.get(pk=self.user.pk)
        self.assertEqual(fieldrules.hidden_by_type(user), {'dcim.device': {'description'}})
        hidden = areas.unseen_objects(user, 'core', 'objectchange')
        self.assertIn('changed_object_type__model', str(hidden))
        search_backend.cache([self.secret, self.other])
        self.assertEqual(len(search_backend.search('TOPSECRET', user=user)), 0)
        sees = User.objects.create_user('userc', 'c@example.com')  # a group without the hidden-field rule
        other = areas.create_group(self.area, 'dcim.device', 'Vsetko', ['view'], self.owner1, records='all')
        areas.add_member(other, sees, None, self.owner1)
        areas.clear_cache()
        self.assertGreaterEqual(len(search_backend.search('TOPSECRET', user=sees)), 1)

    def test_graphql_in_the_browser_is_closed_while_a_field_is_hidden(self):
        body = {'query': '{ __typename }'}
        response = self.client.post('/graphql/', body, content_type='application/json')
        self.assertEqual((response.status_code, response.headers.get('X-UserPIN')), (403, 'denied'))
        scripted = self.client.post('/graphql/', body, content_type='application/json', HTTP_AUTHORIZATION='Token x')
        self.assertNotEqual(scripted.headers.get('X-UserPIN'), 'denied')  # a script with a token is not ours to judge

    def test_api_refuses_to_write_a_read_only_custom_field_and_a_text_rule(self):
        url = f'/api/dcim/devices/{self.other.pk}/'
        response = self.client.patch(url, {'custom_fields': {'ro': 'new'}}, content_type='application/json', **self.json)
        self.assertEqual(response.status_code, 400, response.content[:300])
        self.other.refresh_from_db()
        self.assertNotIn('ro', self.other.custom_field_data or {})
        response = self.client.patch(url, {'custom_fields': {'ro': None}}, content_type='application/json', **self.json)
        self.assertEqual(response.status_code, 200, response.content[:300])  # echoing what is there is no change
        response = self.client.patch(url, {'name': 'DEV_B2'}, content_type='application/json', **self.json)
        self.assertEqual(response.status_code, 200)  # an allowed field is written
        response = self.client.patch(url, {'description': 'x'}, content_type='application/json', **self.json)
        self.other.refresh_from_db()
        self.assertEqual(self.other.description, 'plain')  # the hidden field is not even a field of the API

    def test_a_rule_that_hides_a_field_wins_over_a_write_of_another_source(self):
        from netbox_user_pin import fieldrules
        grant = areas.grant_custom(self.area, self.user, 'dcim.device', ['view', 'change'], None, self.owner1)
        areas.save_field_rules(self.area, grant.profile, 'dcim.device', {'description': ('write', '')}, self.owner1)
        areas.clear_cache()
        policy = fieldrules.compute_policy(User.objects.get(pk=self.user.pk), self.area, 'dcim', 'device')
        self.assertEqual(policy.mode('description'), 'hidden')  # the group hides it, the entry writes it: hidden
        self.assertEqual(policy.mode('comments'), 'read')  # the group reads it, nobody writes it
        areas.save_field_rules(self.area, grant.profile, 'dcim.device', {'comments': ('write', '')}, self.owner1)
        areas.clear_cache()
        policy = fieldrules.compute_policy(User.objects.get(pk=self.user.pk), self.area, 'dcim', 'device')
        self.assertEqual(policy.mode('comments'), 'read')  # read only from one source is not overridden by a write

    def test_hiding_any_single_field_never_breaks_the_edit_page_of_a_device(self):
        from netbox_user_pin import fieldrules
        self.client.raise_request_exception = True
        self.maxDiff = None
        broken = []
        for key, _label, kind in fieldrules.fields_of('dcim', 'device'):
            if kind != 'field':
                continue
            areas.save_field_rules(self.area, self.group, 'dcim.device', {key: ('hidden', '')}, self.owner1)
            areas.clear_cache()
            for url in (f'/dcim/devices/{self.other.pk}/edit/', f'/dcim/devices/{self.other.pk}/', '/dcim/devices/'):
                try:
                    status = self.client.get(url).status_code
                except Exception as exc:  # noqa: BLE001
                    import traceback
                    status = repr(exc)[:100] + ' @ ' + ' | '.join(traceback.format_exc().splitlines()[-7:-1])[:700]
                if status != 200:
                    broken.append((key, url, status))
            areas.save_field_rules(self.area, self.group, 'dcim.device', {key: ('default', '')}, self.owner1)
        self.assertEqual(broken, [])

    def test_a_text_is_kept_whatever_the_mode_of_the_field_is(self):
        from netbox_user_pin import fieldrules
        from netbox_user_pin.models import AreaFieldRule
        areas.save_field_rules(self.area, self.group, 'dcim.device', {'role': ('default', 'Print')}, self.owner1)
        rule = AreaFieldRule.objects.get(profile=self.group, field='role')
        self.assertEqual((rule.mode, rule.contains), ('default', 'Print'))  # "by rights" does not drop the text
        areas.clear_cache()
        policy = fieldrules.compute_policy(User.objects.get(pk=self.user.pk), self.area, 'dcim', 'device')
        self.assertEqual((policy.mode('role'), policy.texts('role')), ('write', ['Print']))  # the rights decide
        areas.save_field_rules(self.area, self.group, 'dcim.device', {'role': ('default', '')}, self.owner1)
        self.assertFalse(AreaFieldRule.objects.filter(profile=self.group, field='role').exists())

    def test_hiding_any_single_field_never_breaks_the_edit_page_of_a_device(self):
        from netbox_user_pin import fieldrules
        self.client.raise_request_exception = True
        broken = []
        for key, _label, kind in fieldrules.fields_of('dcim', 'device'):
            if kind != 'field':
                continue
            areas.save_field_rules(self.area, self.group, 'dcim.device', {key: ('hidden', '')}, self.owner1)
            areas.clear_cache()
            for url in (f'/dcim/devices/{self.other.pk}/edit/', f'/dcim/devices/{self.other.pk}/', '/dcim/devices/'):
                try:
                    status = self.client.get(url).status_code
                except Exception as exc:  # noqa: BLE001
                    import traceback
                    status = ' | '.join(traceback.format_exc().splitlines()[-9:])[:900]
                if status != 200:
                    broken.append((key, url, status))
            areas.save_field_rules(self.area, self.group, 'dcim.device', {key: ('default', '')}, self.owner1)
        self.assertEqual(broken, [], '\n'.join(map(str, broken)))

    def test_an_area_may_hide_what_is_not_allowed_instead_of_showing_a_door(self):
        member = User.objects.create_user('member_su', 'msu@example.com', is_superuser=True)  # NetBox shows every tab
        areas.add_member(self.group, member, None, self.owner1)
        self.client.logout()
        self.login(member)
        journal = f'/dcim/devices/{self.other.pk}/journal/'
        html = self.client.get(f'/dcim/devices/{self.other.pk}/').content.decode()
        self.assertIn(journal, html)  # the default: the tab is a door, the page behind it explains
        self.assertEqual(self.client.get(journal).status_code, 403)
        areas.update_area(self.area, self.owner1, hide_denied=True)
        areas.clear_cache()
        html = self.client.get(f'/dcim/devices/{self.other.pk}/').content.decode()
        self.assertNotIn(journal, html)  # hidden: the user sees no tab his group does not allow
        self.assertEqual(self.client.get(journal).status_code, 403)  # and the address stays closed
        areas.set_group_tabs(self.group, ['journal'], self.owner1)
        areas.clear_cache()
        self.assertIn(journal, self.client.get(f'/dcim/devices/{self.other.pk}/').content.decode())  # allowed: shown
        stranger = User.objects.create_user('stranger2', 's2@example.com')
        areas.clear_cache()
        stranger = User.objects.get(pk=stranger.pk)
        area_guard.arm_user(stranger)
        self.assertFalse(stranger.has_perm('dcim.view_device'))  # no door in the menu either
        areas.update_area(self.area, self.owner1, hide_denied=False)
        areas.clear_cache()
        stranger = User.objects.get(pk=stranger.pk)
        area_guard.arm_user(stranger)
        self.assertTrue(stranger.has_perm('dcim.view_device'))


class VisibilityBTest(AreaTestCase):
    """B: what is not allowed is not seen at all - only the password and the PIN stay (and an own API key if allowed)."""

    def setUp(self):
        super().setUp()
        from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site
        site = Site.objects.create(name='S1', slug='s1')
        dtype = DeviceType.objects.create(manufacturer=Manufacturer.objects.create(name='M1', slug='m1'),
                                          model='T1', slug='t1')
        Device.objects.create(name='DEV_1', site=site, device_type=dtype,
                              role=DeviceRole.objects.create(name='R1', slug='r1', color='ff0000'))
        self.keeper = User.objects.create_superuser('keeperb', 'kb@example.com', 'x')
        service.set_pin(self.keeper, GOOD_PIN)
        enable_2fa(self.keeper)
        areas.add_keeper(self.keeper, self.master)
        self.area = self.make_area(targets=('dcim.device',))
        self.group = areas.create_group(self.area, 'dcim.device', 'Technici', ['view'], self.owner1, records='all')
        self.member = User.objects.create_user('memberb', 'mb@example.com')
        areas.add_member(self.group, self.member, None, self.owner1)
        self.nobody = User.objects.create_user('nobody', 'n@example.com')
        areas.set_visibility(self.keeper, 'hidden', False, False)
        areas.clear_cache()
        self.denied = lambda response: response.headers.get('X-UserPIN') == 'denied'

    def armed(self, user):
        areas.clear_cache()
        user = User.objects.get(pk=user.pk)
        area_guard.arm_user(user)
        return user

    def test_who_sees_nothing(self):
        self.assertTrue(areas.sees_nothing(self.armed(self.nobody)))
        for user in (self.keeper, self.owner1, self.member):
            self.assertFalse(areas.sees_nothing(self.armed(user)), user.username)
        areas.set_visibility(self.keeper, 'doors', True, False)  # A: a door, nobody is "nothing"
        self.assertFalse(areas.sees_nothing(self.armed(self.nobody)))

    def test_a_user_in_no_group_sees_no_menu_page_or_api_and_keeps_the_password_and_the_pin(self):
        nobody = self.armed(self.nobody)
        self.assertFalse(nobody.has_perm('dcim.view_site'))  # no door in the menu
        self.assertFalse(nobody.has_perm('netbox_user_pin.view_myaccess'))  # requests are off: no "My access"
        self.assertFalse(nobody.has_perm('netbox_user_pin.view_pintest'))
        self.assertFalse(nobody.has_perm('netbox_user_pin.view_areaspage'))
        self.login(self.nobody, unlock=False)
        for url in ('/dcim/sites/', '/dcim/devices/', '/ipam/prefixes/', '/search/', '/user/profile/'):
            self.assertTrue(self.denied(self.client.get(url)), url)
        for url in ('/api/', '/api/status/', '/api/dcim/sites/'):
            self.assertTrue(self.denied(self.client.get(url, HTTP_ACCEPT='application/json')), url)
        for url in ('/user/password/', '/plugins/user-pin/'):
            self.assertFalse(self.denied(self.client.get(url)), url)
        page = self.client.get('/dcim/sites/').content.decode()
        self.assertIn('/user/password/', page)  # what he can still do
        self.assertNotIn('request-access', page)  # asking is switched off

    def test_requests_for_access_can_be_switched_off(self):
        with self.assertRaises(PermissionDenied):
            areas.request_target_access(self.nobody, 'dcim.site', ['view'], 'please')
        areas.set_visibility(self.keeper, 'hidden', True, False)
        self.assertIsNotNone(areas.request_target_access(self.nobody, 'dcim.site', ['view'], 'please'))
        self.assertTrue(self.armed(self.nobody).has_perm('netbox_user_pin.view_myaccess'))

    def test_a_member_sees_what_the_group_allows_and_nothing_else(self):
        member = self.armed(self.member)
        self.assertTrue(member.has_perm('dcim.view_device'))
        self.assertFalse(member.has_perm('dcim.view_site'))
        self.login(self.member)
        self.assertEqual(self.client.get('/dcim/devices/').status_code, 200)
        self.assertTrue(self.denied(self.client.get('/dcim/sites/')))
        self.assertEqual(self.client.get('/api/dcim/devices/', HTTP_ACCEPT='application/json').status_code, 200)

    def test_an_area_may_choose_its_own_and_the_keeper_sets_the_switch_on_the_page(self):
        areas.update_area(self.area, self.owner1, hide_denied=False)  # this area: A, whatever the settings say
        self.assertTrue(self.armed(self.nobody).has_perm('dcim.view_device'))  # the door of this area stays
        self.assertFalse(self.armed(self.nobody).has_perm('dcim.view_site'))  # B for the rest
        areas.update_area(self.area, self.owner1, hide_denied=None)
        self.assertFalse(self.armed(self.nobody).has_perm('dcim.view_device'))
        self.client.force_login(self.nobody)
        with self.assertRaises(PermissionDenied):
            areas.set_visibility(self.nobody, 'doors', True, True)

    @override_settings(API_TOKEN_PEPPERS={1: 'x' * 50})
    def test_an_own_api_key_when_the_settings_allow_it(self):
        from users.models import Token
        Token.objects.create(user=self.nobody, description='mine')
        Token.objects.create(user=self.member, description='theirs')
        self.login(self.nobody, unlock=False)
        self.assertTrue(self.denied(self.client.get('/user/api-tokens/')))  # off: closed
        areas.set_visibility(self.keeper, 'hidden', False, True)
        areas.clear_cache()
        self.assertFalse(self.denied(self.client.get('/user/api-tokens/')))
        nobody = self.armed(self.nobody)
        self.assertEqual(list(Token.objects.restrict(nobody, 'view').values_list('description', flat=True)), ['mine'])
        self.assertEqual(Token.objects.restrict(self.armed(self.keeper), 'view').count(), 2)  # a keeper sees all

    def test_menu_items_without_a_permission_or_for_superusers_are_hidden_in_b(self):
        from netbox.navigation import MenuItem
        self.assertFalse(area_guard._menu_item_allowed(MenuItem(link='home', link_text='X')))  # no permission
        self.assertFalse(area_guard._menu_item_allowed(MenuItem(link='home', link_text='X', staff_only=True)))
        self.assertTrue(area_guard._menu_item_allowed(MenuItem(link='home', link_text='X', permissions=['dcim.view_site'])))
        self.assertTrue(area_guard._menu_item_allowed(MenuItem(link='plugins:netbox_user_pin:my_pin', link_text='My PIN')))

    def test_the_menu_of_a_user_in_no_group_has_only_the_pin(self):
        from django.test import RequestFactory
        from netbox.context import current_request
        from utilities.templatetags import navigation as navigation_tags
        request = RequestFactory().get('/')
        for user, expect_only_pin in ((self.nobody, True), (self.keeper, False)):
            request.user = self.armed(user)
            token = current_request.set(request)
            try:
                items = [item.link for menu in navigation_tags.get_menus() for group in menu.groups
                         for item in group.items if request.user.has_perms(item.permissions)]
            finally:
                current_request.reset(token)
            if expect_only_pin:
                self.assertEqual(items, ['plugins:netbox_user_pin:my_pin'], items)
            else:
                self.assertGreater(len(items), 20)  # a keeper sees the whole menu

    @staticmethod
    def user_menu_of(html):
        start = html.index('Open user menu')
        return html[start:html.index('sidebar-menu', start)]

    def test_the_pages_of_a_user_in_no_group_show_only_the_password_and_the_pin(self):
        self.login(self.nobody, unlock=False)
        html = self.client.get('/user/password/').content.decode()
        menu = self.user_menu_of(html)
        self.assertIn('href="/user/password/"', menu)
        self.assertIn('href="/plugins/user-pin/"', menu)
        self.assertIn('/logout/', menu)  # the way out stays
        for gone in ('/user/profile/', '/user/bookmarks/', '/user/preferences/', '/user/subscriptions/',
                     '/user/api-tokens/'):
            self.assertNotIn(gone, menu, gone)
        for gone in ('href="/user/bookmarks/"', 'href="/user/notifications/"', 'href="/user/subscriptions/"',
                     'href="/user/preferences/"', 'href="/user/api-tokens/"', 'action="/search/"',
                     'hx-get="/extras/notifications/"'):
            self.assertNotIn(gone, html, gone)  # nor the tabs of the account pages, the bell, the search
        areas.set_visibility(self.keeper, 'hidden', False, True)  # the own API key allowed: its menu item
        menu = self.user_menu_of(self.client.get('/user/password/').content.decode())
        self.assertIn('href="/user/api-tokens/"', menu)
        self.assertNotIn('/user/profile/', menu)

    def test_a_role_holder_keeps_the_bell_and_the_search_to_be_told_of_approvals(self):
        self.login(self.owner1)
        html = self.client.get('/dcim/devices/').content.decode()
        self.assertIn('action="/search/"', html)
        self.assertIn('hx-get="/extras/notifications/"', html)  # the bell
        self.assertNotIn('/user/profile/', self.user_menu_of(html))  # the account links are shaped for all but a keeper

    def test_the_home_page_of_a_user_in_no_group_leads_to_the_pin(self):
        self.login(self.nobody, unlock=False)
        response = self.client.get('/')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], '/plugins/user-pin/')

    def test_the_new_texts_are_in_slovak(self):
        from django.utils import translation
        texts = ['Change the password', 'My API keys', 'What you can do here', 'What is not allowed',
                 'Users may ask for access', 'Users may create their own API key', 'What the users see',
                 'Choose A or B.', 'Not set (sees no record)', 'Deny (wins over any allowance)']
        with translation.override('sk'):
            for text in texts:
                self.assertNotEqual(translation.gettext(text), text, text)
