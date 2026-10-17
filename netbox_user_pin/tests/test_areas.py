from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone

from netbox_user_pin import area_guard, areas
from netbox_user_pin.forms import PinSettingsForm
from netbox_user_pin.models import (
    AreaGrant, AreaRequest, AreaRequestStatus, PinEvent, PinEventAction, PinSettings, ProtectedArea,
)

from netbox_user_pin import service

from .test_pin import GOOD_PIN, PinTestCase, admin_login, enable_2fa

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
            'action': 'approve', 'pk': req.pk, 'profile': self.profile(area, 'Read').pk, 'hours': 4})
        self.assertEqual(response.status_code, 302, response.content[:300])
        req.refresh_from_db()
        self.assertEqual(req.status, AreaRequestStatus.GRANTED)
        self.assertEqual(self.client.get(DEVICES).status_code, 200)

    def test_decision_needs_step_up(self):
        area = self.make_area()
        areas.request_access(area, self.appadmin, 'I need the devices')
        req = AreaRequest.objects.get()
        service.set_pin(self.owner1, GOOD_PIN)
        enable_2fa(self.owner1)
        self.login(self.owner1)
        self.client.post(reverse('plugins:netbox_user_pin:unlock'), {'pin': GOOD_PIN, 'scope': 'user-pin-admin'})
        response = self.client.post(reverse('plugins:netbox_user_pin:area', kwargs={'pk': area.pk}), {
            'action': 'deny', 'pk': req.pk})
        self.assertEqual(response.status_code, 302)
        self.assertIn('/confirm/', response['Location'])  # sent to the PIN + 2FA confirmation
        req.refresh_from_db()
        self.assertEqual(req.status, AreaRequestStatus.PENDING)

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
        self.assertContains(self.client.get(reverse('plugins:netbox_user_pin:area', kwargs={'pk': area.pk})), 'Grant access')

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
        self.assertIn('User PIN v9.9.9 · ccccccc', html)

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
                self.assertEqual(build.plugin_build(), {'version': '1.2.3', 'commit': 'abcdef1234567890', 'short': 'abcdef1'})
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
        # nothing ticked: the page says why it was not saved
        response = self.client.post(url, {'action': 'profile-save', 'pk': read.pk, 'name': 'Read'})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'The profile was not saved')
        self.assertContains(response, 'Choose at least one right.')


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
            areas.set_default_deny(True, self.master)  # the master is no keeper
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
