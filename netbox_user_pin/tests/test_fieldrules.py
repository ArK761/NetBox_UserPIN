from types import SimpleNamespace

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValidationError
from django.urls import reverse

from netbox_user_pin import areas, fieldrules
from netbox_user_pin.models import AreaFieldMode, AreaFieldRule

from .test_areas import AreaTestCase
from .test_pin import admin_login

User = get_user_model()


class FieldRulesCase(AreaTestCase):
    def setUp(self):
        super().setUp()
        from core.models import ObjectType
        from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site
        from extras.models import CustomField
        from tenancy.models import Tenant

        role = DeviceRole.objects.create(name='r', slug='r')
        site = Site.objects.create(name='s', slug='s')
        kind = DeviceType.objects.create(manufacturer=Manufacturer.objects.create(name='m', slug='m'), model='t', slug='t')
        self.printer = Device.objects.create(name='PRINTER_A', role=role, site=site, device_type=kind)
        self.switch = Device.objects.create(name='SWITCH_X', role=role, site=site, device_type=kind)
        tenant_type = ObjectType.objects.get_for_model(Tenant)
        self.note = CustomField.objects.create(name='secret_note', label='Secret note', type='text')
        self.note.object_types.set([tenant_type])
        self.hw = CustomField.objects.create(name='hw', label='OfficeHardware', type='object',
                                             related_object_type=ObjectType.objects.get_for_model(Device))
        self.hw.object_types.set([tenant_type])
        self.tenant = Tenant.objects.create(name='Acme', slug='acme', description='about Acme',
                                            custom_field_data={'secret_note': 'TOPSECRET-123', 'hw': self.switch.pk})
        self.area = areas.create_area('Tenants', ['tenancy.tenant', 'dcim.device'], [], self.master)
        areas.add_owner(self.area, self.owner1, self.master)
        areas.add_owner(self.area, self.owner2, self.owner1)
        self.edit = self.area.profiles.get(name='Edit')
        self.read = self.area.profiles.get(name='Read')
        self.grant = areas.grant_access(self.area, self.appadmin, self.edit, None, self.owner1)

    def rule(self, field, mode, contains='', profile=None, target='tenancy.tenant', actor=None):
        areas.save_field_rules(self.area, profile or self.edit, target, {field: (mode, contains)}, actor or self.owner1)

    @property
    def detail(self):
        return reverse('tenancy:tenant', args=[self.tenant.pk])

    @property
    def api(self):
        return f'/api/tenancy/tenants/{self.tenant.pk}/'


class PolicyTest(FieldRulesCase):
    def test_default_modes_follow_the_rights(self):
        policy = fieldrules.compute_policy(self.appadmin, self.area, 'tenancy', 'tenant')
        self.assertIsNone(policy)  # no rules yet
        self.rule('cf:secret_note', 'hidden')
        policy = fieldrules.compute_policy(self.appadmin, self.area, 'tenancy', 'tenant')
        self.assertEqual(policy.default, AreaFieldMode.WRITE)
        self.assertEqual(policy.mode('cf:secret_note'), AreaFieldMode.HIDDEN)
        self.assertEqual(policy.mode('name'), AreaFieldMode.WRITE)

    def test_profiles_add_up_the_most_permissive_wins(self):
        self.rule('cf:secret_note', 'hidden')
        areas.grant_access(self.area, self.appadmin, self.read, None, self.owner1)
        policy = fieldrules.compute_policy(self.appadmin, self.area, 'tenancy', 'tenant')
        self.assertEqual(policy.mode('cf:secret_note'), AreaFieldMode.READ)  # Read has no rule: its default is read

    def test_nobody_hides_from_everybody_even_the_owners(self):
        areas.save_field_rules(self.area, None, 'tenancy.tenant', {'cf:secret_note': ('hidden', '')}, self.owner1)
        for user in (self.owner1, self.appadmin):
            policy = fieldrules.compute_policy(user, self.area, 'tenancy', 'tenant')
            self.assertEqual(policy.mode('cf:secret_note'), AreaFieldMode.HIDDEN)

    def test_nobody_accepts_only_hidden(self):
        areas.save_field_rules(self.area, None, 'tenancy.tenant', {'name': ('read', '')}, self.owner1)
        self.assertFalse(AreaFieldRule.objects.filter(profile=None).exists())

    def test_contains_texts_join_up(self):
        self.rule('cf:hw', 'write', 'PRINTER')
        policy = fieldrules.compute_policy(self.appadmin, self.area, 'tenancy', 'tenant')
        self.assertEqual(policy.texts('cf:hw'), ['PRINTER'])
        areas.grant_access(self.area, self.appadmin, self.read, None, self.owner1)  # a profile without a limit
        self.rule('cf:hw', 'read', '', profile=self.read)
        policy = fieldrules.compute_policy(self.appadmin, self.area, 'tenancy', 'tenant')
        self.assertIsNone(policy.texts('cf:hw'))

    def test_only_owners_save_rules(self):
        with self.assertRaises(PermissionDenied):
            areas.save_field_rules(self.area, self.edit, 'tenancy.tenant', {'name': ('hidden', '')}, self.master)
        with self.assertRaises(ValidationError):
            areas.save_field_rules(self.area, self.edit, 'ipam.prefix', {'x': ('hidden', '')}, self.owner1)

    def test_field_list_has_model_and_custom_fields(self):
        keys = {key for key, _l, _k in fieldrules.fields_of('tenancy', 'tenant')}
        self.assertTrue({'name', 'description', 'cf:secret_note', 'cf:hw'} <= keys)
        self.assertNotIn('id', keys)


class DetailAndApiTest(FieldRulesCase):
    def test_custom_field_is_hidden_in_detail_and_api(self):
        self.login(self.appadmin)
        html = self.client.get(self.detail).content.decode()
        self.assertIn('TOPSECRET-123', html)
        self.assertIn('secret_note', self.client.get(self.api, HTTP_ACCEPT='application/json').json()['custom_fields'])
        self.rule('cf:secret_note', 'hidden')
        html = self.client.get(self.detail).content.decode()
        self.assertNotIn('TOPSECRET-123', html)
        self.assertNotIn('Secret note', html)
        fields = self.client.get(self.api, HTTP_ACCEPT='application/json').json()['custom_fields']
        self.assertNotIn('secret_note', fields)
        self.assertIn('hw', fields)
        self.login(self.owner1)  # the owners see it (nobody has hidden it)
        self.assertIn('TOPSECRET-123', self.client.get(self.detail).content.decode())

    def test_nobody_sees_it(self):
        areas.save_field_rules(self.area, None, 'tenancy.tenant', {'cf:secret_note': ('hidden', '')}, self.owner1)
        self.login(self.owner1)
        self.assertNotIn('TOPSECRET-123', self.client.get(self.detail).content.decode())

    def test_model_field_hidden_in_the_api(self):
        self.login(self.appadmin)
        self.assertIn('description', self.client.get(self.api, HTTP_ACCEPT='application/json').json())
        self.rule('description', 'hidden')
        body = self.client.get(self.api, HTTP_ACCEPT='application/json').json()
        self.assertNotIn('description', body)
        self.assertIn('name', body)

    def test_value_filter_in_detail_and_api(self):
        from tenancy.models import Tenant
        self.rule('cf:hw', 'write', 'PRINTER')
        other = Tenant.objects.create(name='Beta', slug='beta', custom_field_data={'hw': self.printer.pk})
        self.login(self.appadmin)
        self.assertNotIn('SWITCH_X', self.client.get(self.detail).content.decode())  # this tenant uses a switch
        self.assertIn('PRINTER_A', self.client.get(reverse('tenancy:tenant', args=[other.pk])).content.decode())
        self.assertIsNone(self.client.get(self.api, HTTP_ACCEPT='application/json').json()['custom_fields']['hw'])
        shown = self.client.get(f'/api/tenancy/tenants/{other.pk}/', HTTP_ACCEPT='application/json').json()
        self.assertEqual(shown['custom_fields']['hw']['name'], 'PRINTER_A')


class FormAndTableTest(FieldRulesCase):
    def edit_url(self):
        return reverse('tenancy:tenant_edit', args=[self.tenant.pk])

    def test_hidden_and_read_only_fields_in_the_form(self):
        self.login(self.appadmin)
        html = self.client.get(self.edit_url()).content.decode()
        self.assertIn('id_cf_secret_note', html)
        self.assertIn('id_description', html)
        self.rule('cf:secret_note', 'hidden')
        self.rule('description', 'read')
        html = self.client.get(self.edit_url()).content.decode()
        self.assertNotIn('id_cf_secret_note', html)
        self.assertRegex(html, r'<[^>]*(?=[^>]*id="id_description")[^>]*disabled')

    def test_saving_does_not_wipe_a_hidden_field(self):
        from tenancy.models import Tenant
        self.rule('cf:secret_note', 'hidden')
        self.login(self.appadmin)
        response = self.client.post(self.edit_url(), {'name': 'Acme 2', 'slug': 'acme', 'description': 'x'})
        self.assertEqual(response.status_code, 302, response.content[:300])
        tenant = Tenant.objects.get(pk=self.tenant.pk)
        self.assertEqual(tenant.name, 'Acme 2')
        self.assertEqual(tenant.custom_field_data.get('secret_note'), 'TOPSECRET-123')

    def test_read_only_field_ignores_what_is_posted(self):
        from tenancy.models import Tenant
        self.rule('description', 'read')
        self.login(self.appadmin)
        self.client.post(self.edit_url(), {'name': 'Acme', 'slug': 'acme', 'description': 'HACKED'})
        self.assertEqual(Tenant.objects.get(pk=self.tenant.pk).description, 'about Acme')

    def test_value_filter_is_checked_on_save(self):
        from netbox.context import current_request
        from tenancy.forms import TenantForm
        self.rule('cf:hw', 'write', 'PRINTER')
        token = current_request.set(SimpleNamespace(user=User.objects.get(pk=self.appadmin.pk)))
        try:
            form = TenantForm(instance=self.tenant)
            field = form.fields['cf_hw']
            field.clean(self.printer.pk)  # allowed
            with self.assertRaises(ValidationError):
                field.clean(self.switch.pk)
        finally:
            current_request.reset(token)

    def test_hidden_column_is_not_in_the_list(self):
        self.login(self.appadmin)
        self.assertIn('Description', self.client.get(reverse('tenancy:tenant_list')).content.decode())
        self.rule('description', 'hidden')
        self.assertNotIn('Description', self.client.get(reverse('tenancy:tenant_list')).content.decode())


class RulesPageTest(FieldRulesCase):
    def test_page_lists_the_fields_and_saves(self):
        admin_login(self.client, self.owner1)
        url = reverse('plugins:netbox_user_pin:area_fields', kwargs={'pk': self.area.pk})
        html = self.client.get(f'{url}?grant={self.grant.pk}&target=tenancy.tenant').content.decode()
        self.assertIn('mode__cf:secret_note', html)
        self.assertIn('mode__description', html)
        response = self.client.post(url, {'grant': self.grant.pk, 'target': 'tenancy.tenant',
                                          'mode__cf:secret_note': 'hidden', 'mode__cf:hw': 'read',
                                          'contains__cf:hw': 'PRINTER', 'mode__name': 'default'})
        self.assertEqual(response.status_code, 302, response.content[:300])
        self.assertEqual(AreaFieldRule.objects.get(profile=self.edit, field='cf:secret_note').mode, 'hidden')
        rule = AreaFieldRule.objects.get(profile=self.edit, field='cf:hw')
        self.assertEqual((rule.mode, rule.contains), ('read', 'PRINTER'))
        # nobody
        self.client.post(url, {'grant': 'nobody', 'target': 'tenancy.tenant', 'mode__description': 'hidden'})
        self.assertTrue(AreaFieldRule.objects.filter(profile=None, field='description').exists())
        html = self.client.get(f'{url}?grant=nobody').content.decode()
        self.assertIn('mode__description', html)

    def test_a_stranger_cannot_open_the_page(self):
        admin_login(self.client, self.appadmin)
        url = reverse('plugins:netbox_user_pin:area_fields', kwargs={'pk': self.area.pk})
        self.assertEqual(self.client.get(url).status_code, 200 if areas.can_see(self.appadmin, self.area) else 403)
