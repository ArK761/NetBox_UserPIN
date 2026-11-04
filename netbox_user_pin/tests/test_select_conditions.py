"""
Conditions of a field rule on the fields that offer a fixed list of values: the select / multiselect custom fields (their
drop-down is filled by the API of the choice set) and the model fields with fixed choices (status ...). The drop-down must
offer only the values the rule allows, and a value outside the rule must be refused when saving (form and API).
"""
from django.contrib.auth import get_user_model

from netbox_user_pin import areas, service

from . import test_areas as ta
from .test_pin import GOOD_PIN, enable_2fa

User = get_user_model()
API = {'HTTP_ACCEPT': 'application/json'}


class SelectConditionsTest(ta.RowConditionsTest):
    """The setUp of the row-condition tests (an area on devices, a group, a member) - their tests are not repeated."""

    for _name in [n for n in dir(ta.RowConditionsTest) if n.startswith('test_')]:
        locals()[_name] = None
    del _name

    def setUp(self):
        super().setUp()
        from core.models import ObjectType
        from dcim.models import Device
        from extras.models import CustomField, CustomFieldChoiceSet
        keeper = User.objects.create_superuser('keeperz', 'kz@example.com', 'x')
        service.set_pin(keeper, GOOD_PIN)
        enable_2fa(keeper)
        areas.add_keeper(keeper, self.master)  # the first keeper switches "deny everything not allowed" on
        areas.update_group(self.group, self.owner1, name='Technici', rights=['view', 'change'])
        self.values = ['AllInOne', 'StolovyPocitac', 'DesktopPC-WiFi', 'IpmiManagement', 'KancelarskeZariadenie',
                       'SluzobnyNotebook', 'Server']
        self.choice_set = CustomFieldChoiceSet.objects.create(name='CS-type', extra_choices=[[v, v] for v in self.values])
        self.cf = CustomField.objects.create(name='tz', type='select', choice_set=self.choice_set)
        self.cf.object_types.set([ObjectType.objects.get_for_model(Device)])
        areas.clear_cache()

    def choices(self):
        areas.clear_cache()
        self.login(self.user)
        response = self.client.get(f'/api/extras/custom-field-choice-sets/{self.choice_set.pk}/choices/?limit=100', **API)
        self.assertEqual(response.status_code, 200, response.content[:200])
        return sorted(r['id'] for r in response.json()['results']), response.json()['count']

    def test_the_drop_down_of_a_select_custom_field_offers_only_the_allowed_values(self):
        areas.save_field_rules(self.area, self.group, 'dcim.device',
                               {'cf:tz': ('write', '=KancelarskeZariadenie\n=StolovyPocitac\n=SluzobnyNotebook')},
                               self.owner1)
        ids, count = self.choices()
        self.assertEqual(ids, ['KancelarskeZariadenie', 'SluzobnyNotebook', 'StolovyPocitac'])
        self.assertEqual(count, 3)  # the number of pages follows the narrowed list

    def test_other_kinds_of_conditions_and_the_search_box(self):
        areas.save_field_rules(self.area, self.group, 'dcim.device', {'cf:tz': ('write', '^Desk\n~notebook')}, self.owner1)
        self.assertEqual(self.choices()[0], ['DesktopPC-WiFi', 'SluzobnyNotebook'])
        response = self.client.get(f'/api/extras/custom-field-choice-sets/{self.choice_set.pk}/choices/?q=desk', **API)
        self.assertEqual([r['id'] for r in response.json()['results']], ['DesktopPC-WiFi'])  # q works inside the rule

    def test_a_rule_without_conditions_offers_everything(self):
        areas.save_field_rules(self.area, self.group, 'dcim.device', {'cf:tz': ('write', '')}, self.owner1)
        self.assertEqual(self.choices()[0], sorted(self.values))

    def test_a_set_shared_by_two_fields_offers_what_either_allows_and_everything_if_one_is_open(self):
        from core.models import ObjectType
        from dcim.models import Device
        from extras.models import CustomField
        other = CustomField.objects.create(name='tz2', type='multiselect', choice_set=self.choice_set)
        other.object_types.set([ObjectType.objects.get_for_model(Device)])
        areas.save_field_rules(self.area, self.group, 'dcim.device', {'cf:tz': ('write', '=Server'),
                                                                      'cf:tz2': ('write', '=AllInOne')}, self.owner1)
        self.assertEqual(self.choices()[0], ['AllInOne', 'Server'])
        areas.save_field_rules(self.area, self.group, 'dcim.device', {'cf:tz': ('write', '=Server'),
                                                                      'cf:tz2': ('write', '')}, self.owner1)
        self.assertEqual(self.choices()[0], sorted(self.values))

    def test_a_value_outside_the_rule_is_refused_when_saving(self):
        areas.save_field_rules(self.area, self.group, 'dcim.device', {'cf:tz': ('write', '=Server')}, self.owner1)
        areas.clear_cache()
        self.login(self.user)
        device = self.Device.objects.get(name='AGG_01')
        bad = self.client.patch(f'/api/dcim/devices/{device.pk}/', {'custom_fields': {'tz': 'AllInOne'}},
                                content_type='application/json', **API)
        self.assertGreaterEqual(bad.status_code, 400, bad.content[:200])
        self.assertNotEqual(self.Device.objects.get(pk=device.pk).custom_field_data.get('tz'), 'AllInOne')

    def test_a_relation_field_refuses_a_value_outside_the_rule_through_the_api(self):
        areas.save_field_rules(self.area, self.group, 'dcim.device', {'role': ('write', '=Switch')}, self.owner1)
        areas.clear_cache()
        self.login(self.user)
        device = self.Device.objects.get(name='AGG_01')
        bad = self.client.patch(f'/api/dcim/devices/{device.pk}/', {'role': self.role2.pk},
                                content_type='application/json', **API)
        self.assertGreaterEqual(bad.status_code, 400, bad.content[:200])
        self.assertEqual(self.Device.objects.get(pk=device.pk).role_id, self.role1.pk)
        other = self.Device.objects.get(name='AGG_02')  # (its role is the Router one: not touched by this request)
        ok = self.client.patch(f'/api/dcim/devices/{other.pk}/', {'role': self.role1.pk}, content_type='application/json',
                               **API)
        self.assertEqual(ok.status_code, 200, ok.content[:200])
        self.assertEqual(self.Device.objects.get(pk=other.pk).role_id, self.role1.pk)

    def test_fixed_choices_of_a_model_field_follow_the_rule_too(self):
        """A model field with a fixed list (the status of a device): a condition narrows the drop-down and is enforced."""
        areas.save_field_rules(self.area, self.group, 'dcim.device', {'status': ('write', '=active\n=planned')}, self.owner1)
        areas.clear_cache()
        self.login(self.user)
        device = self.Device.objects.get(name='AGG_01')
        page = self.client.get(f'/dcim/devices/{device.pk}/edit/')
        self.assertEqual(page.status_code, 200)
        html = page.content.decode()
        self.assertIn('value="active"', html)
        self.assertNotIn('value="offline"', html)
        self.assertNotIn('value="decommissioning"', html)
        bad = self.client.patch(f'/api/dcim/devices/{device.pk}/', {'status': 'offline'}, content_type='application/json',
                                **API)
        self.assertGreaterEqual(bad.status_code, 400, bad.content[:200])
        self.assertNotEqual(self.Device.objects.get(pk=device.pk).status, 'offline')
        ok = self.client.patch(f'/api/dcim/devices/{device.pk}/', {'status': 'planned'}, content_type='application/json',
                               **API)
        self.assertEqual(ok.status_code, 200, ok.content[:200])
