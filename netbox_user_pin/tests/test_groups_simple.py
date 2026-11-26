"""3.3.0: a group sees every record of its type (no records / denials on the page) and a member of a group sees only
what the groups allow in the menu, also with A (the doors are for the users in no group)."""
from django.contrib.auth import get_user_model

from netbox_user_pin import areas

from . import test_areas as ta

User = get_user_model()


class SimpleGroupTest(ta.AreaChangeMailTest):

    for _name in [n for n in dir(ta.AreaChangeMailTest) if n.startswith('test_')]:
        locals()[_name] = None
    del _name

    def test_a_new_group_sees_all_records(self):
        group = areas.create_group(self.area, 'tenancy.tenant', 'Citanie', ['view'], self.keeper)
        self.assertEqual(group.records, 'all')

    def test_a_member_lives_in_b_while_the_others_get_doors(self):
        self.assertFalse(areas.hides_denied(user=self.worker))  # A (doors) for a user in no group
        group = areas.create_group(self.area, 'tenancy.tenant', 'Citanie', ['view'], self.keeper)
        areas.add_member(group, self.worker, None, self.keeper)
        areas.clear_cache()
        self.assertTrue(areas.hides_denied(user=self.worker))
        other = User.objects.create_user('nobody', 'n@example.com')
        self.assertFalse(areas.hides_denied(user=other))

    def test_the_group_page_has_no_records_and_no_denials(self):
        from django.urls import reverse

        from .test_pin import admin_login
        group = areas.create_group(self.area, 'tenancy.tenant', 'Citanie', ['view'], self.keeper)
        admin_login(self.client, self.keeper)
        html = self.client.get(reverse('plugins:netbox_user_pin:group', kwargs={'pk': self.area.pk, 'gid': group.pk})
                               ).content.decode()
        self.assertNotIn('name="records"', html)
        self.assertNotIn('deny__', html)
        self.assertIn('acc-read', html)

    def test_the_list_of_areas_shows_the_members_with_their_names_under_an_arrow(self):
        from django.urls import reverse

        from .test_pin import admin_login
        group = areas.create_group(self.area, 'tenancy.tenant', 'VLAN_LOOK', ['view'], self.keeper)
        self.worker.first_name, self.worker.last_name = 'Jan', 'Novak'
        self.worker.save()
        areas.add_member(group, self.worker, None, self.keeper)
        admin_login(self.client, self.keeper)
        html = self.client.get(reverse('plugins:netbox_user_pin:areas')).content.decode()
        self.assertIn('<summary><strong>VLAN_LOOK</strong>', html)
        self.assertIn('worker <span class="text-secondary">– Jan Novak</span>', html)
