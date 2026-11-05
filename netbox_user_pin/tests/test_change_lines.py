"""What the e-mail and the audit log say about a created / changed / deleted object: the headline (who, what, which
object) and one bullet per field (the filled ones for a new or deleted object), related objects by name, secrets hidden."""
from django.test import TestCase
from django.utils import timezone

from netbox_user_pin import areachanges, guests


class ChangeLinesTest(TestCase):

    def change(self, action, before=None, after=None):
        from core.models import ObjectChange, ObjectType
        from tenancy.models import Tenant
        from uuid import uuid4
        return ObjectChange(time=timezone.now(), request_id=uuid4(), action=action, object_repr='ABCDEFG',
                            changed_object_type=ObjectType.objects.get_for_model(Tenant),
                            prechange_data=before, postchange_data=after)

    def test_the_headline_says_who_did_what_with_which_object(self):
        self.assertEqual(guests.change_headline('X001', self.change('create')), 'X001 : created Tenant – ABCDEFG')
        self.assertEqual(guests.change_headline('X001', self.change('update')),
                         'X001 : change of parameters Tenant – ABCDEFG')
        self.assertEqual(guests.change_headline('X001', self.change('delete')), 'X001 : deleted Tenant – ABCDEFG')

    def test_a_created_object_lists_its_filled_fields(self):
        rows = guests.change_rows(self.change('create', after={
            'id': 5, 'name': 'ABCDEFG', 'description': '', 'comments': None, 'created': 'x', 'last_updated': 'y',
            'custom_fields': {'hw': 'A', 'empty': None}}))
        text = '\n'.join(rows)
        self.assertIn('* Name: "ABCDEFG"', text)
        self.assertIn('* hw: "A"', text)
        for hidden in ('Description', 'Comments', 'created', 'last_updated', 'empty', 'Id'):
            self.assertNotIn(hidden, text)

    def test_the_block_starts_with_what_happened(self):
        block = guests.change_block(self.change('create', after={'name': 'ABCDEFG'}))
        self.assertTrue(block[0].startswith('* created Tenant ABCDEFG ('))
        self.assertEqual(block[1], '* Name: "ABCDEFG"')

    def test_a_deleted_object_lists_what_it_had(self):
        rows = guests.change_rows(self.change('delete', before={'name': 'ABCDEFG', 'slug': 'abc'}))
        self.assertIn('* Name: "ABCDEFG"', rows)
        self.assertIn('* Slug: "abc"', rows)

    def test_secrets_are_hidden_in_the_mail_and_in_the_audit_text(self):
        change = self.change('create', after={'name': 'x', 'api_token': 'SECRET123'})
        self.assertNotIn('SECRET123', '\n'.join(guests.change_rows(change)))
        detail = areachanges.detail_of(change, 'X001')
        self.assertNotIn('SECRET123', detail)
        self.assertTrue(detail.startswith('X001 : created Tenant – ABCDEFG\n'))  # the line that expands in the audit log
        self.assertIn('* Name: "x"', detail)

    def test_a_related_object_is_shown_by_its_name_not_by_its_id(self):
        from tenancy.models import TenantGroup
        group = TenantGroup.objects.create(name='Tlaciarne', slug='tlaciarne')
        changed = self.change('update', before={'group': None}, after={'group': group.pk})
        self.assertIn('* Group: from "-" to "Tlaciarne"', guests.change_rows(changed))
        self.assertIn('* Group: from "-" to "Tlaciarne"', areachanges.detail_of(changed, 'X001'))
        created = self.change('create', after={'name': 'T', 'group': group.pk})
        self.assertIn('* Group: "Tlaciarne"', guests.change_rows(created))
        gone = self.change('update', before={'group': 999999}, after={'group': None})
        self.assertIn('* Group: from "999999" to "-"', guests.change_rows(gone))  # deleted: the id stays
