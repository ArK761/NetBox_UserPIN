"""What the e-mail and the audit log say about a created / deleted object: every filled field (secrets hidden)."""
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

    def test_a_created_object_lists_its_filled_fields(self):
        lines = guests._change_lines(self.change('create', after={
            'id': 5, 'name': 'ABCDEFG', 'description': '', 'comments': None, 'created': 'x', 'last_updated': 'y',
            'custom_fields': {'hw': 'A', 'empty': None}}))
        text = '\n'.join(lines)
        self.assertIn('Tenant: ABCDEFG', lines[1])
        self.assertIn('    name: "ABCDEFG"', text)
        self.assertIn('    hw: "A"', text)
        for hidden in ('description', 'comments', 'created', 'last_updated', 'empty', 'id:'):
            self.assertNotIn(hidden, '\n'.join(lines[2:]))

    def test_a_deleted_object_lists_what_it_had(self):
        lines = guests._change_lines(self.change('delete', before={'name': 'ABCDEFG', 'slug': 'abc'}))
        self.assertIn('    name: "ABCDEFG"', lines)
        self.assertIn('    slug: "abc"', lines)

    def test_secrets_are_hidden_in_the_mail_and_in_the_audit_text(self):
        change = self.change('create', after={'name': 'x', 'api_token': 'SECRET123'})
        self.assertNotIn('SECRET123', '\n'.join(guests._change_lines(change)))
        detail = areachanges.detail_of(change, 'added')
        self.assertNotIn('SECRET123', detail)
        self.assertIn('name: "x"', detail)  # the audit detail has the field rows too, so it expands under the line
