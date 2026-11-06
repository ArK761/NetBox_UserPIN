"""E-mail rules of a group: extra addresses told about the changes of the members (create / change / delete)."""
from django.contrib.auth import get_user_model
from django.core import mail
from django.core.exceptions import PermissionDenied, ValidationError
from django.test import override_settings

from netbox_user_pin import areachanges, areas
from netbox_user_pin.models import AreaMailRule

from . import test_areas as ta

User = get_user_model()
MAIL = {'SERVER': 'localhost', 'FROM_EMAIL': 'netbox@example.com'}


class MailRuleTest(ta.AreaChangeMailTest):
    """The setUp of the change-mail tests (an area on tenants, a worker, a keeper) - their tests are not repeated."""

    for _name in [n for n in dir(ta.AreaChangeMailTest) if n.startswith('test_')]:
        locals()[_name] = None
    del _name

    def setUp(self):
        super().setUp()
        self.group = areas.create_group(self.area, 'tenancy.tenant', 'Technici', ['view', 'change'], self.keeper)
        areas.add_member(self.group, self.worker, None, self.keeper)

    def rule(self, addresses='a@example.com\nb@example.com', events=('create', 'update'), active=True, rule_id=''):
        return areas.save_mail_rule(self.group, self.keeper, rule_id, 'Hlásenie', addresses, events, active)

    def send(self, change):
        areachanges.send_rule_mails(change.pk)

    def test_a_rule_is_saved_with_several_addresses_and_audited(self):
        rule = self.rule('a@example.com, b@example.com; a@example.com')
        self.assertEqual(rule.address_list, ['a@example.com', 'b@example.com'])
        self.assertTrue(rule.on_create and rule.on_update and not rule.on_delete)
        from netbox_user_pin.models import PinEvent
        self.assertTrue(PinEvent.objects.filter(action='area_changed', detail__contains='e-mail rule added').exists())

    def test_wrong_input_is_refused(self):
        for addresses in ('', 'not-an-address', 'x@other.org'):
            with self.assertRaises(ValidationError):
                self.rule(addresses)
        with self.assertRaises(ValidationError):
            self.rule(events=())
        self.assertEqual(AreaMailRule.objects.count(), 0)

    def test_only_who_manages_the_group_may_save_a_rule(self):
        with self.assertRaises(PermissionDenied):
            areas.save_mail_rule(self.group, self.worker, '', 'x', 'a@example.com', ['create'], True)

    def test_the_addresses_get_the_mail_for_the_chosen_kinds_of_change_only(self):
        self.rule(events=('create',))
        with override_settings(EMAIL=MAIL):
            mail.outbox.clear()
            self.send(self.change(action='update'))
            self.assertEqual(mail.outbox, [])
            created = self.change(action='create')
            self.send(created)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(sorted(mail.outbox[0].to), ['a@example.com', 'b@example.com'])
        self.assertIn(' : created Tenant – T1', mail.outbox[0].subject)
        self.assertIn('USER PIN : ', mail.outbox[0].body)

    def test_a_switched_off_rule_and_a_non_member_send_nothing(self):
        self.rule(active=False)
        other = User.objects.create_user('other', 'o@example.com')
        with override_settings(EMAIL=MAIL):
            mail.outbox.clear()
            self.send(self.change())
            self.rule(active=True, rule_id=AreaMailRule.objects.get().pk)
            self.send(self.change(user=other))
        self.assertEqual(mail.outbox, [])

    def test_the_change_is_queued_only_when_a_rule_matches_and_the_other_mails_stay(self):
        from unittest import mock
        self.rule(events=('update',))
        queued = []
        with mock.patch('django_rq.get_queue') as get_queue:
            get_queue.return_value.enqueue.side_effect = lambda func, *args: queued.append(func)
            with self.captureOnCommitCallbacks(execute=True):
                self.change(action='update')
            self.assertIn(areachanges.send_rule_mails, queued)
            queued.clear()
            with self.captureOnCommitCallbacks(execute=True):
                self.change(action='delete')  # no rule wants it
            self.assertNotIn(areachanges.send_rule_mails, queued)
        self.assertEqual(len(self.events()), 2)  # the audit log of both changes is written as before

    def test_a_rule_can_be_deleted(self):
        rule = self.rule()
        areas.delete_mail_rule(self.group, self.keeper, rule.pk)
        self.assertEqual(AreaMailRule.objects.count(), 0)

    def test_the_group_page_shows_the_card_and_saves_and_deletes_rules(self):
        from django.urls import reverse
        url = reverse('plugins:netbox_user_pin:group', kwargs={'pk': self.area.pk, 'gid': self.group.pk})
        from .test_pin import admin_login
        admin_login(self.client, self.keeper)
        page = self.client.get(url)
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, 'E-mails about the changes of this group')
        bad = self.client.post(url, {'action': 'mail-save', 'name': 'x', 'addresses': 'zle', 'events': ['create']})
        self.assertEqual(bad.status_code, 302)
        self.assertEqual(AreaMailRule.objects.count(), 0)
        self.client.post(url, {'action': 'mail-save', 'name': 'Hlásenie', 'addresses': 'a@example.com\nb@example.com',
                               'events': ['create', 'delete'], 'active': 'on'})
        rule = AreaMailRule.objects.get()
        self.assertEqual((rule.on_create, rule.on_update, rule.on_delete), (True, False, True))
        self.assertContains(self.client.get(url), 'b@example.com')
        self.client.post(url, {'action': 'mail-delete', 'rule': rule.pk})
        self.assertEqual(AreaMailRule.objects.count(), 0)

    def test_a_summary_rule_sends_one_mail_for_what_piled_up(self):
        from datetime import timedelta

        from django.utils import timezone
        rule = areas.save_mail_rule(self.group, self.keeper, '', 'Suhrn', 'a@example.com', ['create', 'update'], True,
                                    mode='summary', every=5)
        from unittest import mock
        with override_settings(EMAIL=MAIL):
            mail.outbox.clear()
            areachanges.report_rule_mails()  # the first run only sets the mark
            self.assertEqual(mail.outbox, [])
            queued = []
            with mock.patch('django_rq.get_queue') as get_queue:
                get_queue.return_value.enqueue.side_effect = lambda func, *args: queued.append(func)
                with self.captureOnCommitCallbacks(execute=True):
                    self.change(action='update')
                    self.change(action='create', name='T2')
                    self.change(action='delete', name='T3')  # not chosen
            self.assertEqual(queued, [])  # a summary is never sent at once
            areachanges.report_rule_mails()  # too early
            self.assertEqual(mail.outbox, [])
            AreaMailRule.objects.filter(pk=rule.pk).update(last_sent=timezone.now() - timedelta(minutes=10))
            areachanges.report_rule_mails()
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn('changes (2)', mail.outbox[0].subject)
        self.assertIn('created Tenant – T2', mail.outbox[0].body)
        self.assertNotIn('T3', mail.outbox[0].body)

    def test_the_interval_must_be_one_of_the_offered(self):
        with self.assertRaises(ValidationError):
            areas.save_mail_rule(self.group, self.keeper, '', 'x', 'a@example.com', ['create'], True,
                                 mode='summary', every=7)
