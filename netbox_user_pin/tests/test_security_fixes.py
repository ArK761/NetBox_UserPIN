"""
Regression tests of the fixes that followed the security audit (F-01, F-03 .. F-08). Every test goes through the whole
HTTP path (middleware, authentication, permission classes, queryset) and checks the real content of the answer and the
state of the database, never only the status code.

The audit file ``test_security_audit.py`` stays as it was (the proof of the original findings); the scenarios there
that describe F-02 (a request authenticated by an API token is outside the PIN protection) still fail on purpose: that
is a decision of the owner of the project, not a defect fixed here.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.db import DatabaseError, OperationalError
from django.test import Client, override_settings
from django.utils import timezone

from netbox_user_pin import area_guard, areas, service

from . import test_security_audit as audit
from .test_pin import GOOD_PIN

GQL = audit.GQL

User = get_user_model()
DEVICES = '/api/dcim/devices/?limit=100'


class F01SessionAndHeaderTest(audit.DataLeakTest):
    """F-01: the Authorization header never switches the PIN protection off for a signed-in person."""

    # the tests of the audit class this one extends are not repeated here
    test_read_paths_as_a_member = test_graphql_paths = test_write_paths_as_a_member = None
    test_header_trick_row_escalation_with_a_change_right = test_bulk_import_and_buttons = None

    HEADERS = (None, 'Token garbage', 'Bearer garbage', 'Token', 'Bearer nbt_invalid', 'Basic garbage',
               'token lower', 'Bearer')

    def test_every_header_with_a_session_is_judged_like_no_header(self):
        from dcim.models import Device
        for mode in ('rest', 'graphql'):
            for header in self.HEADERS:
                kw = {'headers': {'HTTP_AUTHORIZATION': header}} if header else {}
                if mode == 'rest':
                    response = self.call('get', DEVICES, 'memberx', token=False, session=True, **kw)
                else:
                    response = self.call('post', '/graphql/', 'memberx', token=False, session=True, data=GQL, **kw)
                leaked = [n for n in ('SECRETDEV', 'SECRETTEXT', 'HIDDENFIELDVALUE') if n.encode() in response.content]
                self.record('F-01 headers', f'session + header {header!r} | {mode} GET', [], leaked,
                            f'HTTP {response.status_code}')
        self.finish()

    def test_writes_with_a_session_and_any_header_change_nothing(self):
        from dcim.models import Device
        edit = areas.create_group(self.area, 'dcim.device', 'Editors', ['view', 'change', 'delete'], self.owner1,
                                  records='all')
        areas.add_group_condition(edit, self.owner1, 'name', 'contains', ['agg'])
        areas.add_member(edit, self.member, None, self.owner1)
        areas.clear_cache()
        for header in self.HEADERS:
            Device.objects.filter(pk=self.device.pk).update(comments='', description='SECRETTEXT')
            kw = {'headers': {'HTTP_AUTHORIZATION': header}} if header else {}
            for method, data in (('patch', {'comments': 'ESCALATED'}), ('delete', None)):
                self.call(method, f'/api/dcim/devices/{self.device.pk}/', 'memberx', token=False, session=True,
                          data=data, **kw)
            row = Device.objects.filter(pk=self.device.pk).first()
            self.record('F-01 writes', f'session + header {header!r}: the closed row is untouched', 'untouched',
                        'untouched' if row is not None and row.comments == '' else 'CHANGED/DELETED')
            if row is None:
                Device.objects.create(pk=self.device.pk, name='SECRETDEV', site=self.agg.site,
                                      device_type=self.agg.device_type, role=self.agg.role, description='SECRETTEXT')
        self.finish()

    def test_a_valid_token_with_a_session_is_the_session(self):
        """Both a session and a VALID token of somebody else: NetBox authenticates the session first, so does the PIN."""
        from users.models import Token
        Token.objects.create(user=self.su_free, version=1, token='s' * 40)
        response = Client().get(DEVICES, HTTP_AUTHORIZATION='Token ' + 's' * 40)
        self.record('F-01 headers', 'a valid token of a superuser without any session (F-02: outside the PIN)',
                    True, b'SECRETDEV' in response.content, f'HTTP {response.status_code}')
        client = Client()
        client.force_login(self.member)
        response = client.get(DEVICES, HTTP_AUTHORIZATION='Token ' + 's' * 40)
        self.record('F-01 headers', 'the same valid token of a superuser NEXT TO the session of a member: the member '
                    'decides, no closed row', False, b'SECRETDEV' in response.content, f'HTTP {response.status_code}')
        response = client.post('/graphql/', json.dumps(GQL), content_type='application/json',
                               HTTP_AUTHORIZATION='Token ' + 's' * 40)
        self.record('F-01 headers', 'GraphQL: the same, a superuser token next to a member session', False,
                    b'SECRETDEV' in response.content, f'HTTP {response.status_code}')
        self.finish()

    def test_the_header_scheme_of_a_request_without_a_session_still_means_a_token(self):
        factory = __import__('django.test', fromlist=['RequestFactory']).RequestFactory()
        for header, want in (('Token abc', True), ('Bearer nbt_x.y', True), ('Basic x', False), ('Foo bar', False)):
            request = factory.get('/api/dcim/devices/', HTTP_AUTHORIZATION=header)
            self.record('F-01 headers', f'no session, {header!r}: counts as a token request', want,
                        area_guard._is_token_request(request))
        request = factory.get('/api/dcim/devices/', HTTP_AUTHORIZATION='Token abc')
        request.user = self.member
        self.record('F-01 headers', 'a SIGNED-IN user with a token header: not a token request', False,
                    area_guard._is_token_request(request))
        self.finish()


class F03F05MatrixTest(audit.AuditBase):
    """F-03 / F-05: `tokens` and `api` are two flags: all four combinations, by session and by token, REST and GraphQL."""

    def allow(self, who, tokens, api):
        codes = ['password'] + (['tokens'] if tokens else []) + (['api'] if api else [])
        areas.set_exception_allowed(self.users_by_name(who), self.keeper, codes)
        areas.clear_cache()

    def test_all_four_combinations(self):
        from users.models import Token
        for who in ('plainx', 'suexc'):
            for tokens in (0, 1):
                for api in (0, 1):
                    self.allow(who, tokens, api)
                    label = f'{who} tokens={tokens} api={api}'
                    for channel in ('token', 'session'):
                        kw = dict(token=channel == 'token', session=channel == 'session')
                        general = self.verdict(self.call('get', '/api/status/', who, **kw))
                        self.record('F-03/05 matrix', f'{label} {channel}: /api/status/', 'ALLOW' if api else 'DENY', general)
                        general = self.verdict(self.call('get', '/api/dcim/devices/?limit=5', who, **kw))
                        self.record('F-03/05 matrix', f'{label} {channel}: REST list', 'ALLOW' if api else 'DENY', general)
                        gql = self.call('post', '/graphql/', who, data={'query': '{ __typename }'}, **kw)
                        self.record('F-03/05 matrix', f'{label} {channel}: GraphQL', 'ALLOW' if api else 'DENY',
                                    self.verdict(gql), f'HTTP {gql.status_code}')
                        mgmt = self.verdict(self.call('get', '/api/users/tokens/', who, **kw))
                        self.record('F-03/05 matrix', f'{label} {channel}: token management',
                                    'ALLOW' if tokens else 'DENY', mgmt)
                    # the page of the own tokens (session only)
                    page = self.verdict(self.call('get', '/user/api-tokens/', who, token=False, session=True))
                    self.record('F-03/05 matrix', f'{label} session: own tokens page', 'ALLOW' if tokens else 'DENY', page)
        self.finish()

    def test_creating_a_token_follows_tokens_in_the_database(self):
        from users.models import Token
        for who in ('plainx', 'suexc'):
            user = self.users_by_name(who)
            for tokens in (0, 1):
                self.allow(who, tokens, 1)
                before = Token.objects.filter(user=user).count()
                self.call('post', '/api/users/tokens/', who, data={'user': user.pk, 'version': 1})
                after = Token.objects.filter(user=user).count()
                self.record('F-03 db', f'{who} tokens={tokens} api=1: a token created through the token API',
                            'created' if tokens else 'not created', 'created' if after > before else 'not created')
        self.finish()

    def test_the_selector_of_a_form_is_not_the_api(self):
        """api=0: the drop-down request of a form (?brief) still works in the browser; the same list without it does not."""
        self.allow('suexc', 0, 0)
        brief = self.call('get', '/api/dcim/devices/?brief=1', 'suexc', token=False, session=True)
        self.record('F-05 helper', 'api=0 session: GET ?brief=1 (the drop-down)', 'ALLOW', self.verdict(brief))
        full = self.call('get', '/api/dcim/devices/', 'suexc', token=False, session=True)
        self.record('F-05 helper', 'api=0 session: the full list', 'DENY', self.verdict(full))
        write = self.call('post', '/api/dcim/devices/?brief=1', 'suexc', token=False, session=True, data={})
        self.record('F-05 helper', 'api=0 session: a write with ?brief is no helper', 'DENY', self.verdict(write))
        self.finish()

    def test_a_keeper_and_a_user_without_an_exception_are_not_limited_by_the_flags(self):
        from users.models import Token
        Token.objects.get_or_create(user=self.keeper, defaults={'version': 1, 'token': 'k' * 40})
        self.tokens['keeperx'] = 'k' * 40
        got = self.verdict(self.call('get', '/api/status/', 'keeperx', token=True))
        self.record('F-03/05 keeper', 'keeper TOKEN /api/status/', 'ALLOW', got)
        got = self.verdict(self.call('get', '/api/status/', 'normalx', token=True))
        self.record('F-03/05 keeper', 'a user without an exception TOKEN /api/status/ (the flags are for exceptions)',
                    'ALLOW', got)
        self.finish()


class F04OwnershipTest(audit.AuditBase):
    def setUp(self):
        super().setUp()
        for who in ('plainx', 'suexc'):
            areas.set_exception_allowed(self.users_by_name(who), self.keeper, ['password', 'tokens', 'api'])
        areas.clear_cache()

    def owners(self, who, channel):
        kw = dict(token=channel == 'token', session=channel == 'session')
        response = self.call('get', '/api/users/tokens/', who, **kw)
        return sorted({r['user']['username'] for r in response.json().get('results', [])}) \
            if response.status_code == 200 else f'HTTP{response.status_code}'

    def test_only_own_tokens_by_every_channel(self):
        for who in ('plainx', 'suexc'):
            for channel in ('token', 'session'):
                self.record('F-04 own', f'{who} {channel}: the token list holds only the own tokens', [who],
                            self.owners(who, channel))
        for who in ('plainx', 'suexc'):
            page = self.call('get', '/users/tokens/', who, token=False, session=True)
            self.record('F-04 own', f'{who}: the administrator list /users/tokens/ shows no foreign key',
                        False, 'victimx' in page.content.decode())
        self.finish()

    def test_no_foreign_token_can_be_read_changed_deleted_or_taken_over(self):
        from users.models import Token
        for who in ('plainx', 'suexc'):
            me = self.users_by_name(who)
            for channel in ('token', 'session'):
                kw = dict(token=channel == 'token', session=channel == 'session')
                victim = self.fresh_victim_token()
                for method, data, label in (('get', None, 'read'), ('patch', {'description': 'taken'}, 'change'),
                                            ('patch', {'user': me.pk}, 'take over'), ('delete', None, 'delete')):
                    response = self.call(method, f'/api/users/tokens/{victim.pk}/', who, data=data, **kw)
                    self.record('F-04 own', f'{who} {channel}: {label} a foreign token', 'DENY', self.refused(response),
                                f'HTTP {response.status_code}')
                row = Token.objects.filter(pk=victim.pk).first()
                self.record('F-04 own db', f'{who} {channel}: the foreign token is intact (exists, same owner, '
                            'same description)', ('victimx', ''),
                            (row.user.username, row.description) if row else None)
                before = Token.objects.filter(user=self.victim).count()
                self.call('post', '/api/users/tokens/', who, data={'user': self.victim.pk, 'version': 1}, **kw)
                self.record('F-04 own db', f'{who} {channel}: no token created for another person',
                            before, Token.objects.filter(user=self.victim).count())
        self.finish()

    def test_a_keeper_administers_foreign_tokens(self):
        from users.models import Token
        Token.objects.get_or_create(user=self.keeper, defaults={'version': 1, 'token': 'k' * 40})
        self.tokens['keeperx'] = 'k' * 40
        names = self.owners('keeperx', 'token')
        self.record('F-04 own', 'a keeper (the administrator of the keys) sees every key', True,
                    isinstance(names, list) and 'victimx' in names, f'{names}')
        self.finish()


class F06DefaultDenyTest(audit.AuditBase):
    URLS = None

    def setUp(self):
        super().setUp()
        areas.set_exception_allowed(self.su, self.keeper, ['password'])
        areas.clear_cache()

    def get(self, url, method='get'):
        return self.call(method, url, 'suexc', token=False, session=True)

    @override_settings(ROOT_URLCONF='netbox_user_pin.tests.test_security_audit')
    def test_known_unknown_twins_and_writes(self):
        allowed, denied = ['/user/password/'], [
            '/user/profile/', '/user/preferences/', '/user/bookmarks/', '/user/notifications/', '/user/subscriptions/',
            '/user/api-tokens/', '/user/api-tokens/add/', '/users/tokens/', '/api/users/tokens/', '/api/users/config/',
            '/extras/notifications/', '/api/extras/bookmarks/', '/api/extras/subscriptions/', '/api/extras/notifications/',
            # simulated future routes of the account and of the users app
            '/user/new-thing/', '/user/security/', '/api/users/new-endpoint/', '/users/new-admin-page/',
            # spellings of a known prefix
            '/user/%61pi-tokens/', '/user/api-tokens//', '/user/api-tokens/?x=1']
        for url in allowed:
            self.record('F-06 default deny', f'password-only exception GET {url}', 'ALLOW', self.verdict(self.get(url)))
        for url in denied:
            response = self.get(url)
            leaked = any(m in response.content for m in (b'NEW-ACCOUNT-PAGE', b'NEW-SECURITY-PAGE', b'NEW-API-ENDPOINT',
                                                         b'NEW-USERS-PAGE'))
            self.record('F-06 default deny', f'password-only exception GET {url}', 'DENY',
                        'ALLOW' if leaked else self.refused(response), f'HTTP {response.status_code}')
        for url in ('/user/new-thing/', '/api/users/new-endpoint/', '/users/new-admin-page/', '/user/api-tokens/add/'):
            for method in ('post', 'put', 'patch', 'delete'):
                response = self.get(url, method)
                leaked = b'NEW-' in response.content
                self.record('F-06 default deny', f'password-only exception {method.upper()} {url}', 'DENY',
                            'ALLOW' if leaked else self.refused(response), f'HTTP {response.status_code}')
        self.finish()

    def test_other_netbox_endpoints_keep_their_own_rules(self):
        """The default deny is for the account / users app only: data endpoints follow NetBox RBAC for an exception."""
        for url in ('/api/dcim/devices/?limit=5', '/dcim/devices/', '/api/users/users/', '/users/groups/'):
            areas.set_exception_allowed(self.su, self.keeper, ['password', 'api'])
            areas.clear_cache()
            self.record('F-06 scope', f'exception with api: {url} is not an account feature (NetBox decides)', 'ALLOW',
                        self.verdict(self.get(url)))
        self.finish()


class F08FailClosedTest(audit.AuditBase):
    """F-08: an unreadable protection state never lets anything through."""

    def sees_data(self, failure=None):
        """The REST list as a user who must not see the device; ``failure``: a patch context entered AFTER the login."""
        client = Client(raise_request_exception=False)
        client.force_login(self.users_by_name('normalx'))
        if failure is None:
            response = client.get(DEVICES)
        else:
            with failure:
                response = client.get(DEVICES)
        return response.status_code, b'SECRETDEV' in response.content

    def cold(self):
        areas._cache.update({'at': 0.0, 'ok': 0.0, 'areas': None, 'deny': False, 'keepers': frozenset(),
                             'exempt': frozenset(), 'allowed': {}, 'guests': frozenset(), 'next_expiry': None})

    SOURCES = (('areas', 'all'), ('keepers', 'filter'), ('exceptions', 'filter'), ('guests', 'values_list'))

    def failing(self, name):
        """One source of the state raises a database error (only that manager of that model)."""
        from netbox_user_pin import models
        model = {'areas': models.ProtectedArea, 'keepers': models.PolicyKeeper, 'exceptions': models.PolicyException,
                 'guests': models.PinGuest, 'memberships': models.AreaGrant, 'field rules': models.AreaFieldRule}[name]
        method = dict((n, m) for n, m in self.SOURCES).get(name, 'filter')
        return mock.patch.object(model.objects, method, side_effect=DatabaseError(f'{name} down'))

    def test_a_cold_process_refuses_when_any_part_cannot_be_read(self):
        for name, _target in self.SOURCES:
            self.cold()
            with self.failing(name):
                try:
                    got = f'returned {len(areas.active_areas())} areas'
                except areas.ProtectionUnavailable:
                    got = 'ProtectionUnavailable'
            self.record('F-08', f'cold process, {name} cannot be read: the state is refused', 'ProtectionUnavailable', got)
        self.cold()
        with mock.patch('django.db.backends.utils.CursorWrapper.execute', side_effect=OperationalError('down')):
            try:
                got = f'returned {len(areas.active_areas())} areas'
            except areas.ProtectionUnavailable:
                got = 'ProtectionUnavailable'
        self.record('F-08', 'cold process, total outage', 'ProtectionUnavailable', got)
        self.finish()

    def test_http_answers_503_and_no_data_while_the_state_is_unreadable(self):
        for name, _target in self.SOURCES:
            client = self.sees_data  # (the login happens before the failure starts)
            self.cold()
            status, leaked = self.sees_data(self.failing(name))
            self.record('F-08 http', f'cold process, {name} cannot be read: REST list', (503, False), (status, leaked))
        self.cold()
        status, leaked = self.sees_data(mock.patch('django.db.backends.utils.CursorWrapper.execute',
                                                   side_effect=OperationalError('down')))
        # a TOTAL outage fails in Django's own session / authentication before this plugin is asked: an error status
        # (500) and no data - the 503 of the plugin is for the partial failures above
        self.record('F-08 http', 'cold process, total outage: REST list (an error, no data)', (True, False),
                    (status >= 500, leaked), f'HTTP {status}')
        self.finish()

    def test_a_warm_process_keeps_the_last_state_only_for_a_while(self):
        areas.clear_cache()
        areas.active_areas()
        self.assertTrue(areas.protection_on())
        # it is time to re-read, the database fails: the last known state (protection ON) is served, never "no areas"
        areas._cache['at'] = time.monotonic() - areas.CACHE_SECONDS - 1
        with self.failing('areas'):
            still_on = areas.protection_on()
        areas._cache['at'] = time.monotonic() - areas.CACHE_SECONDS - 1
        status, leaked = self.sees_data(self.failing('areas'))
        self.record('F-08', 'warm cache + failing read: the last known protection still holds', (True, False),
                    (still_on, leaked), f'HTTP {status}')
        # ... the database is asked again soon, not after the whole cache age
        retry = areas._cache['at'] + areas.CACHE_SECONDS - time.monotonic()
        self.record('F-08', 'warm cache + failing read: the next attempt comes within RETRY_SECONDS', True,
                    0 <= retry <= areas.RETRY_SECONDS + 0.5, f'{retry:.2f}s')
        # too long without a successful read: refuse
        areas._cache['ok'] = time.monotonic() - areas.MAX_STALE - 1
        areas._cache['at'] = time.monotonic() - areas.CACHE_SECONDS - 1
        with self.failing('areas'):
            try:
                got = 'served'
                areas.active_areas()
            except areas.ProtectionUnavailable:
                got = 'ProtectionUnavailable'
        self.record('F-08', f'a state older than MAX_STALE={areas.MAX_STALE}s is not served', 'ProtectionUnavailable', got)
        # the database is back: a normal read again
        areas.clear_cache()
        self.record('F-08', 'after the recovery the protection is read again', True, areas.protection_on())
        self.finish()

    def test_a_valid_empty_list_of_areas_is_not_a_failure(self):
        from netbox_user_pin.models import ProtectedArea
        ProtectedArea.objects.all().delete()
        areas.clear_cache()
        self.record('F-08', 'a successfully read EMPTY list of areas is accepted as the state', [], areas.active_areas())
        self.finish()

    def test_a_failure_in_the_memberships_or_field_rules_is_no_permission(self):
        """These are read when a request needs them: a failure is an error answer, never an allowance."""
        from dcim.models import Device
        from users.models import ObjectPermission
        Device.objects.create(name='AGG_1', site=self.device.site, device_type=self.device.device_type,
                              role=self.device.role)
        group = areas.create_group(self.area, 'dcim.device', 'Technici', ['view'], self.owner1, records='all')
        areas.add_condition = areas.add_group_condition(group, self.owner1, 'name', 'contains', ['agg'])
        member = User.objects.create_user('memberq', 'memberq@example.com', 'x')
        perm = ObjectPermission.objects.create(name='mq', actions=['view'])
        perm.object_types.set([ContentType.objects.get_for_model(Device)])
        perm.users.set([member])
        areas.add_member(group, member, None, self.owner1)
        areas.clear_cache()

        def fetch():
            client = Client(raise_request_exception=False)
            client.force_login(member)
            response = client.get(DEVICES)
            return response.status_code, [n for n in ('AGG_1', 'SECRETDEV') if n.encode() in response.content]
        self.record('F-08 http', 'control: the member sees his row only', (200, ['AGG_1']), fetch())
        for label in ('memberships', 'field rules'):
            areas.clear_cache()
            with self.failing(label):
                status, names = fetch()
            self.record('F-08 http', f'{label} cannot be read: an error and no data', (True, []), (status >= 400, names),
                        f'HTTP {status}')
        self.finish()


class F07SharedCacheTest(audit.AuditBase):
    def setUp(self):
        super().setUp()
        from dcim.models import Device
        from users.models import ObjectPermission, Token
        self.member = User.objects.create_user('cachex', 'cachex@example.com', 'x')
        perm = ObjectPermission.objects.create(name='cache-all', actions=['view'])
        perm.object_types.set([ContentType.objects.get_for_model(Device)])
        perm.users.set([self.member])
        areas.add_exception(self.member, self.keeper, allowed=audit.API_ALLOWED)
        areas.clear_cache()

    def sees(self):
        client = Client()
        client.force_login(self.member)
        response = client.get(DEVICES)
        return response.status_code == 200 and b'SECRETDEV' in response.content

    def test_a_change_elsewhere_is_seen_within_a_fraction_of_a_second(self):
        from netbox_user_pin.models import PolicyException
        self.record('F-07', 'exception ON: data visible', True, self.sees())
        PolicyException.objects.filter(user=self.member).update(active=False)  # what another process writes
        areas._bump_shared_version()                                          # ... and what its clear_cache() does
        time.sleep(areas.VERSION_CHECK_SECONDS + 0.2)
        self.record('F-07', 'another process switched the exception OFF: this process follows within '
                    f'{areas.VERSION_CHECK_SECONDS + 0.2:.1f}s (not CACHE_SECONDS={areas.CACHE_SECONDS})', False, self.sees())
        self.finish()

    def test_a_change_that_did_not_use_the_plugin_is_seen_within_the_cache_age(self):
        from netbox_user_pin.models import PolicyException
        self.sees()
        PolicyException.objects.filter(user=self.member).update(active=False)  # raw SQL: no shared version change
        areas._cache['at'] = time.monotonic() - areas.CACHE_SECONDS - 1
        self.record('F-07', 'a raw database change (no bump): seen after at most CACHE_SECONDS', False, self.sees())
        self.finish()

    def test_the_end_of_an_exception_is_exact_without_the_job_and_without_clear_cache(self):
        from netbox_user_pin.models import PolicyException
        PolicyException.objects.filter(user=self.member).update(expires=timezone.now() + timedelta(seconds=1.5))
        areas.clear_cache()
        self.record('F-07', 'before the end: data visible', True, self.sees())
        time.sleep(1.8)
        self.record('F-07', 'after the end, no job, no clear_cache, cache age not reached: no data', False, self.sees())
        self.finish()

    def test_a_missing_shared_cache_falls_back_to_the_cache_age(self):
        with mock.patch.object(areas.shared_cache, 'get', side_effect=OSError('redis down')), \
                mock.patch.object(areas.shared_cache, 'set', side_effect=OSError('redis down')):
            areas.clear_cache()
            areas.active_areas()
            self.record('F-07', 'the shared cache is down: the guard still works (cache age as the limit)', True,
                        areas.protection_on())
        self.finish()


class F07TwoProcessesTest(__import__('django.test', fromlist=['TransactionTestCase']).TransactionTestCase):
    """F-07: a REAL second OS process (it commits to the same test database) and this process watching the effect."""

    SCRIPT = (
        "from django.contrib.auth import get_user_model\n"
        "from netbox_user_pin import areas\n"
        "U = get_user_model()\n"
        "actor, user = U.objects.get(username='tp_keeper'), U.objects.get(username='tp_user')\n"
        "areas.set_exception_enabled(user, actor, False)\n"
        "print('OTHER-PROCESS-DONE')\n")

    def test_the_other_process_switches_the_exception_off(self):
        from django.conf import settings as django_settings
        from django.db import connection
        from netbox_user_pin.models import PinSettings, PolicyException, PolicyKeeper
        PinSettings.load()
        keeper = User.objects.create_superuser('tp_keeper', 'tpk@example.com', 'x')
        PolicyKeeper.objects.create(user=keeper)
        settings_row = service.get_settings()
        settings_row.default_deny = True
        settings_row.save()
        user = User.objects.create_user('tp_user', 'tpu@example.com', 'x')
        areas.clear_cache()
        areas.add_exception(user, keeper, allowed=audit.API_ALLOWED)
        areas.clear_cache()
        self.assertTrue(areas.is_exempt(User.objects.get(pk=user.pk)))
        # the second process: the same code and database (the test database), its own memory and its own cache
        original = os.environ.get('NETBOX_CONFIGURATION', 'netbox.configuration')
        conf = (f"from {original} import *\n"
                f"DATABASE = dict(DATABASE, NAME={connection.settings_dict['NAME']!r})\n")
        with tempfile.TemporaryDirectory() as folder:
            with open(os.path.join(folder, 'userpin_second_process_conf.py'), 'w') as handle:
                handle.write(conf)
            env = dict(os.environ, NETBOX_CONFIGURATION='userpin_second_process_conf',
                       PYTHONPATH=os.pathsep.join([folder, django_settings.BASE_DIR, os.environ.get('PYTHONPATH', '')]))
            run = subprocess.run([sys.executable, os.path.join(django_settings.BASE_DIR, 'manage.py'), 'shell', '-c',
                                  self.SCRIPT], capture_output=True, text=True, env=env, cwd=django_settings.BASE_DIR,
                                 timeout=240)
        self.assertIn('OTHER-PROCESS-DONE', run.stdout, run.stderr[-1500:])
        self.assertFalse(PolicyException.objects.get(user=user).active)  # the other process really changed the row
        time.sleep(areas.VERSION_CHECK_SECONDS + 0.2)
        probe = type('P', (), {'failures': [], 'record': audit.AuditBase.record})()
        probe.record('F-07 two processes', 'the second OS process switched the exception OFF: this process no longer '
                     'treats the user as exempt after the version check', False,
                     areas.is_exempt(User.objects.get(pk=user.pk)))
        self.assertEqual(probe.failures, [], '\n'.join(probe.failures))
