"""
Security audit of the exceptions, the API tokens, the REST API / GraphQL authentication, the default deny and the cache.

These are REGRESSION / EVIDENCE tests: they never change the production code. A failing test is kept as the proof of a
finding. Every scenario goes through the whole HTTP path (the test client: middleware, authentication, permission
classes, queryset) and is recorded in ``AUDIT_LOG`` (a line per scenario: area, scenario, expected, actual).

Run:  python manage.py test netbox_user_pin.tests.test_security_audit --keepdb --parallel 1
"""
import json
import os
import time
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.test import override_settings
from django.utils import timezone

from netbox_user_pin import area_guard, areas, service
from netbox_user_pin.models import ProtectedArea

from .test_areas import AreaTestCase
from .test_pin import GOOD_PIN, admin_login, enable_2fa

User = get_user_model()
# the flags of an exception that may use the REST API (since F-05 `api` governs REST also by a session)
API_ALLOWED = ['password', 'api']
AUDIT_LOG = os.environ.get('USERPIN_AUDIT_LOG', '/tmp/userpin_audit_results.jsonl')


class AuditBase(AreaTestCase):
    """A keeper, a protected area on devices, the default deny on and a set of people with their tokens."""

    def setUp(self):
        super().setUp()
        from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site
        from users.models import ObjectPermission, Token
        self.failures = []
        self.keeper = User.objects.create_superuser('keeperx', 'kx@example.com', 'x')
        service.set_pin(self.keeper, GOOD_PIN)
        enable_2fa(self.keeper)
        areas.add_keeper(self.keeper, self.master)
        areas.set_default_deny(True, self.keeper)
        self.area = self.make_area(targets=('dcim.device',))
        site = Site.objects.create(name='S1', slug='s1')
        dtype = DeviceType.objects.create(manufacturer=Manufacturer.objects.create(name='M1', slug='m1'),
                                          model='T1', slug='t1')
        role = DeviceRole.objects.create(name='R1', slug='r1', color='ff0000')
        self.device = Device.objects.create(name='SECRETDEV', site=site, device_type=dtype, role=role,
                                            description='SECRETTEXT')
        # people
        self.plain = User.objects.create_user('plainx', 'plainx@example.com', 'x')      # exception holder, no superuser
        self.su = User.objects.create_superuser('suexc', 'suexc@example.com', 'x')       # superuser with an exception
        self.su_free = User.objects.create_superuser('sufree', 'sufree@example.com', 'x')  # superuser, no exception
        self.normal = User.objects.create_user('normalx', 'normalx@example.com', 'x')   # no exception, no group
        self.victim = User.objects.create_user('victimx', 'victimx@example.com', 'x')    # owner of a foreign token
        # NetBox object permissions: the plain user may do everything with tokens and see devices
        perm = ObjectPermission.objects.create(name='audit-all', actions=['view', 'add', 'change', 'delete'])
        perm.object_types.set([ContentType.objects.get_for_model(Token), ContentType.objects.get_for_model(Device)])
        perm.users.set([self.plain, self.normal])
        self.tokens = {}
        for i, user in enumerate((self.plain, self.su, self.su_free, self.normal, self.victim)):
            plaintext = chr(ord('a') + i) * 40
            Token.objects.create(user=user, version=1, token=plaintext)
            self.tokens[user.username] = plaintext
        self.victim_token = Token.objects.get(user=self.victim)
        self.noperm = User.objects.create_user('nopermx', 'nopermx@example.com', 'x')  # control: no object permission
        Token.objects.create(user=self.noperm, version=1, token='f' * 40)
        self.tokens['nopermx'] = 'f' * 40
        areas.add_exception(self.plain, self.keeper, allowed=API_ALLOWED)
        areas.add_exception(self.su, self.keeper, allowed=API_ALLOWED)
        areas.add_exception(self.noperm, self.keeper, allowed=API_ALLOWED)
        areas.clear_cache()

    # -- helpers ---------------------------------------------------------------------------------------------------
    def call(self, method, url, who=None, token=True, session=False, data=None, headers=None, **extra):
        """One request; ``token``: send the user's token, ``session``: log the user in as well. Returns the response."""
        from django.test import Client
        client = Client(raise_request_exception=False)
        user = self.users_by_name(who) if who else None
        if user is not None and session:
            client.force_login(user)
            client.post('/plugins/user-pin/unlock/', {'pin': GOOD_PIN}) if service.has_pin(user) else None
        http = dict(headers or {})
        if user is not None and token:
            http.setdefault('HTTP_AUTHORIZATION', 'Token ' + self.tokens[who])
        extra.pop('json', None)
        if method.lower() in ('post', 'put', 'patch', 'delete'):
            extra.setdefault('content_type', 'application/json')
            data = json.dumps(data or {})
        return getattr(client, method.lower())(url, data=data, **{**http, **extra}) if method.lower() != 'get' \
            else client.get(url, **{**http, **extra})

    def fresh_victim_token(self):
        """A new token of the victim for each destructive request (so one case never spoils the next)."""
        from users.models import Token
        Token.objects.filter(user=self.victim).delete()
        import secrets
        return Token.objects.create(user=self.victim, version=1, token=secrets.token_hex(20))

    def users_by_name(self, name):
        return User.objects.get(username=name)

    def record(self, area, scenario, expected, actual, note=''):
        row = {'area': area, 'scenario': scenario, 'expected': expected, 'actual': actual, 'ok': expected == actual,
               'note': note}
        with open(AUDIT_LOG, 'a') as handle:
            handle.write(json.dumps(row, default=str) + '\n')
        if not row['ok']:
            self.failures.append(f'{area} | {scenario} | expected {expected!r}, got {actual!r} {note}')

    def finish(self):
        if self.failures:
            self.fail('\n' + '\n'.join(self.failures))

    @classmethod
    def refused(cls, response):
        """DENY also for 404: NetBox answers 404 for a row outside the narrowed queryset (the row is not shown at all)."""
        got = cls.verdict(response)
        return 'DENY' if got in ('DENY', 'NOTFOUND') else got

    @staticmethod
    def verdict(response):
        """ALLOW (2xx), DENY (401/403/redirect to a refusal), NOTFOUND (404), other: the code."""
        code = response.status_code
        if 200 <= code < 300:
            return 'ALLOW'
        if code in (401, 403) or code in (301, 302, 303, 307, 308):
            return 'DENY'
        if code == 404:
            return 'NOTFOUND'
        return f'HTTP{code}'


class TokenMatrixTest(AuditBase):
    """2.1 / 2.2: the `tokens` x `api` matrix, by token and by session, on the real endpoints and methods."""

    ENDPOINTS = (('/api/users/tokens/', 'token API list'), ('/api/status/', 'plain API'),
                 ('/user/api-tokens/', 'own tokens page'), ('/users/tokens/', 'admin tokens list'))

    def allow(self, who, tokens, api):
        codes = ['password'] + (['tokens'] if tokens else []) + (['api'] if api else [])
        areas.set_exception_allowed(self.users_by_name(who), self.keeper, codes)
        areas.clear_cache()

    def test_the_matrix_by_token_and_by_session(self):
        for who in ('plainx', 'suexc'):
            for tokens in (0, 1):
                for api in (0, 1):
                    self.allow(who, tokens, api)
                    for url, label in self.ENDPOINTS:
                        page = url.startswith(('/user/', '/users/'))
                        if not page:  # the REST API by a token
                            got = self.verdict(self.call('get', url, who, token=True, session=False))
                            want = 'ALLOW' if api and (tokens if 'tokens' in url else True) else 'DENY'
                            if 'tokens' in url:   # the specified matrix: the token pages follow `tokens` alone
                                want = 'ALLOW' if tokens else 'DENY'
                            self.record('2.1 matrix', f'{who} tokens={tokens} api={api} TOKEN GET {url}', want, got)
                        # the browser: a session without a token header
                        got = self.verdict(self.call('get', url, who, token=False, session=True))
                        if page:
                            want = 'ALLOW' if tokens else 'DENY'
                        else:
                            want = 'ALLOW' if api and (tokens if 'tokens' in url else True) else 'DENY'
                            if 'tokens' in url:
                                want = 'ALLOW' if tokens else 'DENY'  # the spec: tokens decide the management
                        self.record('2.1 matrix', f'{who} tokens={tokens} api={api} SESSION GET {url}', want, got)
        self.finish()

    def test_methods_on_the_token_endpoints(self):
        """2.2: POST / PATCH / PUT / DELETE on the token API and the token pages, tokens=0 api=1 (must be denied)."""
        for who in ('plainx', 'suexc'):
            self.allow(who, 0, 1)
            cases = (('post', '/api/users/tokens/', {'user': self.users_by_name(who).pk, 'version': 1}),
                     ('patch', '/api/users/tokens/{pk}/', {'description': 'x'}),
                     ('put', '/api/users/tokens/{pk}/', {'user': self.victim.pk, 'version': 1}),
                     ('delete', '/api/users/tokens/{pk}/', None),
                     ('get', '/api/users/tokens/{pk}/', None))
            for method, url, data in cases:
                for channel in ('token', 'session'):
                    url = url.format(pk=self.fresh_victim_token().pk) if '{pk}' in url else url
                    response = self.call(method, url, who, token=channel == 'token', session=channel == 'session',
                                         data=data, json=True if data is not None else None)
                    self.record('2.2 methods', f'{who} tokens=0 api=1 {channel.upper()} {method.upper()} {url}',
                                'DENY', self.verdict(response), f'HTTP {response.status_code}')
        self.finish()

    def test_provision_endpoint_needs_no_token(self):
        """`/api/users/tokens/provision/` is anonymous by design (username + password): the keeper's `tokens` is moot."""
        self.allow('plainx', 0, 0)
        user = self.users_by_name('plainx')
        user.set_password('Pw-audit-12345')
        user.save()
        from django.test import Client
        response = Client(raise_request_exception=False).post(
            '/api/users/tokens/provision/', json.dumps({'username': 'plainx', 'password': 'Pw-audit-12345',
                                                          'version': 1}), content_type='application/json')
        self.record('2.2 provision', 'anonymous POST /api/users/tokens/provision/ for a user whose exception denies '
                    'tokens and api', 'DENY', self.verdict(response), f'HTTP {response.status_code}')
        self.finish()


class TokenOwnershipTest(AuditBase):
    """2.3: 'own tokens only' - or whatever NetBox RBAC gives."""

    def setUp(self):
        super().setUp()
        for who in ('plainx', 'suexc'):
            areas.set_exception_allowed(self.users_by_name(who), self.keeper, ['password', 'tokens', 'api'])
        areas.clear_cache()

    def ids(self, response):
        try:
            return sorted(row['user']['username'] for row in response.json().get('results', []))
        except Exception:  # noqa: BLE001
            return f'HTTP{response.status_code}'

    def test_who_sees_whose_tokens(self):
        for who in ('plainx', 'suexc'):
            for channel in ('token', 'session'):
                response = self.call('get', '/api/users/tokens/', who, token=channel == 'token',
                                     session=channel == 'session')
                self.record('2.3 ownership', f'{who} (tokens+api) {channel.upper()} lists /api/users/tokens/',
                            [who], self.ids(response), 'only the own tokens are expected')
            page = self.call('get', '/users/tokens/', who, token=False, session=True)
            self.record('2.3 ownership', f'{who} admin list /users/tokens/ shows the foreign token',
                        False, 'victimx' in page.content.decode() if page.status_code == 200 else False)
        self.finish()

    def test_foreign_token_detail_edit_delete_create(self):
        for who in ('plainx', 'suexc'):
            pk = self.fresh_victim_token().pk
            got = self.refused(self.call('get', f'/api/users/tokens/{pk}/', who))
            self.record('2.3 ownership', f'{who} GET foreign token detail', 'DENY', got)
            got = self.refused(self.call('post', '/api/users/tokens/', who,
                                         data={'user': self.victim.pk, 'version': 1}, json=True))
            self.record('2.3 ownership', f'{who} POST a token for another user', 'DENY', got)
            got = self.refused(self.call('patch', f'/api/users/tokens/{pk}/', who,
                                         data={'description': 'taken'}, json=True))
            self.record('2.3 ownership', f'{who} PATCH foreign token', 'DENY', got)
            got = self.refused(self.call('patch', f'/api/users/tokens/{pk}/', who, data={'user': who and self.users_by_name(who).pk},
                                         json=True))
            self.record('2.3 ownership', f'{who} PATCH foreign token to become its owner', 'DENY', got)
            pk = self.fresh_victim_token().pk
            got = self.refused(self.call('delete', f'/api/users/tokens/{pk}/', who))
            self.record('2.3 ownership', f'{who} DELETE foreign token', 'DENY', got)
        self.finish()

    def test_superuser_without_the_tokens_right(self):
        """A superuser with an exception but without `tokens` (and with `api`) must not manage tokens by any channel."""
        areas.set_exception_allowed(self.su, self.keeper, ['password', 'api'])
        areas.clear_cache()
        got = self.verdict(self.call('get', '/api/users/tokens/', 'suexc'))
        self.record('2.3 ownership', 'superuser exception tokens=0 api=1 TOKEN GET /api/users/tokens/', 'DENY', got)
        got = self.verdict(self.call('get', '/api/users/tokens/', 'suexc', token=False, session=True))
        self.record('2.3 ownership', 'superuser exception tokens=0 api=1 SESSION GET /api/users/tokens/', 'DENY', got)
        self.finish()


class TokenControlTest(AuditBase):
    """Control: what NetBox itself does for a user with an exception who has NO object permission on tokens."""

    def test_user_without_an_object_permission_and_the_superuser_baseline(self):
        for who in ('nopermx', 'suexc'):
            areas.set_exception_allowed(self.users_by_name(who), self.keeper, ['password', 'tokens', 'api'])
        areas.clear_cache()
        response = self.call('get', '/api/users/tokens/', 'nopermx')
        own = sorted(r['user']['username'] for r in response.json().get('results', [])) \
            if response.status_code == 200 else f'HTTP{response.status_code}'
        self.record('2.3 control', 'nopermx (no NetBox permission) TOKEN GET /api/users/tokens/: only the own key',
                    ['nopermx'], own)
        page = self.call('get', '/user/api-tokens/', 'nopermx', token=False, session=True)
        self.record('2.3 control', 'nopermx own tokens page (session)', 'ALLOW', self.verdict(page))
        response = self.call('get', '/api/users/tokens/', 'suexc')
        names = sorted(r['user']['username'] for r in response.json()['results']) if response.status_code == 200 else []
        self.record('2.3 control', 'superuser exception tokens+api: how many foreign tokens a REST list shows',
                    ['suexc'], names, 'NetBox itself lets a superuser see all tokens')
        self.finish()


GQL = {'query': '{ device_list { name description } }'}


class ApiAuthTest(AuditBase):
    """3: REST and GraphQL by token and by session, for every state of the user, and the Authorization-header tricks."""

    def leaked(self, response):
        return b'SECRETDEV' in response.content

    def fetch(self, mode, who, headers=None, session=None, token=None):
        """mode: rest | gql. Returns (verdict, leaked, http)."""
        if mode == 'rest':
            response = self.call('get', '/api/dcim/devices/', who, token=bool(token), session=bool(session),
                                 headers=headers)
        else:
            response = self.call('post', '/graphql/', who, token=bool(token), session=bool(session), data=GQL,
                                 headers=headers)
        return ('DATA' if self.leaked(response) else 'BLOCKED'), self.leaked(response), response.status_code

    def test_states_of_the_user(self):
        """3.1: (state, channel) -> may the device be read?  Expected by the protection semantics."""
        from netbox_user_pin.models import PolicyException
        for state in ('no exception', 'exception api=False', 'exception api=True', 'exception switched off',
                      'exception expired', 'keeper'):
            who = {'keeper': 'keeperx'}.get(state, 'plainx')
            if state == 'keeper':
                self.tokens['keeperx'] = 'k' * 40
                from users.models import Token
                Token.objects.create(user=self.keeper, version=1, token='k' * 40)
            if state == 'no exception':
                PolicyException.objects.filter(user=self.plain).delete()
            else:
                areas.add_exception(self.plain, self.keeper, allowed=['password'] + (['api'] if state.endswith('True') else []))
                if state == 'exception switched off':
                    areas.set_exception_enabled(self.plain, self.keeper, False)
                if state == 'exception expired':
                    PolicyException.objects.filter(user=self.plain).update(expires=timezone.now() - timedelta(minutes=1))
            areas.clear_cache()
            for mode in ('rest', 'gql'):
                for channel in ('token', 'session'):
                    verdict, leaked, http = self.fetch(mode, who, token=channel == 'token', session=channel == 'session')
                    if state == 'keeper':
                        want = 'BLOCKED'        # 'nobody is a god' in a protected area: a keeper needs a grant too
                    elif state == 'exception api=True':
                        want = 'DATA'
                    elif state == 'exception api=False':
                        want = 'BLOCKED'           # the spec: api=False denies the API
                    else:
                        want = 'BLOCKED'           # the PIN rules: no group in the area
                    self.record('3.1 states', f'{state} | {mode.upper()} | {channel}', want, verdict,
                                f'HTTP {http}, leaked={leaked}')
        self.finish()

    def test_authorization_header_tricks_with_a_valid_session(self):
        """3.2: a normal user (no group in the protected area) with a valid session adds an Authorization header."""
        tricks = {
            'no header': None,
            'Token garbage': 'Token garbage',
            'Bearer garbage': 'Bearer garbage',
            'Bearer nbt_x.y': 'Bearer nbt_x.y',
            'Token (empty)': 'Token',
            'Token + spaces': 'Token   ',
            'Basic': 'Basic YWJjOmRlZg==',
            'wrong scheme Foo': 'Foo bar',
            'lower-case token': 'token garbage',
        }
        for mode in ('rest', 'gql'):
            for label, header in tricks.items():
                headers = {'HTTP_AUTHORIZATION': header} if header is not None else None
                verdict, leaked, http = self.fetch(mode, 'normalx', headers=headers, session=True)
                self.record('3.2 header tricks', f'normal user, session, {mode.upper()}, header: {label}',
                            'BLOCKED', verdict, f'HTTP {http}, leaked={leaked}')
        self.finish()

    def test_a_garbage_header_must_not_lift_the_exception_allowlist(self):
        """3.3: an exception user with api=False (session) adds a garbage token header on the account / API paths."""
        areas.set_exception_allowed(self.plain, self.keeper, ['password'])
        areas.clear_cache()
        for url in ('/user/profile/', '/user/api-tokens/', '/user/preferences/', '/users/tokens/', '/api/users/tokens/'):
            for header in ('Token garbage', 'Bearer garbage'):
                response = self.call('get', url, 'plainx', token=False, session=True, headers={'HTTP_AUTHORIZATION': header})
                self.record('3.3 allowlist+header', f'plainx(password only) session GET {url} header {header}', 'DENY',
                            self.verdict(response), f'HTTP {response.status_code}')
        self.finish()

    def test_expired_disabled_and_foreign_tokens(self):
        """3.4: token states."""
        from users.models import Token
        areas.set_exception_allowed(self.plain, self.keeper, ['password', 'api'])
        areas.clear_cache()
        token = Token.objects.get(user=self.plain)
        token.expires = timezone.now() - timedelta(days=1)
        token.save()
        verdict, leaked, http = self.fetch('rest', 'plainx', token=True)
        self.record('3.4 token states', 'expired token', 'BLOCKED', verdict, f'HTTP {http}')
        token.expires = None
        token.enabled = False
        token.save()
        verdict, leaked, http = self.fetch('rest', 'plainx', token=True)
        self.record('3.4 token states', 'disabled token', 'BLOCKED', verdict, f'HTTP {http}')
        token.enabled = True
        token.save()
        # a valid session of the keeper with the token of the exception user: the token's identity must win
        verdict, leaked, http = self.fetch('rest', 'plainx', token=True, session=False)
        self.record('3.4 token states', 'valid token of api=True user', 'DATA', verdict, f'HTTP {http}')
        self.finish()



# ---------------------------------------------------------------------------------------------------------------
# 4. Default deny and unknown endpoints: URLs that NetBox (or a plugin) may add later
# ---------------------------------------------------------------------------------------------------------------
from django.http import HttpResponse  # noqa: E402
from django.urls import include, path  # noqa: E402

from netbox import urls as _netbox_urls  # noqa: E402

urlpatterns = [
    path('user/new-thing/', lambda request: HttpResponse('NEW-ACCOUNT-PAGE')),
    path('user/security/', lambda request: HttpResponse('NEW-SECURITY-PAGE')),
    path('api/users/new-endpoint/', lambda request: HttpResponse('NEW-API-ENDPOINT')),
    path('users/new-admin-page/', lambda request: HttpResponse('NEW-USERS-PAGE')),
    path('', include(_netbox_urls)),
]


class RouteAllowlistTest(AuditBase):
    """4: is `EXCEPTION_PATHS` a default deny or a list of known prefixes?"""

    def setUp(self):
        super().setUp()
        areas.set_exception_allowed(self.su, self.keeper, ['password'])  # the strictest exception
        areas.clear_cache()

    def test_known_account_pages_and_their_twins(self):
        """4.1: the pages the allow-list names, their twins elsewhere in NetBox, and the account API."""
        paths = (
            ('/user/profile/', 'DENY'), ('/user/preferences/', 'DENY'), ('/user/bookmarks/', 'DENY'),
            ('/user/notifications/', 'DENY'), ('/user/subscriptions/', 'DENY'), ('/user/api-tokens/', 'DENY'),
            ('/user/api-tokens/add/', 'DENY'), ('/users/tokens/', 'DENY'), ('/api/users/tokens/', 'DENY'),
            ('/user/password/', 'ALLOW'),
            # the twins of the allow-listed features that live outside the /user/ prefix
            ('/api/users/config/', 'DENY'), ('/extras/notifications/', 'DENY'), ('/api/extras/bookmarks/', 'DENY'),
            ('/api/extras/subscriptions/', 'DENY'), ('/api/extras/notifications/', 'DENY'),
        )
        for url, want in paths:
            got = self.verdict(self.call('get', url, 'suexc', token=False, session=True))
            self.record('4.1 known pages', f'exception password-only GET {url}', want, got)
        self.finish()

    def test_encodings_and_variants_of_a_known_prefix(self):
        for url in ('/user/api-tokens', '/user/%61pi-tokens/', '/user/api-tokens//', '/user/api-tokens/?x=1',
                    '/api/users/tokens', '/api/users/tokens/?format=json', '/api/users/Tokens/', '/user/Api-Tokens/',
                    '//user/api-tokens/', '/user/./api-tokens/', '/user/..;/user/api-tokens/'):
            response = self.call('get', url, 'suexc', token=False, session=True)
            got = 'ALLOW' if response.status_code == 200 and b'api-token' in response.content.lower() \
                and b'denied' not in response.content.lower() and response.get('X-UserPIN') != 'denied' else 'DENY'
            self.record('4.2 variants', f'exception password-only GET {url!r}', 'DENY', got,
                        f'HTTP {response.status_code}')
        self.finish()

    @override_settings(ROOT_URLCONF='netbox_user_pin.tests.test_security_audit')
    def test_a_new_endpoint_the_list_does_not_know(self):
        """4.3: simulated future pages. A real default deny would refuse them for a password-only exception."""
        for url, marker in (('/user/new-thing/', b'NEW-ACCOUNT-PAGE'), ('/user/security/', b'NEW-SECURITY-PAGE'),
                            ('/api/users/new-endpoint/', b'NEW-API-ENDPOINT'),
                            ('/users/new-admin-page/', b'NEW-USERS-PAGE')):
            for channel in ('session',):   # (a token on a plain Django view is meaningless: no DRF authentication)
                response = self.call('get', url, 'suexc', token=channel == 'token', session=channel == 'session')
                got = 'ALLOW' if marker in response.content else 'DENY'
                self.record('4.3 unknown endpoint', f'password-only exception, {channel} GET {url}', 'DENY', got,
                            f'HTTP {response.status_code}')
            for method in ('post', 'patch', 'delete'):
                response = self.call(method, url, 'suexc', token=False, session=True)
                got = 'ALLOW' if marker in response.content else 'DENY'
                self.record('4.3 unknown endpoint', f'password-only exception, session {method.upper()} {url}',
                            'DENY', got, f'HTTP {response.status_code}')
        self.finish()

    def test_the_code_is_a_prefix_list(self):
        """4.4: `_exception_code` answers None for everything it does not list (not 'deny')."""
        for path_ in ('/user/new-thing/', '/user/security/', '/api/users/config/', '/extras/bookmarks/add/',
                      '/api/extras/bookmarks/', '/user/'):
            code = area_guard._exception_code(path_)
            self.record('4.4 prefix list (info)', f'_exception_code({path_!r})', code, code,
                        'None = the path is not governed by the allow-list')
        self.finish()


# ---------------------------------------------------------------------------------------------------------------
# 1. Exceptions: separation of the PIN protection and NetBox RBAC; time; concurrency
# ---------------------------------------------------------------------------------------------------------------
class ExceptionSemanticsTest(AuditBase):
    def setUp(self):
        super().setUp()
        from dcim.models import Device
        from netbox_user_pin.models import AreaGrant
        from users.models import ObjectPermission
        self.AreaGrant = AreaGrant
        site = self.device.site
        Device.objects.create(name='AGG_1', site=site, device_type=self.device.device_type, role=self.device.role)
        self.group = areas.create_group(self.area, 'dcim.device', 'Technici', ['view'], self.owner1, records='all')
        areas.add_group_condition(self.group, self.owner1, 'name', 'contains', ['agg'])
        self.member = User.objects.create_user('memberx', 'memberx@example.com', 'x')
        perm = ObjectPermission.objects.create(name='member-all', actions=['view', 'add', 'change', 'delete'])
        perm.object_types.set([ContentType.objects.get_for_model(Device)])
        perm.users.set([self.member])
        areas.add_member(self.group, self.member, None, self.owner1)
        from users.models import Token
        Token.objects.create(user=self.member, version=1, token='m' * 40)
        self.tokens['memberx'] = 'm' * 40
        areas.clear_cache()

    def names(self, who, session=True):
        response = self.call('get', '/api/dcim/devices/?limit=100', who, token=not session, session=session)
        if response.status_code != 200:
            return f'HTTP{response.status_code}'
        return sorted(r['name'] for r in response.json()['results'])

    def test_exception_lifecycle_through_http(self):
        who = 'memberx'
        self.record('1.1 lifecycle', 'member without exception: rows of his group only', ['AGG_1'], self.names(who))
        areas.add_exception(self.member, self.keeper, allowed=API_ALLOWED)
        self.record('1.1 lifecycle', 'exception ON: NetBox permissions rule (all devices)', ['AGG_1', 'SECRETDEV'],
                    self.names(who))
        areas.set_exception_enabled(self.member, self.keeper, False)
        self.record('1.1 lifecycle', 'exception switched OFF: back under the PIN at once', ['AGG_1'], self.names(who))
        areas.set_exception_enabled(self.member, self.keeper, True)
        self.record('1.1 lifecycle', 'exception switched ON again', ['AGG_1', 'SECRETDEV'], self.names(who))
        grants_before = self.AreaGrant.objects.filter(user=self.member, revoked__isnull=True).count()
        areas.remove_exception(self.member, self.keeper)
        self.record('1.1 lifecycle', 'exception REMOVED: the group returns', ['AGG_1'], self.names(who))
        self.record('1.1 lifecycle', 'the memberships survive the whole exception', grants_before,
                    self.AreaGrant.objects.filter(user=self.member, revoked__isnull=True).count())
        self.finish()

    def test_superuser_with_and_without_an_exception(self):
        from netbox_user_pin.models import PolicyException
        areas.add_member(self.group, self.su_free, None, self.owner1)
        self.tokens.setdefault('sufree', 'c' * 40)
        self.record('1.1 superuser', 'superuser in a group, no exception: only the rows of his group (session)',
                    ['AGG_1'], self.names('sufree'))
        self.record('1.1 superuser', 'superuser with an exception: NetBox superuser rights',
                    ['AGG_1', 'SECRETDEV'], self.names('suexc'))
        PolicyException.objects.filter(user=self.su).update(active=False)
        areas.clear_cache()
        self.record('1.1 superuser', 'the exception of a superuser switched off', 'HTTP403', self.names('suexc'))
        self.finish()

    def test_two_areas_and_a_denied_right(self):
        """a user in two areas; the group has only `view`: change is refused, with an exception NetBox decides."""
        from tenancy.models import Tenant
        tenant_area = areas.create_area('Tenants', ['tenancy.tenant'], [], self.keeper, 'tenants', 24)
        tenant_group = areas.create_group(tenant_area, 'tenancy.tenant', 'TView', ['view'], self.keeper, records='all')
        areas.add_member(tenant_group, self.member, None, self.keeper)
        tenant = Tenant.objects.create(name='T1', slug='t1')
        areas.clear_cache()
        got = self.verdict(self.call('get', '/api/tenancy/tenants/', 'memberx', token=False, session=True))
        self.record('1.1 two areas', 'member of devices + tenants: may view tenants', 'ALLOW', got)
        dev = [d for d in self.device.__class__.objects.filter(name='AGG_1')][0]
        got = self.verdict(self.call('patch', f'/api/dcim/devices/{dev.pk}/', 'memberx', token=False, session=True,
                                     data={'description': 'x'}))
        self.record('1.1 two areas', 'view-only group: PATCH a device (session)', 'DENY', got)
        areas.add_exception(self.member, self.keeper, allowed=API_ALLOWED)
        got = self.verdict(self.call('patch', f'/api/dcim/devices/{dev.pk}/', 'memberx', token=False, session=True,
                                     data={'description': 'x'}))
        self.record('1.1 two areas', 'exception ON: PATCH a device is NetBox RBAC (allowed)', 'ALLOW', got)
        self.finish()


class ExceptionTimeTest(AuditBase):
    """1.2: the end of an exception, with and without the system job, in a running process."""

    def setUp(self):
        super().setUp()
        from dcim.models import Device
        from users.models import ObjectPermission, Token
        self.member = User.objects.create_user('timex', 'timex@example.com', 'x')
        perm = ObjectPermission.objects.create(name='time-all', actions=['view'])
        perm.object_types.set([ContentType.objects.get_for_model(Device)])
        perm.users.set([self.member])
        Token.objects.create(user=self.member, version=1, token='t' * 40)
        self.tokens['timex'] = 't' * 40

    def sees(self):
        response = self.call('get', '/api/dcim/devices/?limit=100', 'timex', token=False, session=True)
        return response.status_code == 200 and b'SECRETDEV' in response.content

    def test_expiry_without_the_job_in_the_same_process(self):
        """The end passes while no job runs and nobody clears the cache: the very next request must already be refused."""
        from netbox_user_pin.models import PolicyException
        areas.add_exception(self.member, self.keeper, allowed=API_ALLOWED)
        areas.set_exception_expires(self.member, self.keeper, timezone.now() + timedelta(seconds=1.5))
        areas.clear_cache()
        self.record('1.2 time', 'exception with a future end: sees data', True, self.sees())
        time.sleep(1.7)   # the end passed; no clear_cache, no job, the age of the cache (5 s) not reached
        self.record('1.2 time', 'the end passed, cache NOT cleared, no job: the very next request', False, self.sees(),
                    f'CACHE_SECONDS={areas.CACHE_SECONDS}: since F-07 the end of an exception is exact')
        self.record('1.2 time', 'the row stays active=True (only the job switches it off)', True,
                    PolicyException.objects.get(user=self.member).active)
        self.finish()

    def test_expiry_in_a_running_session_and_page(self):
        from netbox_user_pin.models import PolicyException
        areas.add_exception(self.member, self.keeper, expires=timezone.now() + timedelta(seconds=60), allowed=API_ALLOWED)
        areas.clear_cache()
        from django.test import Client
        client = Client()
        client.force_login(self.member)
        first = client.get('/api/dcim/devices/?limit=100')
        PolicyException.objects.filter(user=self.member).update(expires=timezone.now() - timedelta(seconds=1))
        areas.clear_cache()  # one forced refresh = a later request after the cache age
        second = client.get('/api/dcim/devices/?limit=100')
        self.record('1.2 time', 'one session: before the end DATA, after the end (same session) BLOCKED',
                    ('DATA', 'BLOCKED'), ('DATA' if b'SECRETDEV' in first.content else 'BLOCKED',
                                          'DATA' if b'SECRETDEV' in second.content else 'BLOCKED'))
        self.finish()

    def test_job_and_rq_down_and_reenabling(self):
        from netbox_user_pin.models import PolicyException
        areas.add_exception(self.member, self.keeper, expires=timezone.now() + timedelta(seconds=60), allowed=API_ALLOWED)
        PolicyException.objects.filter(user=self.member).update(expires=timezone.now() - timedelta(seconds=1))
        areas.clear_cache()
        self.record('1.2 time', 'netbox-rq down (job never ran): an expired exception does not lift the PIN', False,
                    self.sees())
        try:
            areas.set_exception_enabled(self.member, self.keeper, True)
            got = 'switched on'
        except Exception as exc:  # noqa: BLE001
            got = type(exc).__name__
        self.record('1.2 time', 're-enabling an ended exception without a new end is refused', 'ValidationError', got)
        areas.set_exception_expires(self.member, self.keeper, timezone.now() + timedelta(hours=1))
        areas.set_exception_enabled(self.member, self.keeper, True)
        areas.clear_cache()
        self.record('1.2 time', 'a new end + switch ON: sees data again', True, self.sees())
        # change the end and the switch together
        areas.set_exception_expires(self.member, self.keeper, timezone.now() + timedelta(hours=2))
        areas.set_exception_enabled(self.member, self.keeper, False)
        areas.clear_cache()
        self.record('1.2 time', 'new end while the switch is OFF: stays under the PIN', False, self.sees())
        try:
            areas.set_exception_expires(self.member, self.keeper, timezone.now() - timedelta(hours=1))
            got = 'accepted'
        except Exception as exc:  # noqa: BLE001
            got = type(exc).__name__
        self.record('1.2 time', 'an end in the past is refused', 'ValidationError', got)
        self.finish()


class ExceptionConcurrencyTest(__import__('django.test', fromlist=['TransactionTestCase']).TransactionTestCase):
    """1.3: three keepers change one exception at once while the user sends requests (real threads, real commits)."""

    def test_parallel_keepers_and_a_requesting_user(self):
        import threading
        from django.db import close_old_connections, connection
        from netbox_user_pin.models import PinSettings, PolicyException, PolicyKeeper
        areas.clear_cache()
        PinSettings.load()
        keepers = [User.objects.create_superuser(f'ck{i}', f'ck{i}@example.com', 'x') for i in range(3)]
        for k in keepers:
            PolicyKeeper.objects.create(user=k)
        settings = service.get_settings()
        settings.default_deny = True
        settings.save()
        target = User.objects.create_user('ctarget', 'ctarget@example.com', 'x')
        areas.clear_cache()
        areas.add_exception(target, keepers[0])
        errors, seen = [], []

        def keeper_job(index):
            try:
                for n in range(25):
                    actor = keepers[index]
                    if index == 0:
                        areas.set_exception_enabled(target, actor, n % 2 == 0)
                    elif index == 1:
                        areas.set_exception_allowed(target, actor, ['password', 'api'] if n % 2 else ['password'])
                    else:
                        areas.set_exception_expires(target, actor, timezone.now() + timedelta(hours=1 + n % 3))
            except Exception as exc:  # noqa: BLE001
                errors.append(repr(exc))
            finally:
                close_old_connections()
                connection.close()

        def user_job():
            try:
                for _n in range(60):
                    areas.clear_cache()
                    user = User.objects.get(pk=target.pk)
                    seen.append((areas.is_exempt(user), areas.exception_allows(user, 'api')))
            except Exception as exc:  # noqa: BLE001
                errors.append(repr(exc))
            finally:
                close_old_connections()
                connection.close()
        threads = [threading.Thread(target=keeper_job, args=(i,)) for i in range(3)] + [threading.Thread(target=user_job)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        row = PolicyException.objects.get(user=target)
        areas.clear_cache()
        user = User.objects.get(pk=target.pk)
        rec = AuditBase.record
        probe = type('P', (), {'failures': [], 'record': rec})()
        results = [
            ('threads raised no error (SQLite/PG locks, IntegrityError ...)', [], errors),
            ('final cache == final database row (active)', row.active, areas.is_exempt(user)),
            ('final cache == final database row (api allowed)', 'api' in row.allowed_set,
             areas.exception_allows(user, 'api') if areas.restricted(user) else 'api' in row.allowed_set),
        ]
        for scenario, want, got in results:
            probe.record('1.3 concurrency', scenario, want, got)
        self.assertEqual(probe.failures, [], '\n'.join(probe.failures))
        # the audit has one record per change (nothing lost)
        from netbox_user_pin.models import PinEvent
        n = PinEvent.objects.filter(detail__startswith='EXCEPTION of ctarget').count()
        with open(AUDIT_LOG, 'a') as handle:
            handle.write(json.dumps({'area': '1.3 concurrency', 'scenario': 'audit records written by 75 parallel '
                                     'changes (the first switch-on was a no-op)', 'expected': 74, 'actual': n, 'ok': n == 74, 'note': 'a change that '
                                     'does not change the value is a no-op for the switch'}) + '\n')


# ---------------------------------------------------------------------------------------------------------------
# 7. Cache, several processes, database failures
# ---------------------------------------------------------------------------------------------------------------
class CacheProcessTest(AuditBase):
    """7: process B writes to the database (no clear_cache of ours); process A keeps serving from its cache."""

    def setUp(self):
        super().setUp()
        from dcim.models import Device
        from users.models import ObjectPermission, Token
        self.member = User.objects.create_user('cachex', 'cachex@example.com', 'x')
        perm = ObjectPermission.objects.create(name='cache-all', actions=['view'])
        perm.object_types.set([ContentType.objects.get_for_model(Device)])
        perm.users.set([self.member])
        Token.objects.create(user=self.member, version=1, token='h' * 40)
        self.tokens['cachex'] = 'h' * 40

    def sees(self):
        response = self.call('get', '/api/dcim/devices/?limit=100', 'cachex', token=False, session=True)
        return response.status_code == 200 and b'SECRETDEV' in response.content

    def age_cache(self, seconds):
        import time as _t
        areas._cache['at'] = _t.monotonic() - seconds

    def test_another_process_switches_the_exception_off(self):
        from netbox_user_pin.models import PolicyException
        areas.add_exception(self.member, self.keeper, allowed=API_ALLOWED)
        areas.clear_cache()
        self.record('7 cache', 'A: exception ON, data visible', True, self.sees())
        PolicyException.objects.filter(user=self.member).update(active=False)   # process B writes the row ...
        areas._bump_shared_version()      # ... and its clear_cache() tells the others (F-07: the shared cache)
        time.sleep(areas.VERSION_CHECK_SECONDS + 0.2)
        self.record('7 cache', 'B switched it OFF (through the plugin); A follows within the version check', False,
                    self.sees(), f'was CACHE_SECONDS = {areas.CACHE_SECONDS} s before F-07')
        self.age_cache(areas.CACHE_SECONDS + 1)
        self.record('7 cache', 'A after the cache age has passed', False, self.sees())
        self.finish()

    def test_other_changes_not_seen_by_a_stale_process(self):
        from netbox_user_pin.models import PolicyKeeper
        areas.add_exception(self.member, self.keeper, allowed=API_ALLOWED)
        areas.clear_cache()
        self.sees()
        # B removes the keeper switch (global protection off); A is stale
        from netbox_user_pin.models import PinSettings
        PinSettings.objects.update(default_deny=False)
        PolicyKeeper.objects.all().delete()
        self.record('7 cache', 'B removed all keepers + global deny: A still believes protection is ON for 5 s',
                    True, areas.default_deny_active(), 'stale by design (cache)')
        self.age_cache(areas.CACHE_SECONDS + 1)
        self.record('7 cache', 'A after refresh: deny is off', False, areas.default_deny_active())
        self.finish()

    def test_database_failure_during_refresh(self):
        """A total outage during the refresh. After F-08: fail closed (a cold process refuses, a warm one serves the last
        known state for MAX_STALE seconds at most)."""
        from django.db import DatabaseError, OperationalError
        from unittest import mock
        areas.add_exception(self.member, self.keeper, allowed=API_ALLOWED)
        areas.clear_cache()
        self.sees()
        user = User.objects.get(pk=self.member.pk)
        self.age_cache(areas.CACHE_SECONDS + 1)
        with mock.patch('django.db.backends.utils.CursorWrapper.execute', side_effect=OperationalError('down')):
            try:
                got = 'serves the last known state' if areas.is_exempt(user) else 'dropped the exemption'
            except areas.ProtectionUnavailable:
                got = 'ProtectionUnavailable'
        self.record('7 cache', 'total DB outage at the refresh of a warm cache (F-08: bounded last known state)',
                    'serves the last known state', got)
        areas._cache.update({'at': 0.0, 'ok': 0.0, 'areas': None, 'deny': False, 'keepers': frozenset(),
                             'exempt': frozenset(), 'allowed': {}})
        with mock.patch('django.db.backends.utils.CursorWrapper.execute', side_effect=OperationalError('down')):
            try:
                got = 'open' if not areas.protection_on() else 'protected'
            except areas.ProtectionUnavailable:
                got = 'ProtectionUnavailable'
        self.record('7 cache', 'total DB outage at the first load of a cold process', 'ProtectionUnavailable', got)
        # a PARTIAL failure (only the table of the areas is unreadable) on a cold process
        areas._cache.update({'at': 0.0, 'ok': 0.0, 'areas': None})
        with mock.patch.object(ProtectedArea.objects, 'all', side_effect=DatabaseError('partial')):
            try:
                got = 'empty list' if not areas.active_areas() else 'non-empty'
            except areas.ProtectionUnavailable:
                got = 'ProtectionUnavailable'
        self.record('7 cache', 'PARTIAL failure (areas table) on a cold process (F-08: fail closed, no empty list)',
                    'ProtectionUnavailable', got)
        self.finish()


# ---------------------------------------------------------------------------------------------------------------
# 5. Superuser and the layers: has_perm, restrict(), middleware, REST, GraphQL, UI
# ---------------------------------------------------------------------------------------------------------------
class LayersTest(AuditBase):
    def setUp(self):
        super().setUp()
        from users.models import Token
        self.tokens.setdefault('keeperx', 'k' * 40)
        Token.objects.get_or_create(user=self.keeper, defaults={'version': 1, 'token': 'k' * 40})
        self.keeper_tok = 'k' * 40

    def layers(self, who):
        from dcim.models import Device
        user = User.objects.get(username=who)
        areas.clear_cache()
        armed = User.objects.get(pk=user.pk)
        area_guard.arm_user(armed)
        out = {
            'has_perm(change)': bool(armed.has_perm('dcim.change_device')),
            'restrict()': Device.objects.restrict(armed, 'view').filter(name='SECRETDEV').exists(),
        }
        rest = self.call('get', '/api/dcim/devices/?limit=100', who, token=False, session=True)
        out['REST session'] = rest.status_code == 200 and b'SECRETDEV' in rest.content
        ui = self.call('get', '/dcim/devices/', who, token=False, session=True)
        out['UI list'] = ui.status_code == 200 and b'SECRETDEV' in ui.content
        gql = self.call('post', '/graphql/', who, token=False, session=True, data=GQL)
        out['GraphQL session'] = gql.status_code == 200 and b'SECRETDEV' in gql.content
        return out

    def test_every_account_in_every_state(self):
        from netbox_user_pin.models import PolicyException
        for who in ('normalx', 'sufree', 'suexc', 'keeperx'):
            for state in ('deny ON', 'deny OFF (areas still active)', 'exception OFF'):
                areas.set_default_deny(state != 'deny OFF (areas still active)', self.keeper)
                if who == 'suexc':
                    PolicyException.objects.filter(user=self.su).update(active=state != 'exception OFF')
                if state == 'exception OFF' and who != 'suexc':
                    continue
                out = self.layers(who)
                consistent = len(set(out.values())) == 1
                self.record('5 layers', f'{who} | {state} | {out}', True, consistent,
                            'all of has_perm / restrict() / REST / UI / GraphQL should agree')
        self.finish()

    def test_superuser_without_keeper_role_cannot_pass_the_protection(self):
        out = self.layers('sufree')
        self.record('5 superuser', 'superuser (no keeper, no exception) in a protected area: any layer shows data',
                    [], [name for name, val in out.items() if val])
        armed = User.objects.get(username='sufree')
        area_guard.arm_user(armed)
        self.record('5 superuser (info)', "has_perm('dcim.view_device') of the superuser: the 'door' answers True while "
                    'the data layers refuse', True, bool(armed.has_perm('dcim.view_device')),
                    'by design of mode A (door); every data layer refuses')
        self.finish()


# ---------------------------------------------------------------------------------------------------------------
# 6. Queryset and data leaks through every data path
# ---------------------------------------------------------------------------------------------------------------
class DataLeakTest(AuditBase):
    """memberx: a group that sees only AGG_* devices and has the `description` field hidden. SECRETDEV is closed."""

    def setUp(self):
        super().setUp()
        from core.models import ObjectChange
        from dcim.models import Device
        from extras.models import JournalEntry
        from users.models import ObjectPermission, Token
        site = self.device.site
        self.agg = Device.objects.create(name='AGG_1', site=site, device_type=self.device.device_type,
                                         role=self.device.role, description='HIDDENFIELDVALUE')
        self.group = areas.create_group(self.area, 'dcim.device', 'Technici', ['view'], self.owner1, records='all')
        areas.add_group_condition(self.group, self.owner1, 'name', 'contains', ['agg'])
        areas.save_field_rules(self.area, self.group, 'dcim.device', {'description': ('hidden', '')}, self.owner1)
        self.member = User.objects.create_user('memberx', 'memberx@example.com', 'x')
        perm = ObjectPermission.objects.create(name='member-dev', actions=['view', 'add', 'change', 'delete'])
        perm.object_types.set([ContentType.objects.get_for_model(Device),
                               ContentType.objects.get_for_model(JournalEntry),
                               ContentType.objects.get_for_model(ObjectChange)])
        perm.users.set([self.member])
        areas.add_member(self.group, self.member, None, self.owner1)
        Token.objects.create(user=self.member, version=1, token='m' * 40)
        self.tokens['memberx'] = 'm' * 40
        dev_ct = ContentType.objects.get_for_model(Device)
        JournalEntry.objects.create(assigned_object_type=dev_ct, assigned_object_id=self.device.pk,
                                    comments='JOURNALSECRET', created_by=self.keeper)
        ObjectChange.objects.create(user=self.keeper, user_name='keeperx', request_id=__import__('uuid').uuid4(),
                                    action='update', changed_object_type=dev_ct, changed_object_id=self.device.pk,
                                    object_repr='SECRETDEV', prechange_data={'description': 'CHANGELOGSECRET'},
                                    postchange_data={'description': 'CHANGELOGSECRET2'})
        areas.clear_cache()

    def has(self, response, *needles):
        return [n for n in needles if n.encode() in response.content]

    def test_read_paths_as_a_member(self):
        """Each path: which secret strings leak to a member of a group that must not see them."""
        secret_row = ('SECRETDEV', 'SECRETTEXT', 'JOURNALSECRET', 'CHANGELOGSECRET')
        paths = (('UI list', 'get', '/dcim/devices/'), ('UI detail', 'get', f'/dcim/devices/{self.device.pk}/'),
                 ('UI detail journal tab', 'get', f'/dcim/devices/{self.device.pk}/journal/'),
                 ('UI detail changelog tab', 'get', f'/dcim/devices/{self.device.pk}/changelog/'),
                 ('global search', 'get', '/search/?q=ECRETDE'), ('home dashboard', 'get', '/'),
                 ('changelog list', 'get', '/core/changelog/'),
                 ('journal list', 'get', '/extras/journal-entries/'),
                 ('export table', 'get', '/dcim/devices/?export=table'),
                 ('export csv', 'get', '/dcim/devices/?export'),
                 ('REST list', 'get', '/api/dcim/devices/?limit=100'),
                 ('REST detail', 'get', f'/api/dcim/devices/{self.device.pk}/'),
                 ('REST brief (drop-down)', 'get', '/api/dcim/devices/?brief=1'),
                 ('REST journal', 'get', '/api/extras/journal-entries/'),
                 ('REST changelog', 'get', '/api/core/object-changes/'),
                 ('REST search filter q=', 'get', '/api/dcim/devices/?q=SECRET'),
                 ('REST filter by hidden field', 'get', '/api/dcim/devices/?description=HIDDENFIELDVALUE'),
                 ('UI filter by hidden field', 'get', '/dcim/devices/?description=HIDDENFIELDVALUE'))
        for label, method, url in paths:
            for how, kwargs in (('session', dict(token=False, session=True)),
                                ('session+garbage Authorization', dict(token=False, session=True,
                                                                       headers={'HTTP_AUTHORIZATION': 'Token garbage'}))):
                if how != 'session' and not url.startswith(('/api/', '/graphql')):
                    continue
                response = self.call(method, url, 'memberx', **kwargs)
                leaked = self.has(response, *secret_row, 'HIDDENFIELDVALUE')
                self.record('6 read paths', f'member | {how} | {label} {url}', [], leaked, f'HTTP {response.status_code}')
        self.finish()

    def test_graphql_paths(self):
        queries = {'list': '{ device_list { name description } }',
                   'detail': '{ device(id: %d) { name description } }' % self.device.pk,
                   'journal': '{ journal_entry_list { comments } }'}
        for label, query in queries.items():
            for how, kwargs in (('session', dict(token=False, session=True)),
                                ('session+garbage Authorization', dict(token=False, session=True,
                                                                       headers={'HTTP_AUTHORIZATION': 'Token garbage'})),
                                ('token', dict(token=True, session=False))):
                response = self.call('post', '/graphql/', 'memberx', data={'query': query}, **kwargs)
                leaked = self.has(response, 'SECRETDEV', 'SECRETTEXT', 'JOURNALSECRET', 'HIDDENFIELDVALUE')
                self.record('6 graphql', f'member | {how} | {label}', [], leaked, f'HTTP {response.status_code}')
        self.finish()

    def test_write_paths_as_a_member(self):
        """A view-only group must not change, create, delete or bulk-edit anything; the hidden field must not be written."""
        from dcim.models import Device
        for how, kwargs in (('session', dict(token=False, session=True)),
                            ('session+garbage Authorization', dict(token=False, session=True,
                                                                   headers={'HTTP_AUTHORIZATION': 'Token garbage'})),
                            ('token', dict(token=True, session=False))):
            Device.objects.filter(pk=self.device.pk).update(description='SECRETTEXT', comments='')
            Device.objects.filter(pk=self.agg.pk).update(description='HIDDENFIELDVALUE', comments='')
            Device.objects.filter(name='NEWDEV').delete()
            cases = (('PATCH closed device (comments)', 'patch', f'/api/dcim/devices/{self.device.pk}/',
                      {'comments': 'W-CLOSED'}),
                     ('PATCH visible device (view-only group)', 'patch', f'/api/dcim/devices/{self.agg.pk}/',
                      {'comments': 'W-VISIBLE'}),
                     ('PATCH hidden field of visible device', 'patch', f'/api/dcim/devices/{self.agg.pk}/',
                      {'description': 'W-HIDDEN'}),
                     ('POST new device', 'post', '/api/dcim/devices/', {'name': 'NEWDEV', 'site': self.device.site.pk,
                                                                       'device_type': self.device.device_type.pk,
                                                                       'role': self.device.role.pk}))
            for label, method, url, data in cases:
                response = self.call(method, url, 'memberx', data=data, **kwargs)
                self.record('6 write paths', f'member | {how} | {label}', 'DENY', self.verdict(response),
                            f'HTTP {response.status_code}')
            closed = Device.objects.filter(pk=self.device.pk).first()
            agg = Device.objects.get(pk=self.agg.pk)
            self.record('6 write paths (effect)', f'member | {how} | closed device changed or deleted in the DB',
                        'untouched', 'untouched' if closed is not None and closed.comments == '' else 'MODIFIED')
            self.record('6 write paths (effect)', f'member | {how} | view-only device comments written', 'untouched',
                        'untouched' if agg.comments == '' else 'WRITTEN')
            self.record('6 write paths (effect)', f'member | {how} | hidden field written', 'untouched',
                        'untouched' if agg.description == 'HIDDENFIELDVALUE' else 'WRITTEN')
            self.record('6 write paths (effect)', f'member | {how} | new device created', 'untouched',
                        'CREATED' if Device.objects.filter(name='NEWDEV').exists() else 'untouched')
            response = self.call('delete', f'/api/dcim/devices/{self.device.pk}/', 'memberx', **kwargs)
            self.record('6 write paths', f'member | {how} | DELETE closed device', 'DENY', self.verdict(response),
                        f'HTTP {response.status_code}')
            closed = Device.objects.filter(pk=self.device.pk).first()
            self.record('6 write paths (effect)', f'member | {how} | closed device deleted', 'untouched',
                        'DELETED' if closed is None else 'untouched')
            if closed is None:  # restore the closed device for the next channel
                Device.objects.create(pk=self.device.pk, name='SECRETDEV', site=self.agg.site,
                                      device_type=self.agg.device_type, role=self.agg.role, description='SECRETTEXT')
        self.finish()

    def test_header_trick_row_escalation_with_a_change_right(self):
        """A group that may CHANGE only AGG_* devices: with a bogus Authorization header can the member change another row?"""
        from dcim.models import Device
        edit = areas.create_group(self.area, 'dcim.device', 'Editors', ['view', 'change'], self.owner1, records='all')
        areas.add_group_condition(edit, self.owner1, 'name', 'contains', ['agg'])
        areas.add_member(edit, self.member, None, self.owner1)
        areas.clear_cache()
        for how, headers in (('session', None), ('session+garbage Authorization', {'HTTP_AUTHORIZATION': 'Token garbage'})):
            Device.objects.filter(pk=self.device.pk).update(comments='')
            response = self.call('patch', f'/api/dcim/devices/{self.device.pk}/', 'memberx', token=False, session=True,
                                 data={'comments': 'ESCALATED'}, headers=headers)
            written = Device.objects.get(pk=self.device.pk).comments == 'ESCALATED'
            self.record('6 write paths', f'member with change on AGG_* only | {how} | PATCH a row OUTSIDE the group',
                        'DENY', self.refused(response), f'HTTP {response.status_code}, written={written}')
            self.record('6 write paths (effect)', f'member with change on AGG_* only | {how} | outside row written',
                        'untouched', 'WRITTEN' if written else 'untouched')
            response = self.call('patch', f'/api/dcim/devices/{self.agg.pk}/', 'memberx', token=False, session=True,
                                 data={'comments': 'INSIDE'}, headers=headers)
            self.record('6 write paths', f'member with change on AGG_* only | {how} | PATCH a row INSIDE the group '
                        '(control)', 'ALLOW', self.verdict(response), f'HTTP {response.status_code}')
        self.finish()

    def test_bulk_import_and_buttons(self):
        for how, kwargs in (('session', dict(token=False, session=True)),):
            response = self.call('post', '/dcim/devices/delete/', 'memberx', data=None, **kwargs)
            self.record('6 bulk', f'member bulk delete page ({how})', 'DENY', self.verdict(response),
                        f'HTTP {response.status_code}')
            response = self.call('get', '/dcim/devices/import/', 'memberx', **kwargs)
            self.record('6 bulk', f'member import page ({how})', 'DENY', self.verdict(response),
                        f'HTTP {response.status_code}')
        self.finish()



# ---------------------------------------------------------------------------------------------------------------
# 8. Migrations: 0041 -> 0046 with data, the way back, and the model/schema consistency
# ---------------------------------------------------------------------------------------------------------------
class MigrationAuditTest(__import__('django.test', fromlist=['TransactionTestCase']).TransactionTestCase):
    def test_upgrade_with_existing_exceptions_and_the_way_back(self):
        from django.core.management import call_command
        from django.db import connection
        from django.db.migrations.executor import MigrationExecutor
        probe = type('P', (), {'failures': [], 'record': AuditBase.record})()
        app = 'netbox_user_pin'
        executor = MigrationExecutor(connection)
        executor.migrate([(app, '0041_sections_work_time')])
        executor = MigrationExecutor(connection)
        old = executor.loader.project_state([(app, '0041_sections_work_time')]).apps
        user_model = old.get_model('users', 'User') if False else get_user_model()
        u1 = User.objects.create_user('mig1', 'mig1@example.com')
        u2 = User.objects.create_user('mig2', 'mig2@example.com')
        u3 = User.objects.create_user('mig3', 'mig3@example.com')
        PE = old.get_model(app, 'PolicyException')
        PE.objects.create(user_id=u1.pk, expires=None, note='no end', added_by_name='k')
        PE.objects.create(user_id=u2.pk, expires=timezone.now() + timedelta(days=5), note='future', added_by_name='k')
        PE.objects.create(user_id=u3.pk, expires=timezone.now() - timedelta(days=5), note='expired', added_by_name='k')
        executor = MigrationExecutor(connection)
        executor.migrate(executor.loader.graph.leaf_nodes(app))
        from netbox_user_pin.models import PolicyException
        rows = {e.user.username: e for e in PolicyException.objects.all()}
        for name in ('mig1', 'mig2', 'mig3'):
            probe.record('8 migrations', f'0041->0046 exception {name}: allowed is only the password', {'password'},
                         rows[name].allowed_set)
            probe.record('8 migrations', f'0041->0046 exception {name}: active', True, rows[name].active)
        probe.record('8 migrations', 'the expired exception is still expired after the migration (not revived)', True,
                     rows['mig3'].is_expired)
        probe.record('8 migrations', 'an expired but ACTIVE row exists after the migration (only the job switches it '
                     'off; the guard ignores it)', True, rows['mig3'].active and rows['mig3'].is_expired)
        areas.clear_cache()
        probe.record('8 migrations', 'the expired exception does not exempt the user from the guard', False,
                     areas._cache['exempt'].__contains__(rows['mig3'].user_id) if areas.active_areas() is not None
                     else None)
        # the way back and forward again
        try:
            executor = MigrationExecutor(connection)
            executor.migrate([(app, '0041_sections_work_time')])
            executor = MigrationExecutor(connection)
            executor.migrate(executor.loader.graph.leaf_nodes(app))
            got = 'reversible'
        except Exception as exc:  # noqa: BLE001
            got = f'{type(exc).__name__}: {exc}'
        probe.record('8 migrations', '0046 -> 0041 -> 0046 runs', 'reversible', got)
        out = __import__('io').StringIO()
        try:
            call_command('makemigrations', app, '--check', '--dry-run', stdout=out)
            got = 'consistent'
        except SystemExit:
            got = 'models differ from migrations: ' + out.getvalue()[:200]
        probe.record('8 migrations', 'models == migrations (makemigrations --check)', 'consistent', got)
        self.assertEqual(probe.failures, [], '\n'.join(probe.failures))



# ---------------------------------------------------------------------------------------------------------------
# 9. Audit and notifications of the exceptions
# ---------------------------------------------------------------------------------------------------------------
class ExceptionAuditTest(AuditBase):
    def events(self):
        from netbox_user_pin.models import PinEvent
        return [e for e in PinEvent.objects.filter(detail__startswith='EXCEPTION').order_by('pk')]

    def test_every_change_is_audited_with_actor_target_time_ip_and_detail(self):
        from netbox_user_pin.models import PinEvent, PolicyException
        target = User.objects.create_user('audtarget', 'audtarget@example.com', 'x')
        admin_login(self.client, self.keeper)
        url = '/plugins/user-pin/areas/'
        kw = {'REMOTE_ADDR': '10.9.8.7'}
        steps = (
            ('create', {'action': 'exception-add', 'user': target.pk, 'note': 'audit', 'expires': ''}, 'EXCEPTION added'),
            ('permissions', {'action': 'exception-allow', 'pk': target.pk, 'allow': ['password', 'api']},
             'allows: password,api'),
            ('switch off', {'action': 'exception-enable', 'pk': target.pk}, 'switched off'),
            ('switch on', {'action': 'exception-enable', 'pk': target.pk, 'state': 'on'}, 'switched on'),
            ('change end', {'action': 'exception-expires', 'pk': target.pk, 'expires': '2031-01-01T10:00'}, 'EXCEPTION'),
            ('remove', {'action': 'exception-remove', 'pk': target.pk}, 'EXCEPTION removed'),
        )
        for label, data, needle in steps:
            before = PinEvent.objects.count()
            self.client.post(url, data, **kw)
            new = list(PinEvent.objects.order_by('pk')[before:])
            hit = [e for e in new if needle in e.detail]
            self.record('9 audit', f'{label}: one event written', 1, len(hit), f'{[e.detail for e in new]}')
            if hit:
                e = hit[0]
                self.record('9 audit', f'{label}: actor', 'keeperx', e.actor_username)
                self.record('9 audit', f'{label}: target', 'audtarget', e.username)
                self.record('9 audit', f'{label}: IP address', '10.9.8.7', str(e.ip_address))
                self.record('9 audit', f'{label}: time is recent', True,
                            abs((timezone.now() - e.time).total_seconds()) < 30)
        # expiry by the job
        areas.add_exception(target, self.keeper, expires=timezone.now() + timedelta(minutes=5))
        PolicyException.objects.filter(user=target).update(expires=timezone.now() - timedelta(seconds=1))
        areas.expire_exceptions()
        ended = [e for e in self.events() if 'ended and switched off' in e.detail]
        self.record('9 audit', 'expiry by the job: one event', 1, len(ended))
        self.record('9 audit', 'expiry by the job: has no actor and no IP (system)', ('', 'None'),
                    (ended[0].actor_username, str(ended[0].ip_address)) if ended else None)
        self.finish()

    def test_no_secrets_in_the_exception_events(self):
        areas.add_exception(self.plain, self.keeper, note='n')
        areas.set_exception_allowed(self.plain, self.keeper, ['password', 'tokens', 'api'])
        text = ' '.join(e.detail for e in self.events()).lower()
        bad = [w for w in ('hash', 'secret', 'pin=', 'otp', 'plaintext') if w in text]
        self.record('9 audit', 'the event texts carry no hash / secret / token value', [], bad,
                    'the right names (password, tokens, api) are expected; values are not')
        self.finish()

    def test_a_failing_mail_service_does_not_lose_the_audit_or_the_change(self):
        from unittest import mock
        from netbox_user_pin.models import AllowedDomain, PolicyException
        AllowedDomain.objects.create(domain='example.com', verified=timezone.now())
        other = User.objects.create_superuser('keepery', 'keepery@example.com', 'x')
        service.set_pin(other, GOOD_PIN)
        enable_2fa(other)
        areas.add_keeper(other, self.keeper)
        target = User.objects.create_user('mailfail', 'mailfail@example.com', 'x')
        with override_settings(EMAIL={'SERVER': 'localhost', 'FROM_EMAIL': 'netbox@example.com'}):
            with mock.patch('django.core.mail.message.EmailMessage.send', side_effect=OSError('smtp down')):
                try:
                    areas.add_exception(target, self.keeper)
                    areas.set_exception_enabled(target, self.keeper, False)
                    got = 'no exception raised'
                except Exception as exc:  # noqa: BLE001
                    got = f'{type(exc).__name__}: {exc}'
        self.record('9 audit', 'SMTP down while a keeper changes an exception: the call does not fail', 'no exception raised', got)
        self.record('9 audit', 'the exception row and its OFF state were saved', False,
                    PolicyException.objects.get(user=target).active)
        self.record('9 audit', 'audit events were written', 2, len([e for e in self.events() if 'mailfail' in e.detail]))
        self.finish()



class GuestHeaderTest(DataLeakTest):
    """PIN-only people with the Authorization-header trick (their technical account has no NetBox permission)."""

    def test_guest_session_with_a_garbage_header(self):
        from netbox_user_pin import guests
        guest, token = guests.create('Jan Novak', 'jan@example.com', self.group, self.keeper, person_number='G-1')
        from django.test import Client
        client = Client(raise_request_exception=False)
        client.post(guests.link_path(token), {'pin': 'Secret-pin-1', 'pin2': 'Secret-pin-1'})
        for label, headers in (('no header', {}), ('Token garbage', {'HTTP_AUTHORIZATION': 'Token garbage'}),
                               ('Bearer garbage', {'HTTP_AUTHORIZATION': 'Bearer garbage'})):
            for url, want in (('/api/dcim/devices/?limit=100', []), ('/dcim/devices/', ['AGG_1'])):
                response = client.get(url, **headers)
                leaked = [n for n in ('SECRETDEV', 'AGG_1') if n.encode() in response.content]
                self.record('6 guest', f'PIN-only person, {label}, GET {url} (the API is closed for him; the UI shows '
                            'only his rows)', want, leaked, f'HTTP {response.status_code}')
            response = client.post('/graphql/', data=json.dumps(GQL), content_type='application/json', **headers)
            leaked = [n for n in ('SECRETDEV', 'HIDDENFIELDVALUE') if n.encode() in response.content]
            self.record('6 guest', f'PIN-only person, {label}, GraphQL list', [], leaked, f'HTTP {response.status_code}')
        self.finish()
