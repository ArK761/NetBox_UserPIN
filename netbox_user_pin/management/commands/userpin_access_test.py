"""
Test of the protection from the server shell: what a user really gets, without clicking through the pages.

    ./manage.py userpin_access_test XXX [--url /dcim/devices/864/interfaces/ ...]
"""
import re

from django.conf import settings as django_settings
from django.core.management.base import BaseCommand, CommandError
from django.test import Client
from django.urls import URLPattern, URLResolver, get_resolver

from netbox_user_pin import areas

# (what it is, URL): pages and the browser's REST API as a person at a screen (a session, not a token)
PAGES = [
    ('Devices list', '/dcim/devices/'),
    ('Device interfaces list', '/dcim/interfaces/'),
    ('Sites', '/dcim/sites/'),
    ('Prefixes', '/ipam/prefixes/'),
    ('Tenants', '/tenancy/tenants/'),
    ('Users (admin)', '/users/users/'),
    ('Groups (admin)', '/users/groups/'),
    ('Permissions (admin)', '/users/permissions/'),
    ('Tokens', '/users/tokens/'),
    ('Add a token', '/users/tokens/add/'),
    ('Jobs', '/core/jobs/'),
    ('Background tasks', '/core/background-queues/'),
    ('Config history', '/core/config-revisions/'),
    ('Change log', '/core/changelog/'),
    ('Bookmarks', '/user/bookmarks/'),
    ('Notifications', '/user/notifications/'),
    ('Own profile', '/user/profile/'),
    ('Preferences', '/user/preferences/'),
    ('Own API tokens', '/user/api-tokens/'),
    ('Change password', '/user/password/'),
    ('API: devices (browser session)', '/api/dcim/devices/'),
    ('API: users (browser session)', '/api/users/users/'),
    ('API: tokens (browser session)', '/api/users/tokens/'),
]

# models whose rows the user would get in any list, search, GraphQL or widget: visible / all
MODELS = ['dcim.device', 'dcim.interface', 'dcim.site', 'ipam.prefix', 'tenancy.tenant', 'users.user', 'users.token',
          'core.job', 'core.objectchange', 'extras.bookmark', 'extras.journalentry']


def _verdict(response):
    code = response.status_code
    location = response.headers.get('Location', '') if code in (301, 302) else ''
    if code == 200:
        return 'OPEN'
    if code == 403:
        return 'DENIED (no access / request page)'
    if code in (301, 302):
        if any(part in location for part in ('/unlock/', '/set-pin/', '/change-pin/', '/2fa', '/totp')):
            return f'PIN PROMPT -> {location}'
        if '/access/' in location:
            return f'sent to "my access" -> {location}'
        if '/login/' in location:
            return 'LOGIN'
        return f'redirect -> {location}'
    return f'HTTP {code}'


SKIP_ROUTES = ('logout', 'login', 'media', 'static', '__debug__', 'admin/', 'api/docs', 'api/schema', 'graphql', 'oauth',
               'social', 'webhook', 'plugins/user-pin/')
PARAM = re.compile(r'<(?:\w+:)?(\w+)>')


def walk(patterns, prefix='', defaults=None):
    """Every route of the project: (route, callback, default kwargs)."""
    for pattern in patterns:
        route = str(pattern.pattern)
        if re.search(r'[\^$()\\]', route):  # a regular expression, not a plain route
            continue
        if isinstance(pattern, URLResolver):
            yield from walk(pattern.url_patterns, prefix + route, {**(defaults or {}), **pattern.default_kwargs})
        elif isinstance(pattern, URLPattern):
            yield prefix + route, pattern.callback, {**(defaults or {}), **pattern.default_args}


def _model_of(callback, kwargs):
    model = kwargs.get('model')
    if hasattr(model, '_meta'):
        return model
    cls = getattr(callback, 'view_class', None) or getattr(callback, 'cls', None)
    queryset = getattr(cls, 'queryset', None)
    if queryset is not None:
        return queryset.model
    model = getattr(cls, 'model', None)
    return model if hasattr(model, '_meta') else None


class Command(BaseCommand):
    help = 'Show what a user gets from the pages, the REST API (browser) and the lists, to test the protection.'

    def add_arguments(self, parser):
        parser.add_argument('username')
        parser.add_argument('--url', action='append', default=[], help='one more URL to try (repeatable)')
        parser.add_argument('--writes', action='store_true', help='with --all: also try an add, a change and a delete '
                                                                 'of every object type (rolled back at once)')
        parser.add_argument('--all', action='store_true', help='try EVERY page of NetBox (lists, details with all their '
                                                              'tabs, edit pages, the REST API): takes a few minutes')

    def handle(self, *args, **options):
        from django.apps import apps
        from django.contrib.auth import get_user_model
        user = get_user_model().objects.filter(username__iexact=options['username']).first()
        if user is None:
            raise CommandError('No such user.')
        areas.clear_cache()
        keeper = areas.is_keeper(user)
        self.stdout.write(f'User {user.username}: superuser={user.is_superuser}, protection keeper={keeper}, '
                          f'areas on={areas.protection_on()}, deny everything not allowed={areas.default_deny_active()}')
        if keeper:
            self.stdout.write(self.style.WARNING('A keeper is exempt from the deny: expect OPEN almost everywhere.'))
        if areas.is_exempt(user):
            self.stdout.write(self.style.WARNING('An EXCEPTION is set for this user: the PIN protection does not apply '
                                                 'to him, NetBox permissions rule (expect OPEN where NetBox allows).'))

        self.stdout.write('\n== Pages and browser API (as the person at the screen) ==')
        django_settings.ALLOWED_HOSTS = ['*']
        client = Client(HTTP_HOST='localhost')
        client.force_login(user)
        try:
            for label, url in PAGES + [('(yours)', u) for u in options['url']]:
                try:
                    response = client.get(url, HTTP_ACCEPT='application/json' if url.startswith('/api/') else 'text/html')
                    verdict = _verdict(response)
                except Exception as exc:  # noqa: BLE001 - the guard refuses with a response, so this got past it
                    verdict = f'OPEN (the page itself failed to draw in this shell: {type(exc).__name__})'
                self.stdout.write(f'{label:34} {url:34} {verdict}')
        finally:
            client.logout()

        self._drop_downs(user)
        if options['all']:
            self._everything(user, options['writes'])

        self.stdout.write('\n== Rows the user gets in lists, search, GraphQL, widgets: visible / all ==')
        for target in MODELS:
            try:
                model = apps.get_model(target)
                queryset = model.objects.all()
                visible = queryset.restrict(user, 'view').count() if hasattr(queryset, 'restrict') else '(no restrict)'
                self.stdout.write(f'{target:22} {visible} / {model.objects.count()}')
            except Exception as exc:  # noqa: BLE001
                self.stdout.write(f'{target:22} ? ({exc})')

        self.stdout.write('\n== Menu doors (has_perm) ==')
        from netbox_user_pin import area_guard
        area_guard.arm_user(user)
        for perm in ('dcim.view_device', 'dcim.add_device', 'users.view_user', 'users.add_token', 'core.view_job',
                     'netbox_user_pin.view_userpin', 'netbox_user_pin.view_pinsettings'):
            self.stdout.write(f'{perm:36} {user.has_perm(perm)}')
        self.stdout.write('\nPAGE verdicts: OPEN = shown, DENIED = the "what you are allowed / send a request" page.')

    def _drop_downs(self, user):
        """What the user may PICK in the relation fields he may write: the drop-down is served, the pages stay closed."""
        from django.apps import apps
        from django.urls import reverse
        from netbox_user_pin import fieldrules
        from utilities.views import get_viewname
        self.stdout.write('\n== What the user may PICK in relation fields (drop-downs of fields he may write) ==')
        scope = fieldrules.select_scope(user)
        sets = sorted(fieldrules.choice_set_ids(user))
        if not scope and not sets:
            self.stdout.write('(nothing: no relation or select field is writable for him)')
            return
        django_settings.ALLOWED_HOSTS = ['*']
        client = Client(HTTP_HOST='localhost', raise_request_exception=False)
        client.force_login(user)
        try:
            for label, texts in sorted(scope.items()):
                model = apps.get_model(label)
                try:
                    api = reverse(get_viewname(model, action='list', rest_api=True))
                    page = reverse(get_viewname(model, action='list'))
                except Exception:  # noqa: BLE001
                    self.stdout.write(f'{label:28} (no list address)')
                    continue
                response = client.get(f'{api}?brief=true&limit=1', HTTP_ACCEPT='application/json')
                count = response.json().get('count', '?') if response.status_code == 200 else response.status_code
                closed = _verdict(client.get(page))
                rule = 'all' if texts is None else 'only names containing ' + ' / '.join(texts)
                self.stdout.write(f'{label:28} drop-down: {rule:34} gives {count} of {model.objects.count()}'
                                  f'  | pages of the type: {closed}')
            for pk in sets:
                response = client.get(f'/api/extras/custom-field-choice-sets/{pk}/choices/', HTTP_ACCEPT='application/json')
                count = response.json().get('count', '?') if response.status_code == 200 else response.status_code
                self.stdout.write(f'choice set {pk:<16} values of a select field he may write      gives {count}')
        finally:
            client.logout()

    def _everything(self, user, writes):
        """
        Every object type of this NetBox, step by step: its list, a real object (one the user may see, else any), the
        tabs of that object, and - with ``--writes`` - an add, a change and a delete, all of them inside a transaction
        that is rolled back at once (nothing is saved, no webhook is sent).
        """
        from collections import defaultdict

        from django.db import connection, transaction
        django_settings.ALLOWED_HOSTS = ['*']
        client = Client(HTTP_HOST='localhost', raise_request_exception=False)
        client.force_login(user)
        table = defaultdict(dict)  # model label -> {column: text}
        problems = []
        pks = {}
        routes = [r for r in sorted(walk(get_resolver().url_patterns), key=lambda r: r[0])
                  if not any(part in r[0] for part in SKIP_ROUTES)]
        self.stdout.write(f'\n== EVERY object type ({len(routes)} routes; {"with" if writes else "without"} '
                          f'fictitious writes, rolled back) ==')

        def pk_of(model):
            if model not in pks:
                queryset = model._default_manager.all()
                mine = queryset.restrict(user, 'view').first() if hasattr(queryset, 'restrict') else None
                obj = mine or queryset.first()
                pks[model] = obj.pk if obj is not None else None
            return pks[model]

        def call(method, url, api):
            extra = {'HTTP_ACCEPT': 'application/json' if api else 'text/html'}
            if method == 'GET':
                return client.get(url, **extra)
            with transaction.atomic():  # nothing of this stays
                if method == 'POST':
                    response = client.post(url, {} if not api else '{}', content_type='application/json' if api else
                                           'application/x-www-form-urlencoded', **extra)
                elif method == 'PATCH':
                    response = client.patch(url, '{}', content_type='application/json', **extra)
                else:
                    response = client.delete(url, **extra)
                transaction.set_rollback(True)
            return response

        def verdict(response, method='GET'):
            if response.headers.get('X-UserPIN') == 'denied':
                return 'no'
            if response.status_code == 403:
                return 'no(NetBox)'
            if response.status_code in (401, 404, 405):
                return None
            if response.status_code >= 500:
                return 'ok*' if method != 'GET' else 'ERR'  # past the guard; the empty form fails on its own
            return 'ok'

        try:
            for route, callback, kwargs in routes:
                params = set(PARAM.findall(route))
                if params - {'pk'}:
                    continue
                model = _model_of(callback, kwargs)
                if model is None:
                    continue
                label = f'{model._meta.app_label}.{model._meta.model_name}'
                url = '/' + route
                if params:
                    if pk_of(model) is None:
                        continue
                    url = url.replace('<int:pk>', str(pk_of(model)))
                if '<' in url:
                    continue
                api = url.startswith('/api/')
                last = route.rstrip('/').rsplit('/', 1)[-1]
                steps = []  # (column, method)
                if api:
                    if not params:
                        steps = [('API list', 'GET')] + ([('API add', 'POST')] if writes else [])
                    elif last == '<int:pk>':
                        steps = [('API read', 'GET')] + ([('API change', 'PATCH'), ('API delete', 'DELETE')]
                                                         if writes else [])
                else:
                    if not params:
                        if last == 'add':
                            steps = [('add', 'POST')] if writes else []
                        elif last in ('edit', 'delete', 'import', 'rename'):
                            steps = [('bulk ' + last, 'POST')] if writes else []
                        else:
                            steps = [('list', 'GET')]
                    elif last == '<int:pk>':
                        steps = [('detail', 'GET')]
                    elif last == 'edit':
                        steps = [('change', 'POST')] if writes else [('change page', 'GET')]
                    elif last == 'delete':
                        steps = [('delete', 'POST')] if writes else []
                    else:
                        steps = [('tab ' + last, 'GET')]
                for column, method in steps:
                    try:
                        response = call(method, url, api)
                    except Exception as exc:  # noqa: BLE001
                        problems.append(f'{method} {url}: {type(exc).__name__}')
                        continue
                    result = verdict(response, method)
                    if result in ('ERR', 'ok*'):
                        problems.append(f'{method} {url}: HTTP {response.status_code}'
                                        + (' (the empty form of this test; the guard let it in)' if result == 'ok*' else ''))
                    if result:
                        table[label][column] = result
        finally:
            client.logout()

        opened = {label: cols for label, cols in table.items() if any(v in ('ok', 'ok*', 'ERR') for v in cols.values())}
        self.stdout.write(f'Object types: {len(table)}; with something open: {len(opened)}; '
                          f'fully denied: {len(table) - len(opened)}')
        self.stdout.write('\nWHAT THE USER CAN DO (OPEN = allowed, DENIED = the "no access" page; only types with something '
                          'open; * = the guard let it in, the test then sent an empty form that fails on its own):')
        for label in sorted(opened):
            ok = [f'{c}' + ('*' if v == 'ok*' else '') for c, v in sorted(opened[label].items()) if v in ('ok', 'ok*')]
            no = [f'{c}' for c, v in sorted(opened[label].items()) if v.startswith('no')]
            self.stdout.write(f'\n  {label}\n     OPEN:   {", ".join(ok) or "-"}\n     DENIED: {", ".join(no) or "-"}')
        if problems:
            self.stdout.write('\nFailed to draw / server error (past the guard; may be only this shell):')
            for line in problems[:60]:
                self.stdout.write(f'  {line}')
