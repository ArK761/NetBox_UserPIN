"""
Test of the protection from the server shell: what a user really gets, without clicking through the pages.

    ./manage.py userpin_access_test XXX [--url /dcim/devices/864/interfaces/ ...]
"""
from django.conf import settings as django_settings
from django.core.management.base import BaseCommand, CommandError
from django.test import Client

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
    ('Bookmarks', '/account/bookmarks/'),
    ('Preferences', '/user/preferences/'),
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


class Command(BaseCommand):
    help = 'Show what a user gets from the pages, the REST API (browser) and the lists, to test the protection.'

    def add_arguments(self, parser):
        parser.add_argument('username')
        parser.add_argument('--url', action='append', default=[], help='one more URL to try (repeatable)')

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

        self.stdout.write('\n== Pages and browser API (as the person at the screen) ==')
        django_settings.ALLOWED_HOSTS = ['*']
        client = Client(HTTP_HOST='localhost')
        client.force_login(user)
        try:
            for label, url in PAGES + [('(yours)', u) for u in options['url']]:
                response = client.get(url, HTTP_ACCEPT='application/json' if url.startswith('/api/') else 'text/html')
                self.stdout.write(f'{label:34} {url:34} {_verdict(response)}')
        finally:
            client.logout()

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
