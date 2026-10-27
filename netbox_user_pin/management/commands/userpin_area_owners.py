"""Emergency: replace the owners of a protected area from the server shell (audited in the PIN audit log)."""
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from netbox_user_pin import areas, roles, service
from netbox_user_pin.models import ProtectedArea


class Command(BaseCommand):
    help = 'Show or replace the owners of a protected area (emergency, written to the audit log).'

    def add_arguments(self, parser):
        parser.add_argument('area', help='key of the area (see User PIN > Protected areas)')
        parser.add_argument('--set', nargs='+', metavar='USERNAME', help='the new owners (replace the current ones)')
        parser.add_argument('--force', action='store_true',
                            help='set them even when they cannot act as owners (no role, no PIN / 2FA, superuser, keeper)')

    def handle(self, *args, **options):
        area = ProtectedArea.objects.filter(key=options['area']).first()
        if area is None:
            raise CommandError(f'No area with the key "{options["area"]}".')
        if not options['set']:
            owners = ', '.join(u.username for u in areas.owners(area)) or '(none)'
            self.stdout.write(f'{area.name}: {owners}')
            return
        users = []
        for name in options['set']:
            user = get_user_model().objects.filter(username=name, is_active=True).first()
            if user is None:
                raise CommandError(f'No active user "{name}".')
            users.append(user)
        problems = [f'{u.username}: {why}' for u in users if (why := self._not_eligible(u))]
        if problems and not options['force']:
            raise CommandError('These users would be owners on paper only (an owner must be a department head, a '
                               'delegate or a CORE deputy with a PIN and 2FA, and neither a superuser nor a protection '
                               'keeper):\n' + '\n'.join(problems) + '\nFix that first, or add --force.')
        for problem in problems:
            self.stdout.write(self.style.WARNING(f'Not eligible yet: {problem}'))
        areas.reset_owners(area, users, 'server command userpin_area_owners')
        self.stdout.write(self.style.SUCCESS(f'Owners of {area.name}: {", ".join(u.username for u in users)}'))

    @staticmethod
    def _not_eligible(user):
        if user.is_superuser:
            return 'is a superuser'
        if areas.is_keeper(user):
            return 'is a protection keeper'
        if not roles.manager_users(include_superusers=False).filter(pk=user.pk).exists():
            return 'is no department head, delegate or CORE deputy'
        if not (service.has_pin(user) and service.has_2fa(user)):
            return 'has no PIN and 2FA'
        return ''
