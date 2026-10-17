"""Emergency: replace the owners of a protected area from the server shell (audited in the PIN audit log)."""
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from netbox_user_pin import areas
from netbox_user_pin.models import ProtectedArea


class Command(BaseCommand):
    help = 'Show or replace the owners of a protected area (emergency, written to the audit log).'

    def add_arguments(self, parser):
        parser.add_argument('area', help='key of the area (see User PIN > Protected areas)')
        parser.add_argument('--set', nargs='+', metavar='USERNAME', help='the new owners (replace the current ones)')

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
        areas.reset_owners(area, users, 'server command userpin_area_owners')
        self.stdout.write(self.style.SUCCESS(f'Owners of {area.name}: {", ".join(u.username for u in users)}'))
