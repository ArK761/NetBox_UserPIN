"""Emergency: appoint a protection keeper from the server shell (audited, every keeper and superuser is e-mailed)."""
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from netbox_user_pin import areas, guests, service
from netbox_user_pin.models import PinEventAction, PolicyKeeper


class Command(BaseCommand):
    help = 'Show the protection keepers, or appoint one (emergency, written to the audit log, e-mailed to everybody).'

    def add_arguments(self, parser):
        parser.add_argument('--add', metavar='USERNAME', help='appoint this user a protection keeper')

    def handle(self, *args, **options):
        if not options['add']:
            self.stdout.write('Protection keepers: ' + (', '.join(u.username for u in areas.keepers()) or '(none)'))
            return
        user = get_user_model().objects.filter(username=options['add'], is_active=True).first()
        if user is None:
            raise CommandError(f'No active user "{options["add"]}".')
        if guests.is_guest(user):
            raise CommandError('A PIN-only access cannot be a protection keeper.')
        if not (service.has_pin(user) and service.has_2fa(user)):
            raise CommandError(f'{user.username} must set up a PIN and 2FA first (User PIN > My PIN).')
        _keeper, created = PolicyKeeper.objects.get_or_create(user=user,
                                                               defaults={'added_by_name': 'server command'})
        if not created:
            self.stdout.write(f'{user.username} already is a protection keeper.')
            return
        service.log_event(PinEventAction.KEEPER_ADDED, user=user, detail='by the server command userpin_keeper')
        areas.clear_cache()
        told = areas.tell_emergency(f'{user.username} was appointed a protection keeper')
        self.stdout.write(self.style.SUCCESS(f'{user.username} is a protection keeper.'))
        self.stdout.write(f'E-mailed: {", ".join(told) or "nobody (no verified e-mail)"}')
