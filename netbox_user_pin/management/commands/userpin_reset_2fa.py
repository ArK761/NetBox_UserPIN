from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from netbox_user_pin import service


class Command(BaseCommand):
    help = 'Emergency: remove the 2FA of a user (e.g. the master lost the phone and all backup codes).'

    def add_arguments(self, parser):
        parser.add_argument('username')

    def handle(self, *args, **options):
        try:
            user = get_user_model().objects.get(username=options['username'])
        except get_user_model().DoesNotExist:
            raise CommandError(f"User '{options['username']}' does not exist.")
        service.reset_totp(user, actor=None)
        self.stdout.write(self.style.SUCCESS(f'2FA of {user} removed. The user can set it up again under My PIN.'))
