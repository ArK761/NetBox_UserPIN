from django.core.management.base import BaseCommand, CommandError

from netbox_user_pin import crypto
from netbox_user_pin.models import UserPin


class Command(BaseCommand):
    help = 'Verify that every stored PIN hash can be decrypted with the configured keys.'

    def handle(self, *args, **options):
        active = crypto.active_key_id()
        self.stdout.write(f'Active key: {active}  fingerprint {crypto.fingerprint(active)}')
        ok, old_key, failed = 0, 0, []
        for user_pin in UserPin.objects.exclude(pin_hash='').select_related('user'):
            try:
                crypto.decrypt(user_pin.pin_hash, user_pin.aad)
            except crypto.DecryptionError as exc:
                failed.append(f'{user_pin.user}: {exc}')
                continue
            ok += 1
            if crypto.token_key_id(user_pin.pin_hash) != active:
                old_key += 1
        self.stdout.write(f'OK: {ok}, encrypted with a non-active key: {old_key}, failed: {len(failed)}')
        if old_key:
            self.stdout.write(self.style.WARNING('Run userpin_rotate_key to move all PINs to the active key.'))
        if failed:
            raise CommandError('\n'.join(failed))
        self.stdout.write(self.style.SUCCESS('All PINs decrypt correctly.'))
