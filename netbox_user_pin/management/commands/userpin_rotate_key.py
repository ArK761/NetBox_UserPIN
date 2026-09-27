from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from netbox_user_pin import crypto
from netbox_user_pin.models import PinEventAction, UserPin
from netbox_user_pin.service import log_event


class Command(BaseCommand):
    help = (
        "Re-encrypt all stored PIN hashes with the active key. Configure the new key in 'encryption_keys', "
        "set it as 'active_key_id' while keeping the old key, run this command, then remove the old key."
    )

    def handle(self, *args, **options):
        active = crypto.active_key_id()
        rotated = 0
        failed = []
        with transaction.atomic():
            for user_pin in UserPin.objects.select_for_update().exclude(pin_hash=''):
                if crypto.token_key_id(user_pin.pin_hash) == active:
                    continue
                try:
                    plain = crypto.decrypt(user_pin.pin_hash, user_pin.aad)
                except crypto.DecryptionError as exc:
                    failed.append(f'{user_pin.user}: {exc}')
                    continue
                user_pin.pin_hash = crypto.encrypt(plain, user_pin.aad)
                user_pin.save(update_fields=['pin_hash'])
                rotated += 1
            if failed:
                raise CommandError('Rotation aborted, nothing changed:\n' + '\n'.join(failed))
        log_event(PinEventAction.KEY_ROTATED, detail=f'active key {active}, re-encrypted {rotated} PIN(s)')
        self.stdout.write(self.style.SUCCESS(
            f'Re-encrypted {rotated} PIN(s) with key {active} (fingerprint {crypto.fingerprint(active)}).'
        ))
