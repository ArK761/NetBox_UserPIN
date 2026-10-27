from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from netbox_user_pin import crypto
from netbox_user_pin.models import PinEventAction, PinGuest
from netbox_user_pin.service import encrypted_values, log_event


class Command(BaseCommand):
    help = (
        "Re-encrypt everything stored under a key (PIN hashes, 2FA secrets, backup codes, SMTP password) with the "
        "active key. Configure the new key in 'encryption_keys', set it as 'active_key_id' while keeping the old key, "
        "run this command, then check with userpin_check before removing the old key."
    )

    def handle(self, *args, **options):
        active = crypto.active_key_id()
        rotated = 0
        failed = []
        with transaction.atomic():
            for label, obj, field, aad in encrypted_values(lock=True):
                token = getattr(obj, field)
                if crypto.token_key_id(token) == active:
                    continue
                try:
                    plain = crypto.decrypt(token, aad)
                except crypto.DecryptionError as exc:
                    failed.append(f'{label}: {exc}')
                    continue
                setattr(obj, field, crypto.encrypt(plain, aad))
                obj.save(update_fields=[field])
                rotated += 1
            if failed:
                raise CommandError('Rotation aborted, nothing changed:\n' + '\n'.join(failed))
        log_event(PinEventAction.KEY_ROTATED, detail=f'active key {active}, re-encrypted {rotated} value(s)')
        self.stdout.write(self.style.SUCCESS(
            f'Re-encrypted {rotated} value(s) with key {active} (fingerprint {crypto.fingerprint(active)}).'
        ))
        waiting = PinGuest.objects.exclude(pin_index=None).exclude(pin_index__startswith=f'{active}:').count()
        if waiting:
            self.stdout.write(self.style.WARNING(
                f'{waiting} PIN-only access(es) still find their PIN under an old key; it moves to the active key at '
                f'their next sign-in. Keep the old key until userpin_check shows 0.'
            ))
