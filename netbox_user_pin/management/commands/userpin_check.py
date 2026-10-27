from django.core.management.base import BaseCommand, CommandError

from netbox_user_pin import crypto
from netbox_user_pin.models import PinGuest
from netbox_user_pin.service import encrypted_values


class Command(BaseCommand):
    help = ('Verify that everything stored under a key (PIN hashes, 2FA secrets, backup codes, SMTP password) can be '
            'decrypted, and show what still needs an old key.')

    def handle(self, *args, **options):
        active = crypto.active_key_id()
        self.stdout.write(f'Active key: {active}  fingerprint {crypto.fingerprint(active)}')
        ok, old_key, failed = 0, 0, []
        for label, obj, field, aad in encrypted_values():
            token = getattr(obj, field)
            try:
                crypto.decrypt(token, aad)
            except crypto.DecryptionError as exc:
                failed.append(f'{label}: {exc}')
                continue
            ok += 1
            if crypto.token_key_id(token) != active:
                old_key += 1
        guests_old = PinGuest.objects.exclude(pin_index=None).exclude(pin_index__startswith=f'{active}:').count()
        self.stdout.write(f'OK: {ok}, encrypted with a non-active key: {old_key}, failed: {len(failed)}, '
                          f'PIN-only accesses still on an old key: {guests_old}')
        if old_key:
            self.stdout.write(self.style.WARNING('Run userpin_rotate_key to move everything to the active key.'))
        if guests_old:
            self.stdout.write(self.style.WARNING(
                'Some PIN-only people have not signed in since the rotation: keep the old key until this shows 0.'))
        if failed:
            raise CommandError('\n'.join(failed))
        if old_key or guests_old:
            self.stdout.write(self.style.WARNING('Do NOT remove the old key yet.'))
        else:
            self.stdout.write(self.style.SUCCESS('Everything decrypts with the active key; old keys can be removed.'))
