from django.core.management.base import BaseCommand

from netbox_user_pin import crypto


class Command(BaseCommand):
    help = 'Generate a new random encryption key for netbox_user_pin (prints it; stores nothing).'

    def add_arguments(self, parser):
        parser.add_argument('--key-id', default='k1', help='Identifier to use for the key in the configuration.')

    def handle(self, *args, **options):
        key = crypto.generate_key()
        key_id = options['key_id']
        self.stdout.write(
            'Add this to configuration.py (keep an offline backup of the key; never commit it):\n\n'
            'PLUGINS_CONFIG = {\n'
            "    'netbox_user_pin': {\n"
            f"        'encryption_keys': {{'{key_id}': '{key}'}},\n"
            f"        'active_key_id': '{key_id}',\n"
            '    },\n'
            '}\n'
        )
