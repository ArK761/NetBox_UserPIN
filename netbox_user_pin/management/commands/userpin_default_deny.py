"""Emergency: show / switch off (or on) "deny everything not allowed" from the server shell (audited)."""
from django.core.management.base import BaseCommand, CommandError

from netbox_user_pin import areas, service
from netbox_user_pin.models import PinEventAction


class Command(BaseCommand):
    help = 'Show or switch the "deny everything not allowed" setting (emergency, written to the audit log).'

    def add_arguments(self, parser):
        group = parser.add_mutually_exclusive_group()
        group.add_argument('--off', action='store_true', help='switch it off')
        group.add_argument('--on', action='store_true', help='switch it on (needs a protection keeper)')

    def handle(self, *args, **options):
        settings = service.get_settings()
        if not (options['off'] or options['on']):
            keepers = ', '.join(u.username for u in areas.keepers()) or '(none)'
            self.stdout.write(f'Deny everything not allowed: {"ON" if settings.default_deny else "off"}; keepers: {keepers}')
            return
        if options['on'] and not areas.keepers():
            raise CommandError('Appoint a protection keeper first.')
        settings.default_deny = options['on']
        settings.save()
        service.log_event(PinEventAction.DENY_ENABLED if options['on'] else PinEventAction.DENY_DISABLED,
                          detail='by the server command userpin_default_deny')
        areas.clear_cache()
        self.stdout.write(self.style.SUCCESS('Switched ' + ('on.' if options['on'] else 'off.')))
