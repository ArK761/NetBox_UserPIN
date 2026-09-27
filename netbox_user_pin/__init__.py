from netbox.plugins import PluginConfig

__version__ = '0.6.0'


class UserPinConfig(PluginConfig):
    name = 'netbox_user_pin'
    verbose_name = 'User PIN'
    description = 'Personal PIN used to unlock sensitive areas of NetBox and NetBox plugins'
    version = __version__
    author = 'Peter Knotek'
    base_url = 'user-pin'
    min_version = '4.7.0'
    required_settings = ['encryption_keys']
    default_settings = {
        # {key_id: urlsafe-base64 32 byte key}. Generate with `manage.py userpin_generate_key`.
        'encryption_keys': {},
        # Key used for new encryptions. Defaults to the only key when just one is configured.
        'active_key_id': None,
        # Argon2id cost parameters.
        'argon2_time_cost': 3,
        'argon2_memory_cost': 65536,
        'argon2_parallelism': 4,
        # Paths used to show the emergency server commands in the UI.
        'cli_venv': '/opt/netbox/venv',
        'cli_netbox_dir': '/opt/netbox/netbox',
    }

    def ready(self):
        super().ready()
        from . import crypto
        crypto.validate_configuration()
        self._register_event_types()

    @staticmethod
    def _register_event_types():
        from netbox.events import EVENT_TYPE_KIND_WARNING, EventType
        from netbox.registry import registry

        from .approvals import EVENT_TYPE
        if EVENT_TYPE not in registry['event_types']:
            EventType(EVENT_TYPE, 'PIN four-eyes approval requested', kind=EVENT_TYPE_KIND_WARNING).register()


config = UserPinConfig
