from netbox.plugins import PluginConfig

__version__ = '2.0.7'


class UserPinConfig(PluginConfig):
    name = 'netbox_user_pin'
    verbose_name = 'User PIN'
    description = 'Personal PIN used to unlock sensitive areas of NetBox and NetBox plugins'
    version = __version__
    author = 'Peter Knotek'
    base_url = 'user-pin'
    min_version = '4.7.0'
    required_settings = ['encryption_keys']
    middleware = [
        'netbox_user_pin.middleware.PluginLanguageMiddleware',
        'netbox_user_pin.area_guard.AreaGuardMiddleware',
    ]
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
        from . import areas, jobs  # noqa: F401  (jobs registers the hourly system job)
        areas.connect_signals()
        from . import area_guard
        area_guard.install()
        from . import fieldrules
        fieldrules.install()
        from . import guests
        guests.install_user_email_check()
        guests.install_signals()

    @staticmethod
    def _register_event_types():
        from netbox.events import EVENT_TYPE_KIND_WARNING, EventType
        from netbox.registry import registry

        from .approvals import EVENT_TYPE
        from .areas import EVENT_TYPE as AREA_EVENT_TYPE
        from .roles import EVENT_TYPE as ROLE_EVENT_TYPE
        if EVENT_TYPE not in registry['event_types']:
            EventType(EVENT_TYPE, 'PIN four-eyes approval requested', kind=EVENT_TYPE_KIND_WARNING).register()
        if AREA_EVENT_TYPE not in registry['event_types']:
            EventType(AREA_EVENT_TYPE, 'PIN area access requested', kind=EVENT_TYPE_KIND_WARNING).register()
        if ROLE_EVENT_TYPE not in registry['event_types']:
            EventType(ROLE_EVENT_TYPE, 'PIN role / department change', kind=EVENT_TYPE_KIND_WARNING).register()


config = UserPinConfig
