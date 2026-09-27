from netbox.plugins import PluginConfig

__version__ = '0.4.0'


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
    }

    def ready(self):
        super().ready()
        from . import crypto
        crypto.validate_configuration()


config = UserPinConfig
