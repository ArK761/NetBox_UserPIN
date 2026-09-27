"""
Server-side encryption of stored PIN hashes.

A PIN is first hashed with Argon2id (one-way, salted, slow) and the resulting hash string is then encrypted with
AES-256-GCM using a key that lives in the NetBox configuration, never in the database. A stolen database dump
therefore contains neither PINs nor hashes that could be brute-forced offline.

Stored token format:  ``<key_id>:<urlsafe-base64(nonce || ciphertext)>``
"""
import base64
import hashlib
import os
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.core.exceptions import ImproperlyConfigured
from netbox.plugins import get_plugin_config

__all__ = (
    'DecryptionError',
    'active_key_id',
    'configured_key_ids',
    'decrypt',
    'encrypt',
    'fingerprint',
    'generate_key',
    'validate_configuration',
)

PLUGIN_NAME = 'netbox_user_pin'
NONCE_SIZE = 12
KEY_SIZE = 32


class DecryptionError(Exception):
    """Raised when a stored value cannot be decrypted (unknown key, wrong key or tampered data)."""


def _decode_key(key_id, value):
    try:
        raw = base64.urlsafe_b64decode(value.encode() if isinstance(value, str) else value)
    except (ValueError, TypeError):
        raise ImproperlyConfigured(f"netbox_user_pin: encryption key '{key_id}' is not valid base64.")
    if len(raw) != KEY_SIZE:
        raise ImproperlyConfigured(
            f"netbox_user_pin: encryption key '{key_id}' must be {KEY_SIZE} bytes, got {len(raw)}."
        )
    return raw


def _keys():
    keys = get_plugin_config(PLUGIN_NAME, 'encryption_keys') or {}
    if not isinstance(keys, dict) or not keys:
        raise ImproperlyConfigured(
            "netbox_user_pin: PLUGINS_CONFIG['netbox_user_pin']['encryption_keys'] must be a non-empty dict "
            "of {key_id: key}. Generate a key with `manage.py userpin_generate_key`."
        )
    decoded = {}
    for key_id, value in keys.items():
        key_id = str(key_id)
        if not key_id or ':' in key_id:
            raise ImproperlyConfigured(f"netbox_user_pin: invalid key id '{key_id}' (must be non-empty, no ':').")
        decoded[key_id] = _decode_key(key_id, value)
    return decoded


def configured_key_ids():
    return list(_keys().keys())


def active_key_id():
    keys = _keys()
    key_id = get_plugin_config(PLUGIN_NAME, 'active_key_id')
    if key_id is None:
        if len(keys) != 1:
            raise ImproperlyConfigured(
                "netbox_user_pin: several encryption keys are configured; set 'active_key_id'."
            )
        return next(iter(keys))
    key_id = str(key_id)
    if key_id not in keys:
        raise ImproperlyConfigured(f"netbox_user_pin: active_key_id '{key_id}' is not in encryption_keys.")
    return key_id


def validate_configuration():
    """Fail loudly at startup instead of ever generating or silently switching keys."""
    active_key_id()


def fingerprint(key_id=None):
    """Short, non-secret identifier of a key, safe to display for verification of backups."""
    key_id = key_id or active_key_id()
    digest = hashlib.sha256(b'netbox_user_pin:fingerprint:' + _keys()[key_id]).hexdigest()[:16].upper()
    return ':'.join(digest[i:i + 4] for i in range(0, 16, 4))


def generate_key():
    return base64.urlsafe_b64encode(secrets.token_bytes(KEY_SIZE)).decode()


def encrypt(plaintext, aad):
    key_id = active_key_id()
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(_keys()[key_id]).encrypt(nonce, plaintext.encode(), aad)
    return f'{key_id}:{base64.urlsafe_b64encode(nonce + ciphertext).decode()}'


def token_key_id(token):
    return token.split(':', 1)[0] if token and ':' in token else None


def decrypt(token, aad):
    try:
        key_id, payload = token.split(':', 1)
        blob = base64.urlsafe_b64decode(payload.encode())
    except (ValueError, AttributeError):
        raise DecryptionError('Malformed encrypted value.')
    keys = _keys()
    if key_id not in keys:
        raise DecryptionError(f"Encryption key '{key_id}' is not configured.")
    try:
        return AESGCM(keys[key_id]).decrypt(blob[:NONCE_SIZE], blob[NONCE_SIZE:], aad).decode()
    except InvalidTag:
        raise DecryptionError(f"Value cannot be decrypted with key '{key_id}' (wrong key or tampered data).")
