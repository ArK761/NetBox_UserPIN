"""
RFC 6238 TOTP (30 s, 6 digits, SHA-1) compatible with Microsoft / Google Authenticator, Authy, 1Password ...
and one-time backup codes.
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote, urlencode

__all__ = (
    'STEP',
    'format_backup_code',
    'generate_backup_codes',
    'generate_secret',
    'hash_backup_code',
    'match_step',
    'normalize_backup_code',
    'provisioning_uri',
)

STEP = 30
DIGITS = 6
BACKUP_CODE_COUNT = 10


def generate_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip('=')


def _code_at(secret, counter):
    key = base64.b32decode(secret + '=' * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack('>Q', counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** DIGITS).zfill(DIGITS)


def match_step(secret, code, now=None, window=1):
    """Return the matching time step for ``code`` (±window steps) or None."""
    code = (code or '').strip().replace(' ', '')
    if len(code) != DIGITS or not code.isdigit():
        return None
    current = int((now if now is not None else time.time()) // STEP)
    for step in range(current - window, current + window + 1):
        if hmac.compare_digest(_code_at(secret, step), code):
            return step
    return None


def provisioning_uri(secret, account, issuer='NetBox'):
    label = quote(f'{issuer}:{account}')
    return f'otpauth://totp/{label}?' + urlencode({'secret': secret, 'issuer': issuer, 'digits': DIGITS,
                                                    'period': STEP})


# Backup codes: 20 base32 characters = 100 bits, shown as XXXX-XXXX-XXXX-XXXX-XXXX. High entropy, so a plain
# SHA-256 digest is sufficient for storage.

def normalize_backup_code(code):
    return (code or '').upper().replace('-', '').replace(' ', '')


def format_backup_code(code):
    return '-'.join(code[i:i + 4] for i in range(0, len(code), 4))


def hash_backup_code(code):
    return hashlib.sha256(b'netbox_user_pin:backup:' + normalize_backup_code(code).encode()).hexdigest()


def generate_backup_codes(count=BACKUP_CODE_COUNT):
    codes = [base64.b32encode(secrets.token_bytes(13)).decode()[:20] for _ in range(count)]
    return [format_backup_code(c) for c in codes]
