# NetBox User PIN

A reusable NetBox plugin that gives every user a **personal PIN**. Other plugins use it to protect
sensitive pages ("enter your PIN to continue"), so the PIN logic exists only once.

- One personal PIN per user, valid for all plugins that use it
- PIN stored as **Argon2id hash encrypted with AES-256-GCM** – the key lives only in the NetBox configuration
- Unlock is kept in the session for a configurable time (optionally extended on activity)
- Lockout after too many wrong attempts, weak PINs rejected (`111111`, `123456`, `121212`, own blocklist)
- Administrator can **reset** a PIN or clear a lockout, but can never read it
- Append-only **audit log** of every PIN event (never contains a PIN or hash)
- Settings page in the UI, simple API + signals for other plugins

Requires NetBox **4.7+** (Python 3.12+).

## Installation

```bash
source /opt/netbox/venv/bin/activate
pip install git+https://github.com/ArK761/NetBox_UserPIN.git
```

Generate an encryption key (the plugin is not active yet, so use plain Python):

```bash
python3 -c "import base64,os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
```

(Once the plugin is running, `python manage.py userpin_generate_key` does the same.)

Add to `configuration.py`:

```python
PLUGINS = ['netbox_user_pin']

PLUGINS_CONFIG = {
    'netbox_user_pin': {
        'encryption_keys': {'k1': '<generated key or any secret of 32+ characters>'},
        'active_key_id': 'k1',
    },
}
```

> Keep an **offline backup** of the key and never put it into the same backup as the database.
> If the key is lost no other data is lost – users simply set new PINs.

Then:

```bash
python manage.py migrate
sudo systemctl restart netbox
```

### Optional configuration

| Setting | Default | Meaning |
|---|---|---|
| `encryption_keys` | – (required) | `{key_id: key}` – urlsafe base64 32-byte key, or any secret of 32+ characters |
| `active_key_id` | the only key | key used for new encryptions |
| `argon2_time_cost` | `3` | Argon2id iterations |
| `argon2_memory_cost` | `65536` | Argon2id memory in KiB (64 MiB) |
| `argon2_parallelism` | `4` | Argon2id lanes |

Everything else is configured in the UI: **User PIN → Settings**.

## UI

| Menu | Who | What |
|---|---|---|
| My PIN | every user | status, set / change PIN, lock now, own recent activity |
| Test unlock | every user | a protected page to try the flow |
| Users | `view_userpin` / `change_userpin` | PIN status of all users, reset PIN, clear lockout |
| Audit log | `view_pinevent` | all PIN events, filter by user and event |
| Settings | `change_pinsettings` | PIN policy, unlock time, scope mode, lockout, key fingerprint |

Grant the permissions with regular NetBox object permissions (superusers have all of them).

### Settings

| Setting | Default |
|---|---|
| PIN length | 6 digits |
| Block weak PINs / additional blocked PINs | on / empty |
| PIN max age | 0 (never expires) |
| Unlock duration | 15 minutes |
| Extend unlock on activity | on |
| Unlock scope | one unlock for everything (or separate per plugin / area) |
| Max failed attempts / lockout | 5 / 30 minutes |

## Using it from another plugin

Add `netbox-user-pin` to your plugin's dependencies and protect views:

```python
from netbox_user_pin.mixins import PinRequiredMixin, pin_required

class ProjectView(PinRequiredMixin, generic.ObjectView):
    pin_scope = 'projects'          # used when the scope mode is "per scope"

@pin_required(scope='projects')
def download(request, pk): ...
```

The user is redirected to *set PIN* (no PIN yet), *change PIN* (expired) or *enter PIN* and then back to
the original page. HTMX requests get an `HX-Redirect` header.

Service API (`netbox_user_pin.service`):

```python
service.has_pin(user)
service.is_unlocked(request, scope='projects')
service.unlock(request, pin, scope='projects')   # -> VerifyResult (.ok, .status, .remaining_attempts)
service.verify_pin(user, pin)                    # check without unlocking (e.g. confirm a dangerous action)
service.lock(request)                            # lock everything in this session
```

Signals (`netbox_user_pin.signals`) – e.g. to copy events into your own audit log:
`pin_set`, `pin_changed`, `pin_reset`, `pin_unlocked`, `pin_failed`, `pin_locked_out`, `pin_locked`.
All are sent with `sender=UserPin` and kwargs `user`, `request`, `scope` (+ `actor`, `remaining_attempts`,
`until` where relevant).

## Security model

```
PIN ──Argon2id + salt──► hash ──AES-256-GCM (key from configuration, bound to user id)──► database
```

- A database dump alone contains nothing usable – not even something to brute-force offline.
- The ciphertext is bound to its user: a hash copied into another user's row does not decrypt.
- Wrong attempts are counted under a row lock, so parallel guessing cannot bypass the lockout.
- A PIN change or reset invalidates every existing unlock of that user.
- The PIN is only an authentication factor ("it is really you at this computer"); it is not used as an
  encryption key for other data.

## Key rotation

1. Add the new key next to the old one and make it active:
   `'encryption_keys': {'k1': '<old>', 'k2': '<new>'}, 'active_key_id': 'k2'`
2. Restart NetBox and run `python manage.py userpin_rotate_key`
3. Verify with `python manage.py userpin_check`, then remove the old key.

The plugin never generates or switches keys by itself – a missing or wrong key is reported as an error.

## Development

Tests run inside a NetBox checkout with the plugin listed in `PLUGINS`:

```bash
python manage.py test netbox_user_pin
```
