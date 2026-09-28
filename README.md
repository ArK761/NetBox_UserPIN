# NetBox User PIN

A reusable NetBox plugin that gives every user a **personal PIN**. Other plugins use it to protect
sensitive pages ("enter your PIN to continue"), so the PIN logic exists only once.

- One personal PIN per user, valid for all plugins that use it
- PIN stored as **Argon2id hash encrypted with AES-256-GCM** – the key lives only in the NetBox configuration
- Unlock is kept in the session for a configurable time (optionally extended on activity)
- Lockout after too many wrong attempts, weak PINs rejected (`111111`, `123456`, `121212`, own blocklist)
- **Default deny**: only the master (superusers) and explicitly allowed users may use a PIN
- **PIN rotation** (default every 180 days) with expiry warning, forced change and a "test rotation" button
- **Two-factor authentication** (TOTP – Microsoft / Google Authenticator …) with one-time backup codes
- **Step-up**: administrative actions need a fresh PIN + 2FA confirmation (valid a few minutes)
- **Forgotten PIN**: self-service recovery needs an e-mailed code **and** a 2FA code together
- E-mails only to allowed company domains; security notifications (changed, reset, locked, expiring)
- **Delegation**: the master names users / groups who manage PINs (separation of duties)
- **An administrator alone can only remove access** (suspend). A PIN reset is started by an administrator and
  confirmed by the user in their own session with 2FA (a 2FA reset with the PIN) – no meeting needed, the
  administrator never learns the new PIN
- **Four-eyes approval** (optional) for delegates, settings and PIN access: the requester and a second
  administrator / delegate confirm with their own PIN + 2FA – live in their own sessions (each sees the other's
  confirmation) or later until the request expires; optional break-glass for the master
- **Backup codes** stored encrypted; *Show backup codes* after PIN + 2FA or PIN + an e-mailed verification code
  (the codes themselves are never e-mailed)
- Emergency server command for a 2FA reset shown at each account
- **Languages: English / Slovenčina** (Settings → General) for the plugin pages and e-mails
- Administrative confirmation in a **pop-up** directly on the page – the action continues without leaving it.
  Settings and Mail need only the PIN (optionally also 2FA); actions on other users and delegates need
  PIN + 2FA; connection and test e-mail need no confirmation
- Allowed domains entered as `@firma.sk`, exact match only (no sub-domains or look-alikes); verification in a
  pop-up: address → code by e-mail → enter code; **Verify again** at any time (e.g. new address)
- **Mail** page: own SMTP server (server, port, encryption off / STARTTLS / SSL, automatic TLS, SMTP
  authentication with a service account; password encrypted, never shown), connection test; **allowed e-mail
  domains must be verified** with a code sent to an address in the domain before any e-mail goes there
- Separate **Mail** page: allowed domains, notifications, self-service recovery, test e-mail to a chosen user
  (the picker shows account, name and the e-mail address it will go to)
- First and last name shown next to the account in Users and Delegates (Settings → General, can be turned off)
- Append-only **audit log** of every PIN event (never contains a PIN, hash or code)
- Settings page in the UI, stable API + signals for other plugins

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

E-mails (recovery codes, notifications) are sent through the SMTP server configured on the **Mail** page
(service account set by the administrator, password stored encrypted). If no server is set there, NetBox's own
`EMAIL` setting is used.

Then:

```bash
python manage.py migrate
sudo systemctl restart netbox
```

After the first start: log in as superuser → **User PIN → My PIN** → set your PIN and **set up 2FA**
(needed for every administrative action), then set the allowed e-mail domains in **Settings** and allow users
on the **Users** page.

### Optional configuration

| Setting | Default | Meaning |
|---|---|---|
| `encryption_keys` | – (required) | `{key_id: key}` – urlsafe base64 32-byte key, or any secret of 32+ characters |
| `active_key_id` | the only key | key used for new encryptions |
| `argon2_time_cost` | `3` | Argon2id iterations |
| `argon2_memory_cost` | `65536` | Argon2id memory in KiB (64 MiB) |
| `argon2_parallelism` | `4` | Argon2id lanes |
| `cli_venv` | `/opt/netbox/venv` | shown in the emergency server command |
| `cli_netbox_dir` | `/opt/netbox/netbox` | shown in the emergency server command |

Everything else is configured in the UI: **User PIN → Settings**.

## Roles and UI

| Menu | Master (superuser) | Delegate | User |
|---|---|---|---|
| My PIN – PIN, 2FA, backup codes, recovery, test rotation, own activity | ✅ | ✅ | ✅ |
| Users – summary, PIN / 2FA / e-mail / expiry status of everybody | ✅ | ✅ | – |
| Users – allow / deny, suspend, start PIN / 2FA reset, force change, clear lockout | ✅ except self | ✅ except master, other delegates, self | – |
| Audit log | ✅ | ✅ | – |
| Settings, Mail | ✅ edit | view (edit only if allowed by the master) | – |
| Delegates | ✅ | – | – |

All changes on Users, Settings and Delegates require a **step-up** (PIN + 2FA). Administration pages also
require the administrator's own unlocked PIN.

Delegates are stored by the plugin and synchronised into NetBox object permissions named
`User PIN: delegates …` / `User PIN: settings editors` – do not edit those by hand.

### Settings (defaults)

| Setting | Default |
|---|---|
| Who may use a PIN | only explicitly allowed users (superusers always) |
| PIN length / block weak PINs | 6 digits / on |
| PIN max age / warn before | 180 days / 14 days (NIST SP 800-63B-4 does not recommend periodic changes – set according to your company policy) |
| Unlock duration / extend on activity / scope | 15 min / on / one unlock for everything |
| Require 2FA on every unlock | off |
| Show first and last name | on |
| Max failed attempts / lockout | 5 / 30 min (PIN and 2FA failures count together) |
| PIN + 2FA for administrative actions / window | on / 5 min |
| Self-service recovery (e-mail code + 2FA) / code validity | on / 15 min |
| Allowed e-mail domains (Mail page) | none – add and **verify** each domain (code sent to an address in it) |
| Security notifications by e-mail | on |

### Administrator resets (no meeting needed)

| Action | Administrator | User (own session) |
|---|---|---|
| **Suspend PIN** (suspected leak, user absent) | blocks immediately, alone | – |
| **Reset PIN** (forgotten PIN) | starts the reset (valid 24 h by default) | confirms with a **2FA code** and sets a new PIN |
| **Reset 2FA** (lost phone) | starts the reset | confirms with the **PIN** and enrolls the new phone |

Until the user confirms, the old PIN keeps working; the administrator can cancel a pending reset. A reset
requires the user to have 2FA.

### Four-eyes approval

Settings → *Four-eyes approval* (needs at least two administrators / delegates with PIN and 2FA). Choose what it
applies to: delegates, settings (incl. mail), PIN access. Then such a change creates a request:

1. The requester confirms with PIN + 2FA (and a reason).
2. Any other administrator / delegate gets a NetBox notification (bell) and an e-mail, opens
   *User PIN → Approvals* and confirms or rejects with their own PIN + 2FA.
3. The request page refreshes itself every few seconds – both see live who has confirmed (time and IP).
   After the second confirmation the change is executed. Requests expire (default 24 h).

Break-glass (off by default): a superuser may execute a request alone with a reason; all administrators and
delegates are informed and it is marked in the audit log.

### Backup codes

*My PIN → Show backup codes*: PIN + a 2FA code, or – without the phone – PIN + a verification code sent by
e-mail. The codes are shown only in the browser (used ones crossed out), with *Generate new codes*. The user
gets an e-mail notification. Users who enabled 2FA before 0.5.0 get new codes on the first view.

### Emergency 2FA reset on the server

Shown at each account (*Users → Actions → Emergency: server command* and in *My PIN*):

```bash
sudo bash -c 'source /opt/netbox/venv/bin/activate && cd /opt/netbox/netbox && python manage.py userpin_reset_2fa <user>'
```

The paths come from the plugin settings `cli_venv` and `cli_netbox_dir`.

### Forgotten PIN (self-service)

1. *My PIN → Forgot PIN* (or the link on the unlock page) → **Send code** – an 8 digit code is e-mailed
   (only to an allowed domain, valid 15 min, max 5 attempts, resend after 60 s).
2. Enter the e-mail code **and** a 2FA code (or a backup code) and the new PIN.

Without an e-mail in an allowed domain or without 2FA the recovery is not offered – an administrator resets
the PIN. Emergency for a master without phone and backup codes: `python manage.py userpin_reset_2fa <user>`.

## Using it from another plugin

Add `netbox-user-pin` to your plugin's dependencies and protect views:

```python
from netbox_user_pin.mixins import PinRequiredMixin, StepUpRequiredMixin, pin_required, step_up_required

class ProjectView(PinRequiredMixin, generic.ObjectView):
    pin_scope = 'projects'          # used when the scope mode is "per scope"

class ProjectDeleteView(StepUpRequiredMixin, generic.ObjectDeleteView):
    ...                             # sensitive action: fresh PIN + 2FA

@pin_required(scope='projects')
def download(request, pk): ...
```

Check `netbox_user_pin.service.API_VERSION` (currently `2`) if you rely on newer features; the API only grows,
existing calls keep working.

The user is redirected to *set PIN* (no PIN yet), *change PIN* (expired) or *enter PIN* and then back to
the original page. HTMX requests get an `HX-Redirect` header.

Service API (`netbox_user_pin.service`):

```python
service.has_pin(user)
service.is_unlocked(request, scope='projects')
service.unlock(request, pin, scope='projects')   # -> VerifyResult (.ok, .status, .remaining_attempts)
service.verify_pin(user, pin)                    # check without unlocking (e.g. confirm a dangerous action)
service.lock(request)                            # lock everything in this session
service.has_step_up(request)                     # fresh PIN (+ 2FA) confirmation active?
service.has_2fa(user), service.is_allowed(user)
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
- TOTP secrets are encrypted the same way; a TOTP code is accepted only once (replay protection).
- Backup codes (100 bits) and e-mailed recovery codes are stored only as digests, single use, short-lived.
- Recovery never bypasses 2FA (OWASP Forgot Password / MFA cheat sheets; NIST SP 800-63B-4 allows e-mail only
  for recovery codes, not as an authentication factor).
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
