from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

__all__ = (
    'AllowedDomain',
    'ApprovalAction',
    'ApprovalRequest',
    'ApprovalStatus',
    'ApprovalVote',
    'PinEvent',
    'PinAccess',
    'PinAccessMode',
    'PinDelegate',
    'PinEventAction',
    'PinScopeMode',
    'PinSettings',
    'UserPin',
)


class PinScopeMode(models.TextChoices):
    GLOBAL = 'global', _('One unlock for everything')
    PER_SCOPE = 'per_scope', _('Separate unlock per scope (plugin / area)')


class PinAccessMode(models.TextChoices):
    ALL = 'all', _('All users may use a PIN (except denied users)')
    ALLOWED_ONLY = 'allowed_only', _('Only explicitly allowed users may use a PIN')


class PinAccess(models.TextChoices):
    DEFAULT = 'default', _('Default')
    ALLOWED = 'allowed', _('Allowed')
    DENIED = 'denied', _('Denied')


class PinSettings(models.Model):
    """
    Singleton holding the PIN policy. Edited in the UI by users with the change_pinsettings permission.
    """
    language = models.CharField(
        verbose_name=_('Language'),
        max_length=5,
        choices=(('en', 'English'), ('sk', 'Slovenčina')),
        default='en',
        help_text=_('Language of the User PIN pages and e-mails.'),
    )
    access_mode = models.CharField(
        verbose_name=_('Who may use a PIN'),
        max_length=20,
        choices=PinAccessMode.choices,
        default=PinAccessMode.ALLOWED_ONLY,
        help_text=_('Per-user Allow / Deny is set on the Users page. Superusers are always allowed.'),
    )
    pin_length = models.PositiveSmallIntegerField(
        verbose_name=_('PIN length'),
        default=6,
        validators=[MinValueValidator(4), MaxValueValidator(12)],
        help_text=_('Number of digits (4-12). Existing PINs of another length stay valid until changed.'),
    )
    unlock_minutes = models.PositiveIntegerField(
        verbose_name=_('Unlock duration (minutes)'),
        default=15,
        validators=[MinValueValidator(1), MaxValueValidator(24 * 60)],
    )
    sliding_unlock = models.BooleanField(
        verbose_name=_('Extend unlock on activity'),
        default=True,
        help_text=_('Every protected page view restarts the unlock timer (i.e. it expires after inactivity).'),
    )
    scope_mode = models.CharField(
        verbose_name=_('Unlock scope'),
        max_length=20,
        choices=PinScopeMode.choices,
        default=PinScopeMode.GLOBAL,
    )
    max_attempts = models.PositiveSmallIntegerField(
        verbose_name=_('Max failed attempts'),
        default=5,
        validators=[MinValueValidator(1), MaxValueValidator(50)],
    )
    lockout_minutes = models.PositiveIntegerField(
        verbose_name=_('Lockout duration (minutes)'),
        default=30,
        validators=[MinValueValidator(1), MaxValueValidator(7 * 24 * 60)],
    )
    block_weak_pins = models.BooleanField(
        verbose_name=_('Block weak PINs'),
        default=True,
        help_text=_('Reject repeated digits (111111), sequences (123456) and patterns (121212).'),
    )
    blocked_pins = models.TextField(
        verbose_name=_('Additional blocked PINs'),
        blank=True,
        help_text=_('One per line or comma separated.'),
    )
    max_age_days = models.PositiveIntegerField(
        verbose_name=_('PIN max age (days)'),
        default=180,
        validators=[MinValueValidator(1), MaxValueValidator(3650)],
        help_text=_('Users must change their PIN after this many days (company policy). Note: NIST SP 800-63B-4 '
                    'does not recommend periodic changes, only forced changes on suspected compromise.'),
    )
    warn_days = models.PositiveIntegerField(
        verbose_name=_('Warn before expiry (days)'),
        default=14,
        validators=[MaxValueValidator(365)],
    )
    require_2fa_admin = models.BooleanField(
        verbose_name=_('Require PIN + 2FA for administrative actions'),
        default=True,
        help_text=_('Allow / deny, reset, force change, settings and delegates need a fresh PIN + 2FA '
                    'confirmation (step-up). When off, the PIN alone is enough.'),
    )
    require_2fa_settings = models.BooleanField(
        verbose_name=_('Require 2FA also for settings'),
        default=False,
        help_text=_('Off: changes on the Settings and Mail pages need only your PIN (you are logged in anyway). '
                    'Actions on other users and delegates always need PIN + 2FA.'),
    )
    step_up_minutes = models.PositiveIntegerField(
        verbose_name=_('Administrative window (minutes)'),
        default=5,
        validators=[MinValueValidator(1), MaxValueValidator(60)],
        help_text=_('How long a step-up confirmation stays valid.'),
    )
    require_2fa_unlock = models.BooleanField(
        verbose_name=_('Require 2FA on every unlock'),
        default=False,
    )
    self_recovery = models.BooleanField(
        verbose_name=_('Self-service recovery of a forgotten PIN'),
        default=True,
        help_text=_('A code sent by e-mail AND a 2FA code are required together.'),
    )
    recovery_minutes = models.PositiveIntegerField(
        verbose_name=_('Recovery code validity (minutes)'),
        default=15,
        validators=[MinValueValidator(5), MaxValueValidator(60)],
    )
    allowed_email_domains = models.TextField(
        verbose_name=_('Allowed e-mail domains'),
        blank=True,
        help_text=_('E-mails are only sent to these domains, one per line (e.g. firma.sk). Empty = no e-mails.'),
    )
    reset_valid_hours = models.PositiveIntegerField(
        verbose_name=_('Administrator reset valid (hours)'),
        default=24,
        validators=[MinValueValidator(1), MaxValueValidator(24 * 14)],
        help_text=_('How long the user has to confirm a reset started by an administrator.'),
    )
    four_eyes = models.BooleanField(
        verbose_name=_('Four-eyes approval'),
        default=False,
        help_text=_('Selected administrative changes need a second administrator or delegate who confirms with '
                    'their own PIN + 2FA. Needs at least two administrators / delegates with PIN and 2FA.'),
    )
    four_eyes_delegates = models.BooleanField(verbose_name=_('… for delegates (add / remove / change)'),
                                              default=True)
    four_eyes_settings = models.BooleanField(verbose_name=_('… for settings and mail settings'), default=True)
    four_eyes_access = models.BooleanField(verbose_name=_('… for allowing / denying PIN use'), default=False)
    approval_valid_minutes = models.PositiveIntegerField(
        verbose_name=_('Approval request valid (minutes)'),
        default=24 * 60,
        validators=[MinValueValidator(5), MaxValueValidator(7 * 24 * 60)],
        help_text=_('Both can confirm live at the same time or the second one later, until the request expires.'),
    )
    break_glass = models.BooleanField(
        verbose_name=_('Allow break-glass for the master'),
        default=False,
        help_text=_('In an emergency a superuser may execute a request alone with a reason; all administrators '
                    'and delegates are informed by e-mail.'),
    )
    mail_from_name = models.CharField(verbose_name=_('Sender name'), max_length=100, blank=True,
                                      default='NetBox PIN', help_text=_('e.g. NetBox PIN'))
    mail_from_address = models.EmailField(
        verbose_name=_('Sender e-mail address'), blank=True,
        help_text=_('e.g. netbox@firma.sk. Together with the SMTP server; if the server is empty, the NetBox '
                    'e-mail configuration (EMAIL in configuration.py) is used.'),
    )
    smtp_server = models.CharField(
        verbose_name=_('SMTP server'), max_length=255, blank=True,
        help_text=_('e.g. mail.firma.sk. Empty = use the NetBox e-mail configuration.'),
    )
    smtp_port = models.PositiveIntegerField(verbose_name=_('SMTP port'), default=25,
                                            validators=[MinValueValidator(1), MaxValueValidator(65535)])
    smtp_timeout = models.PositiveIntegerField(verbose_name=_('SMTP timeout (s)'), default=10,
                                               validators=[MinValueValidator(1), MaxValueValidator(120)])
    smtp_security = models.CharField(
        verbose_name=_('Encryption'), max_length=10, default='none',
        choices=(('none', _('Off (usually port 25)')), ('starttls', _('STARTTLS (usually port 587)')),
                 ('ssl', _('SSL/TLS (usually port 465)'))),
    )
    smtp_auto_tls = models.BooleanField(
        verbose_name=_('Automatic TLS'), default=True,
        help_text=_('With encryption off, STARTTLS is used when the server offers it.'),
    )
    smtp_auth = models.BooleanField(verbose_name=_('SMTP authentication'), default=False)
    smtp_username = models.CharField(verbose_name=_('SMTP user'), max_length=255, blank=True,
                                     help_text=_('Service account the e-mails are sent from.'))
    smtp_password = models.TextField(blank=True, help_text='AES-256-GCM encrypted SMTP password.')
    notify_email = models.BooleanField(
        verbose_name=_('Security notifications by e-mail'),
        default=True,
        help_text=_('PIN set / changed / reset, lockout, upcoming expiry, 2FA changes.'),
    )

    class Meta:
        verbose_name = _('PIN settings')
        verbose_name_plural = _('PIN settings')

    def __str__(self):
        return str(_('PIN settings'))

    def save(self, *args, **kwargs):
        self.pk = 1
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        pass

    @classmethod
    def load(cls):
        obj, _created = cls.objects.get_or_create(pk=1)
        return obj


class UserPin(models.Model):
    """
    The PIN of one user. Only an encrypted Argon2id hash is stored.
    """
    user = models.OneToOneField(
        to=settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='user_pin',
    )
    pin_hash = models.TextField(
        blank=True,
        help_text='AES-256-GCM encrypted Argon2id hash; empty = PIN not set.',
    )
    version = models.PositiveIntegerField(
        default=0,
        help_text='Incremented on every change/reset; invalidates existing unlocks.',
    )
    access = models.CharField(
        max_length=20,
        choices=PinAccess.choices,
        default=PinAccess.DEFAULT,
        help_text='Administrator decision whether this user may use a PIN.',
    )
    suspended = models.BooleanField(default=False, help_text='Blocked by an administrator (e.g. suspected leak).')
    suspended_by = models.CharField(max_length=150, blank=True)
    pending_reset = models.CharField(
        max_length=10, blank=True, choices=(('pin', 'PIN'), ('2fa', '2FA')),
        help_text='Reset started by an administrator, waiting for the user to confirm.',
    )
    pending_reset_by = models.CharField(max_length=150, blank=True)
    pending_reset_expires = models.DateTimeField(null=True, blank=True)
    must_change = models.BooleanField(
        default=False,
        help_text='Forced PIN change at next use (administrator or test).',
    )
    totp_secret = models.TextField(blank=True, help_text='AES-256-GCM encrypted TOTP secret; empty = 2FA off.')
    totp_enabled = models.DateTimeField(null=True, blank=True)
    totp_last_step = models.BigIntegerField(default=0, help_text='Last accepted TOTP time step (replay protection).')
    backup_codes = models.JSONField(default=list, blank=True, help_text='Digests of unused backup codes.')
    backup_codes_encrypted = models.TextField(
        blank=True, help_text='AES-256-GCM encrypted list of the issued backup codes (for "show backup codes").',
    )
    email_code_purpose = models.CharField(max_length=30, blank=True)
    recovery_code = models.CharField(max_length=128, blank=True)
    recovery_expires = models.DateTimeField(null=True, blank=True)
    recovery_attempts = models.PositiveSmallIntegerField(default=0)
    recovery_sent = models.DateTimeField(null=True, blank=True)
    expiry_warned = models.DateTimeField(null=True, blank=True)
    failed_attempts = models.PositiveSmallIntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)
    changed = models.DateTimeField(null=True, blank=True)
    last_verified = models.DateTimeField(null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('user PIN')
        verbose_name_plural = _('user PINs')
        ordering = ('user__username',)

    def __str__(self):
        return f'PIN of {self.user}'

    @property
    def is_set(self):
        return bool(self.pin_hash)

    @property
    def reset_pending(self):
        """'pin', '2fa' or '' – only while not expired."""
        if self.pending_reset and self.pending_reset_expires and self.pending_reset_expires > timezone.now():
            return self.pending_reset
        return ''

    @property
    def has_2fa(self):
        return bool(self.totp_secret)

    @property
    def is_locked_out(self):
        return self.locked_until is not None and self.locked_until > timezone.now()

    @property
    def aad(self):
        # Binds the ciphertext to its owner: a hash copied to another user's row fails to decrypt.
        return f'netbox_user_pin:user:{self.user_id}'.encode()


class PinEventAction(models.TextChoices):
    SET = 'set', _('PIN set')
    CHANGED = 'changed', _('PIN changed')
    RESET = 'reset', _('PIN reset by administrator')
    VERIFIED = 'verified', _('PIN verified')
    FAILED = 'failed', _('Wrong PIN')
    LOCKED_OUT = 'locked_out', _('Locked out after failed attempts')
    REJECTED_LOCKED = 'rejected_locked', _('Attempt while locked out')
    LOCKOUT_CLEARED = 'lockout_cleared', _('Lockout cleared by administrator')
    FORCE_CHANGE = 'force_change', _('PIN change forced')
    TOTP_ENABLED = 'totp_enabled', _('2FA enabled')
    TOTP_DISABLED = 'totp_disabled', _('2FA disabled')
    TOTP_RESET = 'totp_reset', _('2FA reset by administrator')
    TOTP_FAILED = 'totp_failed', _('Wrong 2FA code')
    BACKUP_CODE_USED = 'backup_code_used', _('Backup code used')
    BACKUP_CODES_NEW = 'backup_codes_new', _('New backup codes generated')
    STEP_UP_OK = 'step_up_ok', _('Administrative confirmation (step-up)')
    STEP_UP_FAILED = 'step_up_failed', _('Administrative confirmation failed')
    RECOVERY_SENT = 'recovery_sent', _('Recovery code e-mailed')
    RECOVERY_OK = 'recovery_ok', _('PIN recovered (e-mail + 2FA)')
    RECOVERY_FAILED = 'recovery_failed', _('PIN recovery failed')
    MAIL_SENT = 'mail_sent', _('E-mail sent')
    MAIL_FAILED = 'mail_failed', _('E-mail failed')
    DELEGATE_ADDED = 'delegate_added', _('Delegate added')
    DELEGATE_REMOVED = 'delegate_removed', _('Delegate removed')
    DELEGATE_CHANGED = 'delegate_changed', _('Delegate changed')
    BACKUP_CODES_VIEWED = 'backup_codes_viewed', _('Backup codes viewed')
    EMAIL_CODE_SENT = 'email_code_sent', _('Verification code e-mailed')
    APPROVAL_REQUESTED = 'approval_requested', _('Four-eyes request created')
    APPROVAL_CONFIRMED = 'approval_confirmed', _('Four-eyes request confirmed')
    APPROVAL_REJECTED = 'approval_rejected', _('Four-eyes request rejected')
    APPROVAL_CANCELLED = 'approval_cancelled', _('Four-eyes request cancelled')
    APPROVAL_EXECUTED = 'approval_executed', _('Four-eyes request executed')
    BREAK_GLASS = 'break_glass', _('Break-glass: executed alone by the master')
    DOMAIN_ADDED = 'domain_added', _('Allowed e-mail domain added')
    DOMAIN_VERIFIED = 'domain_verified', _('Allowed e-mail domain verified')
    DOMAIN_VERIFY_FAILED = 'domain_verify_failed', _('Domain verification failed')
    DOMAIN_REMOVED = 'domain_removed', _('Allowed e-mail domain removed')
    ACCESS_CHANGED = 'access_changed', _('PIN access changed by administrator')
    SUSPENDED = 'suspended', _('PIN suspended by administrator')
    UNSUSPENDED = 'unsuspended', _('PIN suspension lifted by administrator')
    RESET_REQUESTED = 'reset_requested', _('Reset started by administrator')
    RESET_COMPLETED = 'reset_completed', _('Reset confirmed by the user')
    RESET_CANCELLED = 'reset_cancelled', _('Reset cancelled')
    NOT_ALLOWED = 'not_allowed', _('Attempt by a user not allowed to use a PIN')
    LOCKED = 'locked', _('Locked manually')
    SETTINGS_CHANGED = 'settings_changed', _('Settings changed')
    KEY_ROTATED = 'key_rotated', _('Encryption key rotated')
    ERROR = 'error', _('Error')


class PinEvent(models.Model):
    """
    Append-only audit record. Never contains a PIN or a hash.
    """
    time = models.DateTimeField(default=timezone.now, db_index=True, editable=False)
    action = models.CharField(max_length=30, choices=PinEventAction.choices, db_index=True, editable=False)
    user = models.ForeignKey(
        to=settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='+',
        editable=False,
        help_text='Owner of the PIN the event is about.',
    )
    username = models.CharField(max_length=150, blank=True, editable=False)
    actor = models.ForeignKey(
        to=settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='+',
        editable=False,
        help_text='Who performed the action (differs from user for admin actions).',
    )
    actor_username = models.CharField(max_length=150, blank=True, editable=False)
    scope = models.CharField(max_length=100, blank=True, editable=False)
    ip_address = models.GenericIPAddressField(null=True, blank=True, editable=False)
    user_agent = models.CharField(max_length=255, blank=True, editable=False)
    detail = models.TextField(blank=True, editable=False)

    class Meta:
        verbose_name = _('PIN event')
        verbose_name_plural = _('PIN events')
        ordering = ('-time', '-pk')

    def __str__(self):
        return f'{self.time:%Y-%m-%d %H:%M:%S} {self.username or "-"} {self.action}'

    def save(self, *args, **kwargs):
        if self.pk is not None:
            raise RuntimeError('PIN events are append-only and cannot be modified.')
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise RuntimeError('PIN events are append-only and cannot be deleted.')


class PinDelegate(models.Model):
    """
    A user or group the master (superuser) delegated PIN administration to. Synchronised into NetBox object
    permissions so that menus and permission checks work natively.
    """
    user = models.OneToOneField(
        to=settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True, related_name='+',
    )
    group = models.OneToOneField(
        to='users.Group', on_delete=models.CASCADE, null=True, blank=True, related_name='+',
    )
    can_edit_settings = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=150, blank=True)

    class Meta:
        verbose_name = _('PIN delegate')
        verbose_name_plural = _('PIN delegates')
        constraints = (
            models.CheckConstraint(
                condition=(
                    models.Q(user__isnull=False, group__isnull=True) | models.Q(user__isnull=True, group__isnull=False)
                ),
                name='netbox_user_pin_delegate_user_xor_group',
            ),
        )

    def __str__(self):
        return f'user {self.user}' if self.user_id else f'group {self.group}'


class ApprovalAction(models.TextChoices):
    DELEGATE_ADD = 'delegate_add', _('Add delegate')
    DELEGATE_REMOVE = 'delegate_remove', _('Remove delegate')
    DELEGATE_TOGGLE = 'delegate_toggle', _('Change delegate settings permission')
    SETTINGS = 'settings', _('Change PIN settings')
    MAIL_SETTINGS = 'mail_settings', _('Change mail settings')
    ACCESS = 'access', _('Allow / deny PIN use')
    DOMAIN_ADD = 'domain_add', _('Add allowed e-mail domain')


class ApprovalStatus(models.TextChoices):
    PENDING = 'pending', _('Waiting')
    EXECUTED = 'executed', _('Approved and executed')
    REJECTED = 'rejected', _('Rejected')
    CANCELLED = 'cancelled', _('Cancelled')
    EXPIRED = 'expired', _('Expired')
    FAILED = 'failed', _('Failed')


class ApprovalRequest(models.Model):
    """
    A four-eyes request: an administrative change that runs only after two different people confirmed it with
    their own PIN + 2FA (the requester and one other administrator / delegate).
    """
    action = models.CharField(max_length=30, choices=ApprovalAction.choices)
    payload = models.JSONField(default=dict)
    summary = models.CharField(max_length=500)
    reason = models.CharField(max_length=500, blank=True)
    requested_by = models.ForeignKey(
        to=settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='+',
    )
    requested_by_name = models.CharField(max_length=150)
    approver = models.ForeignKey(
        to=settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='+',
        help_text='Optional: only this person may give the second confirmation.',
    )
    created = models.DateTimeField(auto_now_add=True)
    expires = models.DateTimeField()
    status = models.CharField(max_length=20, choices=ApprovalStatus.choices, default=ApprovalStatus.PENDING)
    finished = models.DateTimeField(null=True, blank=True)
    result = models.TextField(blank=True)
    break_glass = models.BooleanField(default=False)

    class Meta:
        verbose_name = _('four-eyes request')
        verbose_name_plural = _('four-eyes requests')
        ordering = ('-created',)

    def __str__(self):
        return f'Four-eyes #{self.pk}: {self.summary}'

    def get_absolute_url(self):
        from django.urls import reverse
        return reverse('plugins:netbox_user_pin:approval', kwargs={'pk': self.pk})

    @property
    def is_open(self):
        return self.status == ApprovalStatus.PENDING and self.expires > timezone.now()


class ApprovalVote(models.Model):
    request = models.ForeignKey(to=ApprovalRequest, on_delete=models.CASCADE, related_name='votes')
    user = models.ForeignKey(to=settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='+')
    username = models.CharField(max_length=150)
    approve = models.BooleanField()
    time = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        ordering = ('time',)
        constraints = (
            models.UniqueConstraint(fields=('request', 'user'), name='netbox_user_pin_one_vote_per_user'),
        )


class AllowedDomain(models.Model):
    """
    E-mail domain the plugin may send to. Only verified domains are used: verification sends a code to an
    address in the domain, which must be entered back.
    """
    domain = models.CharField(max_length=253, unique=True)
    created = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=150, blank=True)
    verified = models.DateTimeField(null=True, blank=True)
    verified_by = models.CharField(max_length=150, blank=True)
    verified_email = models.CharField(max_length=254, blank=True)
    code = models.CharField(max_length=128, blank=True)
    code_email = models.CharField(max_length=254, blank=True)
    code_expires = models.DateTimeField(null=True, blank=True)
    code_attempts = models.PositiveSmallIntegerField(default=0)

    class Meta:
        verbose_name = _('allowed e-mail domain')
        verbose_name_plural = _('allowed e-mail domains')
        ordering = ('domain',)

    def __str__(self):
        return self.domain

    @property
    def is_verified(self):
        return self.verified is not None

    @property
    def code_pending(self):
        return bool(self.code and self.code_expires and self.code_expires > timezone.now())
