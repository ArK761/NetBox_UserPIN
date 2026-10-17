from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

__all__ = (
    'AllowedDomain',
    'AreaGrant',
    'AreaOwner',
    'AreaFieldRule',
    'AreaProfile',
    'AreaRequest',
    'AreaRequestStatus',
    'PolicyKeeper',
    'ProtectedArea',
    'ApprovalAction',
    'ApprovalRequest',
    'ApprovalStatus',
    'ApprovalVote',
    'Department',
    'DepartmentMember',
    'PinEvent',
    'PinAccess',
    'PinAccessMode',
    'PinDelegate',
    'PinEventAction',
    'PinScopeMode',
    'PinSettings',
    'RoleKind',
    'RoleStatus',
    'TransferRequest',
    'TransferStatus',
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
    show_full_names = models.BooleanField(
        verbose_name=_('Show first and last name'),
        default=True,
        help_text=_('Show the users\' first and last name next to the username (Users, Delegates, e-mail recipients).'),
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
        help_text=_('Off: changes on the Settings and Mail pages and everyday actions (allow PIN, moves between '
                    'departments) need only your PIN (you are logged in anyway). Resets, suspension and roles always '
                    'need PIN + 2FA.'),
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
        help_text=_('Selected administrative changes need a second person who confirms with their own PIN + 2FA. '
                    'Turning it on needs at least two active CORE deputies. It cannot be turned off while a '
                    'department exists; turning it off needs two people and ends the CORE delegation.'),
    )
    four_eyes_delegates = models.BooleanField(verbose_name=_('… for roles (CORE, department heads and delegates)'),
                                              default=True)
    four_eyes_settings = models.BooleanField(verbose_name=_('… for settings and mail settings'), default=True)
    four_eyes_access = models.BooleanField(verbose_name=_('… for allowing / denying PIN use'), default=False)
    default_deny = models.BooleanField(
        verbose_name=_('Deny everything not allowed'),
        default=False,
        help_text=_('Everything that no protected area allows is denied to everybody except the protection keepers. '
                    'Needs at least one keeper (PIN + 2FA).'),
    )
    areas_enabled = models.BooleanField(
        verbose_name=_('Protect areas and objects'),
        default=False,
        help_text=_('The areas defined on the Protected areas page take effect: access to their objects (pages, lists, '
                    'editing, REST API, menu, tabs) is decided by PIN grants given by the area owners, whatever the '
                    'NetBox role of the user is, superusers included. Plugins that offer a PIN integration '
                    '(e.g. LibreOXI) are protected when their own switch is on, even if this one is off.'),
    )
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
    ROLE_INVITED = 'role_invited', _('Role invitation sent')
    ROLE_ACCEPTED = 'role_accepted', _('Role accepted')
    ROLE_DECLINED = 'role_declined', _('Role invitation declined')
    ROLE_EXPIRED = 'role_expired', _('Role invitation expired')
    ROLE_RESIGNING = 'role_resigning', _('Resignation waiting for a replacement')
    ROLE_ENDED = 'role_ended', _('Role ended')
    ROLE_ON_LEAVE = 'role_on_leave', _('Rights handed over temporarily')
    ROLE_RETURNED = 'role_returned', _('Rights returned')
    DEPARTMENT_CREATED = 'department_created', _('Department created')
    DEPARTMENT_DELETED = 'department_deleted', _('Department dissolved')
    MEMBER_ADDED = 'member_added', _('Member added to a department')
    MEMBER_REMOVED = 'member_removed', _('Member removed from a department')
    TRANSFER_REQUESTED = 'transfer_requested', _('Move between departments requested')
    TRANSFER_APPROVED = 'transfer_approved', _('Move between departments approved')
    TRANSFER_REJECTED = 'transfer_rejected', _('Move between departments rejected')
    AREA_CREATED = 'area_created', _('Protected area created')
    AREA_CHANGED = 'area_changed', _('Protected area changed')
    AREA_DELETED = 'area_deleted', _('Protected area deleted')
    AREA_OWNER_ADDED = 'area_owner_added', _('Area owner added')
    AREA_OWNER_REMOVED = 'area_owner_removed', _('Area owner removed')
    AREA_REQUESTED = 'area_requested', _('Access to an area requested')
    AREA_GRANTED = 'area_granted', _('Access to an area granted')
    AREA_DENIED = 'area_denied', _('Access request denied')
    AREA_REVOKED = 'area_revoked', _('Access to an area revoked')
    AREA_CANCELLED = 'area_cancelled', _('Access request cancelled')
    AREA_BLOCKED = 'area_blocked', _('Access to an area refused')
    KEEPER_ADDED = 'keeper_added', _('Protection keeper appointed')
    KEEPER_REMOVED = 'keeper_removed', _('Protection keeper removed')
    DENY_ENABLED = 'deny_enabled', _('Default deny switched on')
    DENY_DISABLED = 'deny_disabled', _('Default deny switched off')
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


class Department(models.Model):
    """A department (workplace). Its head and delegates manage the PINs of its members."""
    name = models.CharField(verbose_name=_('Name'), max_length=100, unique=True)
    description = models.CharField(verbose_name=_('Description'), max_length=200, blank=True)
    created = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=150, blank=True)

    class Meta:
        verbose_name = _('department')
        verbose_name_plural = _('departments')
        ordering = ('name',)

    def __str__(self):
        return self.name


class DepartmentMember(models.Model):
    """A user belongs to at most one department."""
    user = models.OneToOneField(to=settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='pin_membership')
    department = models.ForeignKey(to=Department, on_delete=models.CASCADE, related_name='members')
    added = models.DateTimeField(auto_now_add=True)
    added_by = models.CharField(max_length=150, blank=True)

    class Meta:
        verbose_name = _('department member')
        verbose_name_plural = _('department members')
        ordering = ('user__username',)

    def __str__(self):
        return f'{self.user} @ {self.department}'


class RoleKind(models.TextChoices):
    CORE = 'core', _('CORE deputy')
    HEAD = 'head', _('Department head')
    DELEGATE = 'delegate', _('Department delegate')


class RoleStatus(models.TextChoices):
    PENDING = 'pending', _('Waiting for acceptance')
    ACTIVE = 'active', _('Active')
    ON_LEAVE = 'on_leave', _('Handed over temporarily')
    RESIGNING = 'resigning', _('Resigning (until replaced)')
    ENDED = 'ended', _('Ended')
    DECLINED = 'declined', _('Declined')
    EXPIRED = 'expired', _('Expired')


OPEN_ROLE_STATUSES = (RoleStatus.PENDING, RoleStatus.ACTIVE, RoleStatus.ON_LEAVE, RoleStatus.RESIGNING)
EFFECTIVE_ROLE_STATUSES = (RoleStatus.ACTIVE, RoleStatus.RESIGNING)


class PinDelegate(models.Model):
    """
    A role in the PIN administration: CORE deputy (department = empty), department head or department delegate.
    A role starts as an invitation and is effective only after the user accepted it (e-mail code + PIN + 2FA).
    Effective roles are synchronised into NetBox object permissions so that menus and permission checks work.
    """
    user = models.ForeignKey(to=settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='pin_roles')
    role = models.CharField(max_length=10, choices=RoleKind.choices, default=RoleKind.CORE)
    department = models.ForeignKey(to=Department, on_delete=models.CASCADE, null=True, blank=True,
                                   related_name='roles')
    status = models.CharField(max_length=10, choices=RoleStatus.choices, default=RoleStatus.PENDING)
    can_edit_settings = models.BooleanField(default=False)
    temporary_until = models.DateTimeField(null=True, blank=True, help_text='Temporary head until this time.')
    substitute_for = models.ForeignKey(to='self', on_delete=models.SET_NULL, null=True, blank=True,
                                       related_name='substitutes', help_text='Temporary head: the regular head.')
    replaces = models.ForeignKey(to='self', on_delete=models.SET_NULL, null=True, blank=True,
                                 related_name='replaced_by', help_text='Role that ends when this one is accepted.')
    reason = models.CharField(max_length=500, blank=True)
    invited_by = models.CharField(max_length=150, blank=True)
    invite_hours = models.PositiveSmallIntegerField(default=24)
    invite_code = models.CharField(max_length=128, blank=True)
    invite_expires = models.DateTimeField(null=True, blank=True)
    invite_sent = models.DateTimeField(null=True, blank=True)
    invite_attempts = models.PositiveSmallIntegerField(default=0)
    reminder_sent = models.DateTimeField(null=True, blank=True)
    accepted = models.DateTimeField(null=True, blank=True)
    ended = models.DateTimeField(null=True, blank=True)
    end_reason = models.CharField(max_length=500, blank=True)
    created = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=150, blank=True)

    class Meta:
        verbose_name = _('PIN role')
        verbose_name_plural = _('PIN roles')
        ordering = ('created',)

    def __str__(self):
        where = f' {self.department}' if self.department_id else ''
        return f'{self.get_role_display()}{where}: {self.user}'

    def get_absolute_url(self):
        from django.urls import reverse
        return reverse('plugins:netbox_user_pin:invitation', kwargs={'pk': self.pk})

    @property
    def is_open(self):
        return self.status in OPEN_ROLE_STATUSES

    @property
    def is_effective(self):
        return self.status in EFFECTIVE_ROLE_STATUSES and self.user.is_active

    @property
    def invite_pending(self):
        return (self.status == RoleStatus.PENDING and bool(self.invite_code) and self.invite_expires is not None
                and self.invite_expires > timezone.now())

    @property
    def is_temporary(self):
        return self.temporary_until is not None


class TransferStatus(models.TextChoices):
    PENDING = 'pending', _('Waiting')
    APPROVED = 'approved', _('Approved')
    REJECTED = 'rejected', _('Rejected')
    CANCELLED = 'cancelled', _('Cancelled')
    EXPIRED = 'expired', _('Expired')


class TransferRequest(models.Model):
    """Move of a user between departments, requested by one head and approved by the head of the other one."""
    user = models.ForeignKey(to=settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='+')
    from_department = models.ForeignKey(to=Department, on_delete=models.CASCADE, null=True, blank=True,
                                        related_name='+')
    to_department = models.ForeignKey(to=Department, on_delete=models.CASCADE, related_name='+')
    requested_by = models.ForeignKey(to=settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True,
                                     related_name='+')
    requested_by_name = models.CharField(max_length=150)
    approving_department = models.ForeignKey(to=Department, on_delete=models.CASCADE, null=True, blank=True,
                                             related_name='+', help_text='Department whose head must approve.')
    status = models.CharField(max_length=10, choices=TransferStatus.choices, default=TransferStatus.PENDING)
    created = models.DateTimeField(auto_now_add=True)
    expires = models.DateTimeField()
    decided = models.DateTimeField(null=True, blank=True)
    decided_by = models.CharField(max_length=150, blank=True)

    class Meta:
        verbose_name = _('department move')
        verbose_name_plural = _('department moves')
        ordering = ('-created',)

    def __str__(self):
        return f'{self.user}: {self.from_department or "-"} -> {self.to_department}'

    def get_absolute_url(self):
        from django.urls import reverse
        return reverse('plugins:netbox_user_pin:department_list')

    @property
    def is_open(self):
        return self.status == TransferStatus.PENDING and self.expires > timezone.now()


class ApprovalAction(models.TextChoices):
    DELEGATE_ADD = 'delegate_add', _('Invite to a role')
    DELEGATE_REMOVE = 'delegate_remove', _('End or replace a role')
    DELEGATE_TOGGLE = 'delegate_toggle', _('Change delegate settings permission')
    DEPARTMENT_DELETE = 'department_delete', _('Dissolve a department')
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
    department = models.ForeignKey(
        to=Department, on_delete=models.SET_NULL, null=True, blank=True, related_name='+',
        help_text='Department request: its head and delegates (and CORE) may confirm.',
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


#
# Protected areas
#

class ProtectedArea(models.Model):
    """
    Part of NetBox (or of a plugin) whose objects are shown only to people who hold a PIN grant from the area's
    owners – whatever their NetBox role is. ``targets`` lists ``app_label`` (the whole app, e.g. ``dcim`` or
    ``netbox_libreoxi``) or ``app_label.model`` (one object type, e.g. ``users.user``).
    """
    key = models.SlugField(max_length=100, unique=True, help_text=_('Plugin areas use the name of the plugin.'))
    name = models.CharField(verbose_name=_('Name'), max_length=100)
    description = models.TextField(verbose_name=_('Description'), blank=True)
    plugin = models.BooleanField(default=False, editable=False, help_text='Registered by a plugin.')
    targets = models.JSONField(default=list, blank=True)
    enabled = models.BooleanField(verbose_name=_('Active'), default=True)
    max_hours = models.PositiveSmallIntegerField(
        verbose_name=_('Longest temporary access (hours)'), default=24,
        validators=[MinValueValidator(1), MaxValueValidator(24 * 30)],
    )
    created = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('protected area')
        verbose_name_plural = _('protected areas')
        ordering = ('name',)

    def __str__(self):
        return self.name


class AreaOwner(models.Model):
    """Decides who gets access to the area (confirming with PIN + 2FA)."""
    area = models.ForeignKey(ProtectedArea, on_delete=models.CASCADE, related_name='owners')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='area_ownerships')
    since = models.DateTimeField(default=timezone.now)

    class Meta:
        verbose_name = _('area owner')
        verbose_name_plural = _('area owners')
        constraints = [models.UniqueConstraint(fields=('area', 'user'), name='userpin_area_owner_unique')]

    def __str__(self):
        return f'{self.user} - {self.area}'


class AreaProfile(models.Model):
    """A named set of rights (``view``, ``add``, ``change``, ``delete`` and the rights a plugin defines)."""
    area = models.ForeignKey(ProtectedArea, on_delete=models.CASCADE, related_name='profiles')
    name = models.CharField(verbose_name=_('Profile'), max_length=100)
    rights = models.JSONField(default=list)
    # Which rows the profile shows, per object type: {"dcim.device": {"name__istartswith": "PRINTER"}}.
    # No entry for a type = every row of it.
    filters = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = _('area profile')
        verbose_name_plural = _('area profiles')
        ordering = ('pk',)
        constraints = [models.UniqueConstraint(fields=('area', 'name'), name='userpin_area_profile_unique')]

    def __str__(self):
        return f'{self.area}: {self.name}'


class AreaGrant(models.Model):
    """Access of one user to one area with a profile; temporary when ``expires`` is set."""
    area = models.ForeignKey(ProtectedArea, on_delete=models.CASCADE, related_name='grants')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='area_grants')
    profile = models.ForeignKey(AreaProfile, on_delete=models.CASCADE, related_name='grants')
    expires = models.DateTimeField(null=True, blank=True)
    granted_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
                                   related_name='+')
    granted_by_name = models.CharField(max_length=150, blank=True)
    created = models.DateTimeField(default=timezone.now)
    revoked = models.DateTimeField(null=True, blank=True)
    revoked_by_name = models.CharField(max_length=150, blank=True)

    class Meta:
        verbose_name = _('area grant')
        verbose_name_plural = _('area grants')
        ordering = ('-created', '-pk')

    def __str__(self):
        return f'{self.user} - {self.area} ({self.profile.name})'

    @property
    def is_active(self):
        return self.revoked is None and (self.expires is None or self.expires > timezone.now())


class AreaRequestStatus(models.TextChoices):
    PENDING = 'pending', _('Waiting')
    GRANTED = 'granted', _('Granted')
    DENIED = 'denied', _('Denied')
    CANCELLED = 'cancelled', _('Cancelled')


class AreaRequest(models.Model):
    """A user asks the owners of an area for access."""
    area = models.ForeignKey(ProtectedArea, on_delete=models.CASCADE, related_name='requests')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='area_requests')
    status = models.CharField(max_length=10, choices=AreaRequestStatus.choices, default=AreaRequestStatus.PENDING,
                              db_index=True)
    note = models.CharField(max_length=200, blank=True, help_text='The reason of the request.')
    scope = models.CharField(max_length=200, blank=True, help_text='What exactly is needed (section, group ...).')
    created = models.DateTimeField(default=timezone.now)
    decided = models.DateTimeField(null=True, blank=True)
    decided_by_name = models.CharField(max_length=150, blank=True)
    grant = models.ForeignKey(AreaGrant, on_delete=models.SET_NULL, null=True, blank=True, related_name='+')

    class Meta:
        verbose_name = _('area access request')
        verbose_name_plural = _('area access requests')
        ordering = ('-created', '-pk')

    def __str__(self):
        return f'{self.user} -> {self.area} ({self.status})'


class PolicyKeeper(models.Model):
    """
    Holds the "deny everything not allowed" switch: can switch it on / off and hand the duty over. Exempt from it, so
    that nobody locks himself out. Needs a PIN and 2FA and cannot get rid of the duty alone.
    """
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='policy_keeper')
    since = models.DateTimeField(default=timezone.now)
    added_by_name = models.CharField(max_length=150, blank=True)

    class Meta:
        verbose_name = _('protection keeper')
        verbose_name_plural = _('protection keepers')
        ordering = ('user__username',)

    def __str__(self):
        return str(self.user)


class AreaFieldMode(models.TextChoices):
    HIDDEN = 'hidden', _('Hidden')
    READ = 'read', _('Read only')
    WRITE = 'write', _('Read and write')


class AreaFieldRule(models.Model):
    """
    What a profile may do with one field of an object type: hidden, read only or read and write; for a custom field
    the values may be limited to those that contain a text ("must include PRINTER"). A rule without a profile hides
    the field from everybody in the area, owners included ("nobody sees it").
    ``field`` is the name of a model field, or ``cf:<name>`` for a custom field.
    """
    area = models.ForeignKey(ProtectedArea, on_delete=models.CASCADE, related_name='field_rules')
    profile = models.ForeignKey(AreaProfile, on_delete=models.CASCADE, null=True, blank=True,
                                related_name='field_rules')
    target = models.CharField(max_length=100, help_text='app_label.model')
    field = models.CharField(max_length=150)
    mode = models.CharField(max_length=10, choices=AreaFieldMode.choices, default=AreaFieldMode.WRITE)
    contains = models.CharField(max_length=200, blank=True)

    class Meta:
        verbose_name = _('field rule')
        verbose_name_plural = _('field rules')
        ordering = ('target', 'field')
        constraints = [models.UniqueConstraint(fields=('area', 'profile', 'target', 'field'),
                                               name='userpin_area_field_rule_unique')]

    def __str__(self):
        return f'{self.target}.{self.field}: {self.mode}'
