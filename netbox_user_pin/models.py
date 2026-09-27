from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

__all__ = (
    'PinEvent',
    'PinAccess',
    'PinAccessMode',
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
    access_mode = models.CharField(
        verbose_name=_('Who may use a PIN'),
        max_length=20,
        choices=PinAccessMode.choices,
        default=PinAccessMode.ALL,
        help_text=_('Per-user Allow / Deny is set on the Users page.'),
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
        default=0,
        help_text=_('Force a PIN change after this many days. 0 = never.'),
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
    ACCESS_CHANGED = 'access_changed', _('PIN access changed by administrator')
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
