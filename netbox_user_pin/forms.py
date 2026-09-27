from django import forms
from django.utils.translation import gettext_lazy as _

from django.contrib.auth import get_user_model
from users.models import Group

from .models import PinDelegate, PinSettings

__all__ = (
    'ChangePinForm',
    'DelegateForm',
    'MailSettingsForm',
    'ResetConfirmForm',
    'TestMailForm',
    'OtpForm',
    'PinOtpForm',
    'RecoveryForm',
    'PinSettingsForm',
    'SetPinForm',
    'UnlockForm',
)


class PinInput(forms.PasswordInput):
    def __init__(self, attrs=None):
        base = {
            'class': 'form-control',
            'inputmode': 'numeric',
            'pattern': '[0-9]*',
            'autocomplete': 'off',
            'autocorrect': 'off',
            'spellcheck': 'false',
        }
        super().__init__(attrs={**base, **(attrs or {})}, render_value=False)


def pin_field(label, autofocus=False):
    return forms.CharField(
        label=label,
        max_length=12,
        strip=True,
        widget=PinInput(attrs={'autofocus': 'autofocus'} if autofocus else None),
    )


def otp_field(label=_('2FA code'), autofocus=False):
    return forms.CharField(
        label=label,
        max_length=32,
        strip=True,
        help_text=_('6 digits from your authenticator app, or a backup code.'),
        widget=forms.TextInput(attrs={
            'class': 'form-control', 'autocomplete': 'one-time-code', 'inputmode': 'numeric',
            'spellcheck': 'false', **({'autofocus': 'autofocus'} if autofocus else {}),
        }),
    )


class UnlockForm(forms.Form):
    pin = pin_field(_('PIN'), autofocus=True)

    def __init__(self, *args, require_otp=False, **kwargs):
        super().__init__(*args, **kwargs)
        if require_otp:
            self.fields['otp'] = otp_field()


class PinOtpForm(forms.Form):
    """PIN + (optionally) 2FA code: step-up confirmation, disabling 2FA, new backup codes."""
    pin = pin_field(_('Your PIN'), autofocus=True)

    def __init__(self, *args, require_otp=True, **kwargs):
        super().__init__(*args, **kwargs)
        if require_otp:
            self.fields['otp'] = otp_field()


class OtpForm(forms.Form):
    otp = forms.CharField(
        label=_('Code from the app'), max_length=6, min_length=6,
        widget=forms.TextInput(attrs={'class': 'form-control', 'autocomplete': 'one-time-code',
                                      'inputmode': 'numeric', 'autofocus': 'autofocus'}),
    )


class RecoveryForm(forms.Form):
    email_code = forms.CharField(
        label=_('Code from the e-mail'), max_length=8, min_length=8,
        widget=forms.TextInput(attrs={'class': 'form-control', 'autocomplete': 'off', 'inputmode': 'numeric',
                                      'autofocus': 'autofocus'}),
    )
    otp = otp_field()
    new_pin = pin_field(_('New PIN'))
    confirm_pin = pin_field(_('Confirm new PIN'))

    def clean(self):
        cleaned = super().clean()
        if cleaned.get('new_pin') and cleaned.get('new_pin') != cleaned.get('confirm_pin'):
            self.add_error('confirm_pin', _('The PINs do not match.'))
        return cleaned


class DelegateForm(forms.Form):
    user = forms.ModelChoiceField(
        queryset=get_user_model().objects.filter(is_active=True, is_superuser=False).order_by('username'),
        required=False, label=_('User'), widget=forms.Select(attrs={'class': 'form-select'}),
    )
    group = forms.ModelChoiceField(
        queryset=Group.objects.order_by('name'), required=False, label=_('or group'),
        widget=forms.Select(attrs={'class': 'form-select'}),
    )
    can_edit_settings = forms.BooleanField(
        required=False, label=_('Can edit settings'), widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
    )

    def clean(self):
        cleaned = super().clean()
        user, group = cleaned.get('user'), cleaned.get('group')
        if bool(user) == bool(group):
            raise forms.ValidationError(_('Select either a user or a group.'))
        if user and PinDelegate.objects.filter(user=user).exists():
            raise forms.ValidationError(_('This user is already a delegate.'))
        if group and PinDelegate.objects.filter(group=group).exists():
            raise forms.ValidationError(_('This group is already a delegate.'))
        return cleaned


class SetPinForm(forms.Form):
    new_pin = pin_field(_('New PIN'), autofocus=True)
    confirm_pin = pin_field(_('Confirm new PIN'))

    def clean(self):
        cleaned = super().clean()
        if cleaned.get('new_pin') and cleaned.get('new_pin') != cleaned.get('confirm_pin'):
            self.add_error('confirm_pin', _('The PINs do not match.'))
        return cleaned


class ChangePinForm(SetPinForm):
    current_pin = pin_field(_('Current PIN'), autofocus=True)

    field_order = ('current_pin', 'new_pin', 'confirm_pin')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['new_pin'].widget.attrs.pop('autofocus', None)


class ResetConfirmForm(forms.Form):
    """Confirmation of an administrator-initiated reset: 2FA + new PIN (PIN reset) or PIN (2FA reset)."""

    def __init__(self, *args, kind='pin', **kwargs):
        super().__init__(*args, **kwargs)
        if kind == 'pin':
            self.fields['otp'] = otp_field(autofocus=True)
            self.fields['new_pin'] = pin_field(_('New PIN'))
            self.fields['confirm_pin'] = pin_field(_('Confirm new PIN'))
        else:
            self.fields['pin'] = pin_field(_('Your PIN'), autofocus=True)

    def clean(self):
        cleaned = super().clean()
        if cleaned.get('new_pin') and cleaned.get('new_pin') != cleaned.get('confirm_pin'):
            self.add_error('confirm_pin', _('The PINs do not match.'))
        return cleaned


class TestMailForm(forms.Form):
    recipient = forms.ModelChoiceField(
        queryset=get_user_model().objects.none(), label=_('Send test e-mail to'),
        widget=forms.Select(attrs={'class': 'form-select'}),
        help_text=_('Users permitted to use a PIN with an e-mail address in an allowed domain.'),
    )

    def __init__(self, *args, eligible=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['recipient'].queryset = get_user_model().objects.filter(
            pk__in=[u.pk for u in (eligible or [])]
        ).order_by('username')


class _StyledModelForm(forms.ModelForm):

    def __init__(self, *args, read_only=False, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            if read_only:
                field.disabled = True
            widget = field.widget
            if isinstance(widget, forms.CheckboxInput):
                widget.attrs.setdefault('class', 'form-check-input')
            elif isinstance(widget, forms.Select):
                widget.attrs.setdefault('class', 'form-select')
            else:
                widget.attrs.setdefault('class', 'form-control')


class MailSettingsForm(_StyledModelForm):
    class Meta:
        model = PinSettings
        fields = ('allowed_email_domains', 'notify_email', 'self_recovery', 'recovery_minutes')
        widgets = {
            'allowed_email_domains': forms.Textarea(attrs={'rows': 4, 'class': 'form-control'}),
        }


class PinSettingsForm(_StyledModelForm):
    class Meta:
        model = PinSettings
        fields = (
            'access_mode', 'pin_length', 'block_weak_pins', 'blocked_pins', 'max_age_days', 'warn_days',
            'unlock_minutes', 'sliding_unlock', 'scope_mode', 'require_2fa_unlock',
            'max_attempts', 'lockout_minutes', 'require_2fa_admin', 'step_up_minutes', 'reset_valid_hours',
        )
        widgets = {
            'blocked_pins': forms.Textarea(attrs={'rows': 3, 'class': 'form-control'}),
        }
