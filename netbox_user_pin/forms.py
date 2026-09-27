from django import forms
from django.utils.translation import gettext_lazy as _

from .models import PinSettings

__all__ = (
    'ChangePinForm',
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


class UnlockForm(forms.Form):
    pin = pin_field(_('PIN'), autofocus=True)


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


class PinSettingsForm(forms.ModelForm):
    class Meta:
        model = PinSettings
        fields = (
            'access_mode', 'pin_length', 'block_weak_pins', 'blocked_pins', 'max_age_days',
            'unlock_minutes', 'sliding_unlock', 'scope_mode',
            'max_attempts', 'lockout_minutes',
        )
        widgets = {
            'blocked_pins': forms.Textarea(attrs={'rows': 3, 'class': 'form-control'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            widget = field.widget
            if isinstance(widget, forms.CheckboxInput):
                widget.attrs.setdefault('class', 'form-check-input')
            elif isinstance(widget, forms.Select):
                widget.attrs.setdefault('class', 'form-select')
            else:
                widget.attrs.setdefault('class', 'form-control')
