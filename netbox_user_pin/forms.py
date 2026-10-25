from django import forms
from django.utils.translation import gettext_lazy as _

from django.contrib.auth import get_user_model

from .models import PinSettings

__all__ = (
    'AreaForm',
    'AreaTargetForm',
    'KeeperForm',
    'AreaRequestForm',
    'AreaGrantForm',
    'AreaDecideForm',
    'AreaOwnerForm',
    'AreaProfileForm',
    'ApprovalForm',
    'BackupCodesForm',
    'BreakGlassForm',
    'ChangePinForm',
    'AcceptRoleForm',
    'DelegateForm',
    'DepartmentForm',
    'HandOverForm',
    'MemberForm',
    'ReplaceRoleForm',
    'ResignForm',
    'RoleInviteForm',
    'TransferForm',
    'DomainForm',
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


class TwoFactorForm(forms.Form):
    otp = otp_field(autofocus=True)


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


class UserChoiceField(forms.ModelChoiceField):
    """Shows 'username (First Last)' and optionally the e-mail address."""

    def __init__(self, *args, with_email=False, **kwargs):
        self.with_email = with_email
        super().__init__(*args, **kwargs)

    def label_from_instance(self, obj):
        from .service import user_label
        label = user_label(obj)
        return f'{label} – {obj.email}' if self.with_email and obj.email else label


HOURS_CHOICES = ((12, _('12 hours')), (24, _('24 hours')), (36, _('36 hours')), (48, _('48 hours')))


def hours_field():
    return forms.TypedChoiceField(
        choices=HOURS_CHOICES, coerce=int, initial=24, label=_('Invitation valid for'),
        widget=forms.Select(attrs={'class': 'form-select'}),
        help_text=_('The code in the e-mail must be used within this time.'),
    )


def reason_field(required=False):
    return forms.CharField(
        label=_('Reason'), required=required, max_length=500,
        widget=forms.TextInput(attrs={'class': 'form-control'}),
    )


def _users(queryset):
    return queryset.filter(is_active=True, is_superuser=False).order_by('username')


class RoleInviteForm(forms.Form):
    """Invite a user to a role (CORE deputy, head or delegate)."""
    user = UserChoiceField(queryset=get_user_model().objects.none(), label=_('User'), with_email=True,
                           widget=forms.Select(attrs={'class': 'form-select'}))
    hours = hours_field()
    reason = reason_field()

    def __init__(self, *args, users=None, with_can_edit=False, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['user'].queryset = _users(users if users is not None else get_user_model().objects.all())
        if with_can_edit:
            self.fields['can_edit_settings'] = forms.BooleanField(
                required=False, label=_('Can edit settings'),
                widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            )


# kept for compatibility with older imports
DelegateForm = RoleInviteForm


class ReplaceRoleForm(forms.Form):
    replacement = UserChoiceField(queryset=get_user_model().objects.none(), label=_('Replacement'), required=False,
                                  with_email=True, widget=forms.Select(attrs={'class': 'form-select'}),
                                  help_text=_('Needed when the minimum would not be met without it.'))
    hours = hours_field()
    reason = reason_field()

    def __init__(self, *args, users=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['replacement'].queryset = _users(users if users is not None else get_user_model().objects.all())


class HandOverForm(forms.Form):
    user = UserChoiceField(queryset=get_user_model().objects.none(), label=_('Hand over to'), with_email=True,
                           widget=forms.Select(attrs={'class': 'form-select'}))
    until = forms.DateTimeField(
        label=_('Until'), input_formats=['%Y-%m-%dT%H:%M', '%Y-%m-%d %H:%M'],
        widget=forms.DateTimeInput(attrs={'class': 'form-control', 'type': 'datetime-local'}, format='%Y-%m-%dT%H:%M'),
        help_text=_('Then the rights return automatically.'),
    )
    hours = hours_field()
    reason = reason_field(required=True)

    def __init__(self, *args, users=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['user'].queryset = _users(users if users is not None else get_user_model().objects.none())


class DepartmentForm(forms.Form):
    name = forms.CharField(label=_('Name'), max_length=100, widget=forms.TextInput(attrs={'class': 'form-control'}))
    description = forms.CharField(label=_('Description'), max_length=200, required=False,
                                  widget=forms.TextInput(attrs={'class': 'form-control'}))


class MemberForm(forms.Form):
    user = UserChoiceField(queryset=get_user_model().objects.none(), label=_('User'),
                           widget=forms.Select(attrs={'class': 'form-select'}))

    def __init__(self, *args, users=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['user'].queryset = _users(users if users is not None else get_user_model().objects.none())


class TransferForm(forms.Form):
    user = UserChoiceField(queryset=get_user_model().objects.none(), label=_('User'),
                           widget=forms.Select(attrs={'class': 'form-select'}))
    department = forms.ModelChoiceField(queryset=None, label=_('To the department'),
                                        widget=forms.Select(attrs={'class': 'form-select'}))

    def __init__(self, *args, users=None, departments=None, **kwargs):
        super().__init__(*args, **kwargs)
        from .models import Department
        self.fields['user'].queryset = _users(users if users is not None else get_user_model().objects.none())
        self.fields['department'].queryset = departments if departments is not None else Department.objects.all()


class AcceptRoleForm(forms.Form):
    code = forms.CharField(
        label=_('Code from the e-mail'), max_length=8, min_length=8,
        widget=forms.TextInput(attrs={'class': 'form-control', 'autocomplete': 'off', 'inputmode': 'numeric',
                                      'autofocus': 'autofocus'}),
    )
    understand = forms.BooleanField(
        label=_('I understand the responsibility'), widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
    )
    pin = pin_field(_('Your PIN'))
    otp = otp_field()


class ResignForm(forms.Form):
    reason = reason_field(required=True)
    pin = pin_field(_('Your PIN'))
    otp = otp_field()


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


class ApprovalForm(forms.Form):
    """Confirm / reject a four-eyes request with PIN (+ 2FA)."""
    pin = pin_field(_('Your PIN'), autofocus=True)

    def __init__(self, *args, require_otp=True, with_reason=False, **kwargs):
        super().__init__(*args, **kwargs)
        if require_otp:
            self.fields['otp'] = otp_field()
        if with_reason:
            self.fields['reason'] = forms.CharField(
                label=_('Reason'), required=False, max_length=500,
                widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': _('e.g. employee left')}),
            )


class BreakGlassForm(ApprovalForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, with_reason=True, **kwargs)
        self.fields['reason'].required = True


class BackupCodesForm(forms.Form):
    """PIN + (2FA code or e-mailed verification code) to show the backup codes."""
    pin = pin_field(_('Your PIN'), autofocus=True)
    otp = forms.CharField(
        label=_('2FA code'), required=False, max_length=6,
        widget=forms.TextInput(attrs={'class': 'form-control', 'autocomplete': 'one-time-code',
                                      'inputmode': 'numeric'}),
        help_text=_('From your authenticator app – or leave empty and use the e-mail code.'),
    )
    email_code = forms.CharField(
        label=_('Code from the e-mail'), required=False, max_length=8,
        widget=forms.TextInput(attrs={'class': 'form-control', 'autocomplete': 'off', 'inputmode': 'numeric'}),
    )

    def clean(self):
        cleaned = super().clean()
        if not cleaned.get('otp') and not cleaned.get('email_code'):
            raise forms.ValidationError(_('Enter a 2FA code or the code from the e-mail.'))
        return cleaned


class TestMailForm(forms.Form):
    recipient = UserChoiceField(
        with_email=True,
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
    new_smtp_password = forms.CharField(
        label=_('SMTP password'), required=False, strip=False,
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}, render_value=False),
        help_text=_('Stored encrypted and never shown. Leave empty to keep the current password.'),
    )

    class Meta:
        model = PinSettings
        fields = (
            'mail_from_name', 'mail_from_address', 'smtp_server', 'smtp_port', 'smtp_timeout', 'smtp_security',
            'smtp_auto_tls', 'smtp_auth', 'smtp_username', 'notify_email', 'self_recovery', 'recovery_minutes',
        )

    def clean(self):
        cleaned = super().clean()
        if cleaned.get('smtp_server') and not cleaned.get('mail_from_address'):
            self.add_error('mail_from_address', _('A sender address is needed together with the SMTP server.'))
        if cleaned.get('smtp_auth') and not cleaned.get('smtp_username'):
            self.add_error('smtp_username', _('Enter the SMTP user.'))
        if cleaned.get('smtp_auth') and not cleaned.get('new_smtp_password') and not self.instance.smtp_password:
            self.add_error('new_smtp_password', _('Enter the SMTP password.'))
        return cleaned


class DomainForm(forms.Form):
    domain = forms.CharField(label=_('Domain'), max_length=253,
                             widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': '@firma.sk'}))


class PinSettingsForm(_StyledModelForm):
    class Meta:
        model = PinSettings
        fields = (
            'language', 'show_full_names', 'access_mode', 'pin_length', 'block_weak_pins', 'blocked_pins', 'max_age_days', 'warn_days',
            'unlock_minutes', 'sliding_unlock', 'scope_mode', 'require_2fa_unlock',
            'max_attempts', 'lockout_minutes', 'require_2fa_admin', 'require_2fa_settings', 'step_up_minutes', 'reset_valid_hours',
            'four_eyes', 'four_eyes_delegates', 'four_eyes_settings', 'four_eyes_access', 'approval_valid_minutes',
            'break_glass', 'areas_enabled', 'twofa_hours',
        )
        widgets = {
            'blocked_pins': forms.Textarea(attrs={'rows': 3, 'class': 'form-control'}),
        }

    def clean(self):
        cleaned = super().clean()
        if 'four_eyes' not in cleaned:
            return cleaned
        four_eyes = cleaned['four_eyes']
        if four_eyes and not self.instance.four_eyes:
            from . import roles
            from .approvals import eligible_approvers
            deputies = [u for u in eligible_approvers() if not u.is_superuser]
            if len(deputies) < roles.MIN_CORE:
                self.add_error('four_eyes', _('At least two active CORE deputies with PIN and 2FA are needed '
                                              '(User PIN > CORE).'))
        if not four_eyes and self.instance.four_eyes:
            from .models import Department
            if Department.objects.exists():
                self.add_error('four_eyes', _('Four-eyes approval cannot be switched off while a department '
                                              'exists. Dissolve the departments first.'))
        if 'areas_enabled' in cleaned and not cleaned['areas_enabled'] and self.instance.areas_enabled:
            from .models import ProtectedArea
            if ProtectedArea.objects.filter(plugin=False, enabled=True, owners__isnull=False).exists():
                self.add_error('areas_enabled', _('The protection cannot be switched off while areas with owners are '
                                                  'active. Only the owners of an area can deactivate it.'))
        return cleaned


#
# Protected areas
#

def target_choices():
    """Grouped choices of every app and object type that can be protected: ('dcim', [('dcim', 'whole app'), ...])."""
    from django.apps import apps

    from .areas import NEVER

    groups = []
    for config in sorted(apps.get_app_configs(), key=lambda c: c.label):
        if config.label in NEVER:
            continue
        models = [m for m in config.get_models() if not m._meta.auto_created and not m._meta.proxy]
        if not models:
            continue
        items = [(config.label, _('— everything in %(app)s —') % {'app': config.verbose_name})]
        items += [(f'{config.label}.{m._meta.model_name}', str(m._meta.verbose_name).capitalize())
                  for m in sorted(models, key=lambda m: m._meta.verbose_name)]
        groups.append((f'{config.verbose_name} ({config.label})', items))
    return groups


SEARCHABLE = {'class': 'form-select pin-searchable'}


class AreaForm(forms.Form):
    name = forms.CharField(label=_('Name'), max_length=100, widget=forms.TextInput(attrs={'class': 'form-control'}))
    description = forms.CharField(label=_('Description'), max_length=200, required=False,
                                  widget=forms.TextInput(attrs={'class': 'form-control'}))
    target = forms.ChoiceField(
        label=_('Protected object type'), choices=(),
        widget=forms.Select(attrs={'class': 'form-select'}),
        help_text=_('The first object type of the area; more are added on the area page.'),
    )
    max_hours = forms.IntegerField(label=_('Longest temporary access (hours)'), min_value=1, max_value=24 * 30,
                                   initial=24, widget=forms.NumberInput(attrs={'class': 'form-control'}))
    enabled = forms.BooleanField(label=_('Active'), required=False, initial=True,
                                 widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}))
    denied_view = forms.ChoiceField(
        label=_('What is not allowed'), required=False, initial='follow',
        choices=[('follow', _('As the settings say (Protected areas page)')),
                 ('show', _('A: shown, and blocked by the PIN notice (with a request)')),
                 ('hide', _('B: hidden - the user sees only what his group allows'))],
        widget=forms.Select(attrs={'class': 'form-select'}),
        help_text=_('Applies to the menu items and to the tabs of the objects of this area.'))

    def __init__(self, *args, plugin=False, create=False, **kwargs):
        super().__init__(*args, **kwargs)
        self.plugin = plugin
        if create:
            self.fields['target'].choices = [('', _('— choose the object type —'))] + target_choices()
            del self.fields['enabled']
        else:  # the objects of an existing area are added / removed one by one on its page
            del self.fields['target']
            self.fields['denied_view'].required = False
            if plugin:  # the switch of a plugin area belongs to the plugin
                del self.fields['enabled']


class AreaTargetForm(forms.Form):
    target = forms.ChoiceField(label=_('Add an object type'), choices=(),
                               widget=forms.Select(attrs={'class': 'form-select'}))

    def __init__(self, *args, exclude=(), **kwargs):
        super().__init__(*args, **kwargs)
        groups = [(label, [item for item in items if item[0] not in exclude]) for label, items in target_choices()]
        self.fields['target'].choices = [('', _('— choose the object type —'))] + [g for g in groups if g[1]]


class KeeperForm(forms.Form):
    user = UserChoiceField(queryset=get_user_model().objects.none(), label=_('User'), with_email=True,
                           widget=forms.Select(attrs=SEARCHABLE))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['user'].queryset = get_user_model().objects.filter(is_active=True).order_by('username')


class AreaOwnerForm(forms.Form):
    user = UserChoiceField(queryset=get_user_model().objects.none(), label=_('User'), with_email=True,
                           widget=forms.Select(attrs=SEARCHABLE),
                           help_text=_('Department heads and delegates (and CORE deputies). Not the superusers and the protection '
                                       'keepers: the owners decide about them.'))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        from . import roles
        from .models import PolicyKeeper
        self.fields['user'].queryset = roles.manager_users(include_superusers=False).exclude(
            pk__in=PolicyKeeper.objects.values('user_id'))


class AreaProfileForm(forms.Form):
    name = forms.CharField(label=_('Profile'), max_length=100, widget=forms.TextInput(attrs={'class': 'form-control'}))
    rights = forms.MultipleChoiceField(label=_('Rights'), choices=(), widget=forms.CheckboxSelectMultiple,
                                       error_messages={'required': _('Choose at least one right.')})
    filters = forms.CharField(
        label=_('Rows the profile shows'), required=False,
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 3,
                                     'placeholder': 'dcim.device: name__istartswith=PRINTER'}),
        help_text=_('Optional, one line per object type: app.model: lookup=value (several with &). Without a line the '
                    'profile shows every row of the type. E.g. dcim.device: name__istartswith=PRINTER'),
    )

    def __init__(self, *args, area=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.area = area
        from . import areas
        self.fields['rights'].choices = [(r, areas.right_label(area, r)) for r in areas.rights_available(area)] \
            if area else []

    def clean_filters(self):
        from . import areas
        return areas.parse_filters(self.cleaned_data.get('filters'), self.area) if self.area else {}


ACCESS_HOURS = ((1, _('1 hour')), (4, _('4 hours')), (8, _('8 hours')), (24, _('24 hours')), (72, _('3 days')),
                (168, _('7 days')), (720, _('30 days')), (0, _('No time limit')))


class _AccessChoice(forms.Form):
    """What one user may do: the object type, the rights, optionally only some rows, and for how long."""
    target = forms.ChoiceField(label=_('Object type'), required=False,
                               widget=forms.Select(attrs={'class': 'form-select pin-searchable'}))
    rights = forms.MultipleChoiceField(label=_('Rights'), choices=(), widget=forms.CheckboxSelectMultiple,
                                       error_messages={'required': _('Choose at least one right.')})
    rows = forms.CharField(
        label=_('Only the rows where'), required=False,
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'name__istartswith=PRINTER'}),
        help_text=_('Optional: lookup=value (several with &). Empty = every row of the type.'))
    hours = forms.TypedChoiceField(choices=ACCESS_HOURS, coerce=int, initial=0, label=_('For how long'),
                                   widget=forms.Select(attrs={'class': 'form-select'}))

    def __init__(self, *args, area=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.area = area
        if area is None:
            return
        from . import areas
        models = set(areas.area_models(area))
        groups = [(label, [i for i in items if i[0] in models]) for label, items in target_choices()]
        self.fields['target'].choices = [('', _('— everything in this area —'))] + [g for g in groups if g[1]]
        self.fields['rights'].choices = [(r, areas.right_label(area, r)) for r in areas.rights_available(area)]
        self.fields['hours'].choices = [(h, label) for h, label in ACCESS_HOURS if h == 0 or h <= area.max_hours]

    def clean(self):
        data = super().clean()
        rows = (data.get('rows') or '').strip()
        if rows:
            target = data.get('target')
            if not target:
                self.add_error('rows', _('Choose the object type first - the rows belong to it.'))
            else:
                from . import areas
                try:
                    data['filters'] = areas.parse_filters(f'{target}: {rows}', self.area)
                except forms.ValidationError as exc:
                    self.add_error('rows', exc)
        data.setdefault('filters', {})
        return data


class AreaDecideForm(_AccessChoice):
    pass


class AreaGrantForm(_AccessChoice):
    user = UserChoiceField(queryset=get_user_model().objects.none(), label=_('User'), with_email=True,
                           widget=forms.Select(attrs=SEARCHABLE))

    def __init__(self, *args, area=None, **kwargs):
        super().__init__(*args, area=area, **kwargs)
        self.fields['user'].queryset = get_user_model().objects.filter(is_active=True).order_by('username')
        self.order_fields(['user', 'target', 'rights', 'rows', 'hours'])


class AccessRequestForm(forms.Form):
    """From the "no access" page: what the user wants (object type / app, rights) and why."""
    target = forms.CharField(max_length=100)
    rights = forms.MultipleChoiceField(choices=[(r, r) for r in ('view', 'add', 'change', 'delete')], required=False)
    note = forms.CharField(max_length=200, min_length=5)
    scope = forms.CharField(max_length=200, required=False)


class GroupForm(forms.Form):
    """A new group: only a name (and the object type when the area has several); the rights are set inside it."""
    target = forms.ChoiceField(label=_('Object type'), widget=forms.Select(attrs={'class': 'form-select pin-searchable'}))
    name = forms.CharField(label=_('Name of the group'), max_length=100,
                           widget=forms.TextInput(attrs={'class': 'form-control'}))

    def __init__(self, *args, area=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.area = area
        if area is None:
            return
        from . import areas
        models = set(areas.area_models(area))
        groups = [(label, [i for i in items if i[0] in models]) for label, items in target_choices()]
        self.fields['target'].choices = [('', _('— choose the object type —'))] + [g for g in groups if g[1]]


class GroupMemberForm(forms.Form):
    user = UserChoiceField(queryset=get_user_model().objects.none(), label=_('User'), with_email=True,
                           widget=forms.Select(attrs=SEARCHABLE))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['user'].queryset = get_user_model().objects.filter(is_active=True).order_by('username')


class AreaRequestForm(forms.Form):
    note = forms.CharField(label=_('Why do you need the access?'), max_length=200, min_length=5,
                           widget=forms.TextInput(attrs={'class': 'form-control'}))
    scope = forms.CharField(label=_('What exactly (section, group, object …)'), max_length=200, required=False,
                            widget=forms.TextInput(attrs={'class': 'form-control'}))
