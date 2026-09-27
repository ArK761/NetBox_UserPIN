"""
Delegation of PIN administration by the master (superuser).

The PinDelegate rows are the source of truth; they are synchronised into NetBox ObjectPermissions so that the
menu and ``user.has_perm()`` work natively:

- "User PIN: delegates"          view + change UserPin, view PinEvent, view PinSettings
- "User PIN: settings editors"   change PinSettings (delegates with "can edit settings")

Only superusers have ``add_pinsettings`` which guards the Delegates page (nobody else is ever granted it).
"""
from core.models import ObjectType
from django.db import transaction
from users.models import ObjectPermission

from .models import PinDelegate, PinEvent, PinSettings, UserPin

__all__ = (
    'DELEGATES_PERMISSION',
    'EDITORS_PERMISSION',
    'sync_permissions',
)

DELEGATES_PERMISSION = 'User PIN: delegates'
EDITORS_PERMISSION = 'User PIN: settings editors'


def _apply(name, actions, models, users, groups):
    permission, _created = ObjectPermission.objects.get_or_create(
        name=name, defaults={'actions': actions},
    )
    permission.description = 'Managed by the User PIN plugin (User PIN > Delegates). Do not edit here.'
    permission.actions = actions
    permission.enabled = True
    permission.save()
    permission.object_types.set([ObjectType.objects.get_for_model(m) for m in models])
    permission.users.set(users)
    permission.groups.set(groups)


@transaction.atomic
def sync_permissions():
    delegates = list(PinDelegate.objects.all())
    users = [d.user for d in delegates if d.user_id]
    groups = [d.group for d in delegates if d.group_id]
    editor_users = [d.user for d in delegates if d.user_id and d.can_edit_settings]
    editor_groups = [d.group for d in delegates if d.group_id and d.can_edit_settings]

    # ObjectPermission actions apply to all of its object types, hence three permissions.
    _apply(DELEGATES_PERMISSION, ['view', 'change'], [UserPin], users, groups)
    _apply(f'{DELEGATES_PERMISSION} (read)', ['view'], [PinEvent, PinSettings], users, groups)
    _apply(EDITORS_PERMISSION, ['change'], [PinSettings], editor_users, editor_groups)
