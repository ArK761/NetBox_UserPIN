"""
Roles (see roles.py) are the source of truth; effective roles are synchronised into NetBox ObjectPermissions so
that the menu and ``user.has_perm()`` work natively:

- "User PIN: delegates"                 CORE deputies: view + change UserPin
- "User PIN: delegates (read)"          CORE deputies: view PinEvent, view PinSettings
- "User PIN: settings editors"          CORE deputies with "can edit settings": change PinSettings
- "User PIN: departments"               department heads and delegates: view + change UserPin
- "User PIN: departments (read)"        department heads and delegates: view PinEvent

What a department role may see or do is limited to its department by the plugin's views (roles.visible_users,
roles.can_manage). Only superusers have ``add_pinsettings`` which guards the CORE page (nobody else is granted it).
"""
from core.models import ObjectType
from django.db import transaction
from users.models import ObjectPermission

from .models import EFFECTIVE_ROLE_STATUSES, PinDelegate, PinEvent, PinSettings, RoleKind, UserPin

__all__ = (
    'DELEGATES_PERMISSION',
    'DEPARTMENTS_PERMISSION',
    'EDITORS_PERMISSION',
    'sync_permissions',
)

DELEGATES_PERMISSION = 'User PIN: delegates'
EDITORS_PERMISSION = 'User PIN: settings editors'
DEPARTMENTS_PERMISSION = 'User PIN: departments'


def _apply(name, actions, models, users):
    permission, _created = ObjectPermission.objects.get_or_create(
        name=name, defaults={'actions': actions},
    )
    permission.description = 'Managed by the User PIN plugin (User PIN > CORE / Departments). Do not edit here.'
    permission.actions = actions
    permission.enabled = True
    permission.save()
    permission.object_types.set([ObjectType.objects.get_for_model(m) for m in models])
    permission.users.set(users)
    permission.groups.set([])


@transaction.atomic
def sync_permissions():
    roles = list(PinDelegate.objects.filter(status__in=EFFECTIVE_ROLE_STATUSES, user__is_active=True)
                 .select_related('user'))
    core = {r.user for r in roles if r.role == RoleKind.CORE}
    editors = {r.user for r in roles if r.role == RoleKind.CORE and r.can_edit_settings}
    managers = {r.user for r in roles if r.role in (RoleKind.HEAD, RoleKind.DELEGATE)}

    # ObjectPermission actions apply to all of its object types, hence several permissions.
    _apply(DELEGATES_PERMISSION, ['view', 'change'], [UserPin], core)
    _apply(f'{DELEGATES_PERMISSION} (read)', ['view'], [PinEvent, PinSettings], core)
    _apply(EDITORS_PERMISSION, ['change'], [PinSettings], editors)
    _apply(DEPARTMENTS_PERMISSION, ['view', 'change'], [UserPin], managers)
    _apply(f'{DEPARTMENTS_PERMISSION} (read)', ['view'], [PinEvent], managers)
