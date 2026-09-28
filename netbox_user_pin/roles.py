"""
Roles in the PIN administration.

    CORE        the master (superusers) + CORE deputies        see and manage everything
    Department  head + delegates                             manage the PINs of the department's members

Every role starts as an invitation (link + e-mailed code, valid 12-48 h). It becomes effective only after the
invited user accepted it with the code, their PIN and 2FA. Roles never silently disappear below the minimum:
a resignation or removal waits for a replacement ("resigning").
"""
import logging
import secrets
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Q
from django.urls import reverse
from django.utils import timezone, translation
from django.utils.translation import gettext as _

from . import crypto, service
from .models import (
    EFFECTIVE_ROLE_STATUSES, OPEN_ROLE_STATUSES, Department, DepartmentMember, PinAccess, PinDelegate, PinEventAction,
    RoleKind, RoleStatus, TransferRequest, TransferStatus, UserPin,
)

__all__ = (
    'INVITE_HOURS',
    'MAX_TEMPORARY_DAYS',
    'MIN_CORE',
    'MIN_DEPARTMENT_DELEGATES',
    'accept',
    'can_manage',
    'core_users',
    'create_department',
    'decide_transfer',
    'decline',
    'delete_department',
    'department_of',
    'effective_head',
    'end_role',
    'four_eyes_changed',
    'hand_over',
    'invite',
    'is_core',
    'is_manager',
    'managed_departments',
    'move_member',
    'process_due',
    'remove_member',
    'remove_role',
    'request_transfer',
    'resend',
    'resign',
    'visible_users',
)

logger = logging.getLogger('netbox_user_pin')

INVITE_HOURS = (12, 24, 36, 48)
MIN_CORE = 2
MIN_DEPARTMENT_DELEGATES = 2
MAX_TEMPORARY_DAYS = 30
EVENT_TYPE = 'netbox_user_pin_role'


def _username(user):
    return getattr(user, 'username', '') or ''


def _label(user):
    return service.user_label(user) if user else '—'


#
# Queries
#

def _effective(qs):
    return qs.filter(status__in=EFFECTIVE_ROLE_STATUSES, user__is_active=True)


def core_roles():
    return _effective(PinDelegate.objects.filter(role=RoleKind.CORE))


def is_core(user):
    """Master (superuser) or an effective CORE deputy."""
    if not getattr(user, 'is_authenticated', False) or not user.is_active:
        return False
    return user.is_superuser or core_roles().filter(user=user).exists()


def core_users():
    """Superusers and effective CORE deputies (active accounts)."""
    user_model = get_user_model()
    return list(user_model.objects.filter(
        Q(is_superuser=True) | Q(pin_roles__in=core_roles()), is_active=True).distinct().order_by('username'))


def department_of(user):
    membership = DepartmentMember.objects.filter(user=user).select_related('department').first()
    return membership.department if membership else None


def effective_head(department):
    role = _effective(PinDelegate.objects.filter(role=RoleKind.HEAD, department=department)).select_related(
        'user').order_by('-temporary_until').first()
    return role


def department_delegates(department, include_resigning=True):
    statuses = EFFECTIVE_ROLE_STATUSES if include_resigning else (RoleStatus.ACTIVE,)
    return PinDelegate.objects.filter(role=RoleKind.DELEGATE, department=department, status__in=statuses,
                                      user__is_active=True).select_related('user')


def managed_departments(user):
    """Departments where ``user`` is the effective head or a delegate."""
    if not getattr(user, 'is_authenticated', False):
        return Department.objects.none()
    ids = _effective(PinDelegate.objects.filter(user=user, role__in=(RoleKind.HEAD, RoleKind.DELEGATE)))
    return Department.objects.filter(pk__in=ids.values('department_id'))


def headed_departments(user):
    ids = _effective(PinDelegate.objects.filter(user=user, role=RoleKind.HEAD))
    return Department.objects.filter(pk__in=ids.values('department_id'))


def is_head(user, department):
    return headed_departments(user).filter(pk=department.pk).exists()


def is_manager(user):
    """CORE, or head / delegate of a department."""
    return is_core(user) or managed_departments(user).exists()


def visible_users(user):
    """Users whose PIN state ``user`` may see."""
    user_model = get_user_model()
    if is_core(user):
        return user_model.objects.all()
    return user_model.objects.filter(pin_membership__department__in=managed_departments(user))


def role_in(user, department):
    """'head', 'delegate' or '' – effective role of ``user`` in ``department``."""
    kinds = set(_effective(PinDelegate.objects.filter(user=user, department=department)).values_list('role',
                                                                                                    flat=True))
    return RoleKind.HEAD if RoleKind.HEAD in kinds else (RoleKind.DELEGATE if kinds else '')


def can_manage(actor, target):
    """
    Nobody manages themselves here (own PIN only under My PIN). The master manages everybody else; CORE deputies
    everybody except the master and other CORE deputies; a department head the members of the department; a
    department delegate the members without a role.
    """
    if target.pk == actor.pk or not actor.is_active:
        return False
    if actor.is_superuser:
        return True
    if target.is_superuser or is_core(target):
        return False
    if is_core(actor):
        return True
    department = department_of(target)
    if department is None:
        return False
    actor_role = role_in(actor, department)
    if actor_role == RoleKind.HEAD:
        return role_in(target, department) != RoleKind.HEAD
    if actor_role == RoleKind.DELEGATE:
        return not role_in(target, department)
    return False


def ready_for_role(user):
    """Reasons why ``user`` cannot hold an effective role yet (PIN / 2FA missing)."""
    reasons = []
    if not service.has_pin(user):
        reasons.append('no_pin')
    if not service.has_2fa(user):
        reasons.append('no_2fa')
    return reasons


#
# Notifications
#

def _bell(users, obj, text=''):
    from core.models import ObjectType
    from extras.models import Notification
    for user in users:
        try:
            Notification.objects.update_or_create(
                user=user, object_type=ObjectType.objects.get_for_model(obj), object_id=obj.pk,
                defaults={'event_type': EVENT_TYPE, 'read': None, 'object_repr': (text or str(obj))[:200]},
            )
        except Exception as exc:  # notifications are a convenience only
            logger.warning('Cannot create NetBox notification for %s: %s', user, exc)


def _mail(users, subject, body, request=None):
    sent = set()
    for user in users:
        if user is None or user.pk in sent or not user.is_active:
            continue
        sent.add(user.pk)
        service.send_user_mail(user, subject, body, request=request)


def department_members(department):
    return [m.user for m in DepartmentMember.objects.filter(department=department).select_related('user')]


def _mail_department(department, subject, body, request=None, extra=()):
    """Everybody in the department (with an e-mail in an allowed domain) plus ``extra``."""
    _mail([*department_members(department), *extra], subject, body, request=request)


def _superiors(role):
    """Who is informed about a resignation: the head for delegates, CORE for heads, the master for CORE."""
    if role.role == RoleKind.DELEGATE:
        head = effective_head(role.department)
        if head and head.user_id != role.user_id:
            return [head.user]
        return core_users()
    if role.role == RoleKind.HEAD:
        return core_users()
    return list(get_user_model().objects.filter(is_superuser=True, is_active=True))


def _fmt(value):
    return timezone.localtime(value).strftime('%d.%m.%Y %H:%M') if value else ''


def role_title(role):
    if role.role == RoleKind.CORE:
        return _('CORE deputy')
    if role.role == RoleKind.HEAD:
        if role.is_temporary:
            return _('temporary head of the department {department}').format(department=role.department)
        return _('head of the department {department}').format(department=role.department)
    return _('delegate of the department {department}').format(department=role.department)


#
# Minimum rules
#

def _active_peers(role):
    """Other ACTIVE (not resigning) holders of the same kind of role."""
    qs = PinDelegate.objects.filter(role=role.role, status=RoleStatus.ACTIVE, user__is_active=True).exclude(pk=role.pk)
    if role.role != RoleKind.CORE:
        qs = qs.filter(department=role.department)
    return qs


def below_minimum_without(role):
    """True when ending ``role`` now would leave fewer holders than required."""
    if role.status not in EFFECTIVE_ROLE_STATUSES:
        return False
    if role.role == RoleKind.CORE:
        return service.get_settings().four_eyes and _active_peers(role).count() < MIN_CORE
    if role.role == RoleKind.HEAD:
        return not role.is_temporary
    return _active_peers(role).count() < MIN_DEPARTMENT_DELEGATES


def _settle_resigning(request=None):
    """End resigning roles that are no longer needed (a replacement arrived)."""
    for role in PinDelegate.objects.filter(status=RoleStatus.RESIGNING).select_related('user', 'department'):
        if role.role == RoleKind.HEAD:
            others = _effective(PinDelegate.objects.filter(role=RoleKind.HEAD, department=role.department,
                                                           temporary_until=None)).exclude(pk=role.pk)
            if not others.exists():
                continue
        elif below_minimum_without(role):
            continue
        end_role(role, None, _('replacement accepted'), request=request)


#
# Invitations
#

def _check_can_hold(user, kind, department, replaces=None, temporary=False):
    if not user.is_active:
        raise ValidationError(_('{user} is not active.').format(user=user))
    if user.is_superuser:
        raise ValidationError(_('{user} is a superuser (master) and needs no role.').format(user=user))
    user_pin = UserPin.objects.filter(user=user).first()
    if user_pin and user_pin.access == PinAccess.DENIED:
        raise ValidationError(_('{user} is denied to use a PIN.').format(user=user))
    if service.email_status(user) != 'ok' or not service.email_configured():
        raise ValidationError(_('{user} has no e-mail address in a verified allowed domain (or no mail server is '
                                'configured), so the invitation cannot be delivered.').format(user=user))
    open_roles = PinDelegate.objects.filter(user=user, status__in=OPEN_ROLE_STATUSES)
    if replaces is not None:
        open_roles = open_roles.exclude(pk=replaces.pk)
    if kind == RoleKind.CORE:
        if open_roles.exists():
            raise ValidationError(_('{user} already has a role (or an open invitation).').format(user=user))
        return
    if open_roles.filter(role=RoleKind.CORE).exists():
        raise ValidationError(_('{user} is a CORE deputy and cannot hold a department role.').format(user=user))
    current = department_of(user)
    if current is not None and current.pk != department.pk:
        raise ValidationError(_('{user} belongs to the department {department}. Move the user first.').format(
            user=user, department=current))
    same = open_roles.filter(role=kind, department=department)
    if temporary:
        same = same.exclude(temporary_until=None)
    elif kind == RoleKind.HEAD:
        same = same.filter(temporary_until=None)
    if same.exists():
        raise ValidationError(_('{user} already has this role (or an open invitation).').format(user=user))
    if kind == RoleKind.HEAD and not temporary:
        heads = PinDelegate.objects.filter(role=RoleKind.HEAD, department=department, temporary_until=None,
                                           status__in=OPEN_ROLE_STATUSES)
        if replaces is not None:
            heads = heads.exclude(pk=replaces.pk)
        if heads.exclude(status=RoleStatus.RESIGNING).exists():
            raise ValidationError(_('The department {department} already has a head. Replace the head instead.')
                                  .format(department=department))


def _invitation_link(role, request=None):
    path = reverse('plugins:netbox_user_pin:invitation', kwargs={'pk': role.pk})
    return request.build_absolute_uri(path) if request is not None else path


def _invitation_body(role, code, link, actor):
    lines = [
        _('{actor} has chosen you as {role} for the PIN administration in NetBox.').format(
            actor=_label(actor) if actor else role.invited_by, role=role_title(role)),
        '',
        _('What it means:'),
    ]
    department = role.department
    if role.role == RoleKind.CORE:
        lines += [
            '- ' + _('Together with the administrator you see and manage the PINs of all users and departments.'),
            '- ' + _('You confirm sensitive changes together with a second person (four eyes): roles, settings, '
                     'departments.'),
            '- ' + _('You create departments and appoint their heads.'),
        ]
    elif role.role == RoleKind.HEAD:
        lines += [
            '- ' + _('You manage the PINs of the people in the department {department}: allow / deny, resets (the '
                     'user always confirms them), suspend.').format(department=department),
            '- ' + _('You invite the delegates of the department and can hand over your rights temporarily.'),
            '- ' + _('You approve moves of people into and out of the department.'),
        ]
    else:
        lines += [
            '- ' + _('Together with the head or another delegate you confirm changes in the department {department} '
                     '(four eyes).').format(department=department),
            '- ' + _('You handle PIN and 2FA resets of the people in the department {department} (the user always '
                     'confirms them).').format(department=department),
            '- ' + _('When the head is not available, two delegates together can hand the head\'s rights over '
                     'temporarily.'),
        ]
    lines += [
        '- ' + _('The PIN protects sensitive parts of NetBox and of other plugins that require it (e.g. projects and '
                 'documentation) – you share responsibility for this protection.'),
        '',
        _('Your responsibility:'),
        '- ' + _('Never give your PIN, 2FA or backup codes to anybody; keep the phone with 2FA with you.'),
        '- ' + _('React to approval requests in time; confirm only what you understand and what is justified.'),
        '- ' + _('Every action you take is recorded in the audit log.'),
        '- ' + _('You can resign under User PIN > My roles (it takes effect after a hand-over).'),
    ]
    if role.is_temporary:
        original = role.substitute_for.user if role.substitute_for_id else None
        lines += ['', _('This is a temporary hand-over: the rights end on {until} and then return to {head}.').format(
            until=_fmt(role.temporary_until), head=_label(original)) if original else
            _('This is a temporary hand-over: the rights end on {until}.').format(until=_fmt(role.temporary_until))]
    if role.reason:
        lines += ['', _('Reason: {reason}').format(reason=role.reason)]
    lines += [
        '',
        _('Accept: {link}').format(link=link),
        _('Code: {code} – valid until {time} ({hours} h)').format(code=code, time=_fmt(role.invite_expires),
                                                                 hours=role.invite_hours),
        '',
        _('To accept, log in to NetBox, set a PIN and 2FA if you do not have them yet, enter the code and confirm with '
          'your PIN + 2FA.'),
        _('If you know nothing about this, do not accept and contact your administrator.'),
    ]
    return '\n'.join(lines)


def _send_invitation(role, actor=None, request=None):
    code = f'{secrets.randbelow(10 ** 8):08d}'
    now = timezone.now()
    role.invite_code = crypto.keyed_digest(code, f'role:{role.pk}:{role.user_id}')
    role.invite_expires = now + timedelta(hours=role.invite_hours)
    role.invite_sent = now
    role.invite_attempts = 0
    role.save(update_fields=['invite_code', 'invite_expires', 'invite_sent', 'invite_attempts'])
    where = role.department.name if role.department_id else 'CORE'
    subject = _('PIN administration role – {where}').format(where=where)
    if not service.send_user_mail(role.user, subject, _invitation_body(role, code, _invitation_link(role, request),
                                                                         actor), request=request):
        raise ValidationError(_('The invitation e-mail to {user} could not be sent – see the audit log.').format(
            user=role.user))
    _bell([role.user], role, _('Invitation: {role}').format(role=role_title(role)))


def _hours(hours):
    try:
        hours = int(hours)
    except (TypeError, ValueError):
        hours = 24
    if hours not in INVITE_HOURS:
        raise ValidationError(_('The invitation can be valid for 12, 24, 36 or 48 hours.'))
    return hours


def invite(user, kind, actor, department=None, hours=24, can_edit=False, temporary_until=None, replaces=None,
           reason='', request=None):
    """Create a role in state 'waiting for acceptance' and e-mail the invitation. Returns the role."""
    hours = _hours(hours)
    if kind != RoleKind.CORE and department is None:
        raise ValidationError(_('Select a department.'))
    temporary = temporary_until is not None
    if temporary:
        if kind != RoleKind.HEAD:
            raise ValueError('only a head can be temporary')
        if temporary_until <= timezone.now() + timedelta(hours=1):
            raise ValidationError(_('The end of the hand-over must be in the future.'))
        if PinDelegate.objects.filter(department=department, role=RoleKind.HEAD, status__in=OPEN_ROLE_STATUSES
                                      ).exclude(temporary_until=None).exists():
            raise ValidationError(_('There already is a temporary hand-over in this department.'))
    _check_can_hold(user, kind, department, replaces=replaces, temporary=temporary)
    substitute_for = effective_head(department) if temporary else None
    if substitute_for is not None and substitute_for.is_temporary:
        substitute_for = None
    with transaction.atomic():
        role = PinDelegate.objects.create(
            user=user, role=kind, department=department if kind != RoleKind.CORE else None,
            status=RoleStatus.PENDING, can_edit_settings=bool(can_edit) and kind == RoleKind.CORE,
            temporary_until=temporary_until, substitute_for=substitute_for, replaces=replaces,
            reason=(reason or '')[:500], invited_by=_username(actor), invite_hours=hours, created_by=_username(actor),
        )
        _send_invitation(role, actor, request)
    service.log_event(PinEventAction.ROLE_INVITED, user=user, actor=actor, request=request,
                      detail=f'{role}, valid {hours} h' + (f', until {_fmt(temporary_until)}' if temporary else '')
                             + (f', replaces {replaces.user}' if replaces else '') + (f' – {reason}' if reason else ''))
    return role


def resend(role, actor, hours=24, request=None):
    """New code and validity for an invitation that is waiting or expired."""
    if role.status not in (RoleStatus.PENDING, RoleStatus.EXPIRED):
        raise ValidationError(_('This invitation cannot be sent again.'))
    role.invite_hours = _hours(hours)
    role.status = RoleStatus.PENDING
    role.save(update_fields=['invite_hours', 'status'])
    _check_can_hold(role.user, role.role, role.department, replaces=role, temporary=role.is_temporary)
    _send_invitation(role, actor, request)
    service.log_event(PinEventAction.ROLE_INVITED, user=role.user, actor=actor, request=request,
                      detail=f'{role}, sent again, valid {role.invite_hours} h')


def accept(role, user, code, pin, otp, request=None):
    """The invited user accepts with the e-mailed code, the PIN and 2FA."""
    if role.user_id != user.pk:
        raise ValidationError(_('This invitation is not for you.'))
    if role.status != RoleStatus.PENDING or not role.invite_pending:
        raise ValidationError(_('The invitation is no longer valid. Ask for a new one.'))
    if ready_for_role(user):
        raise ValidationError(_('Set your PIN and 2FA first.'))
    if role.invite_attempts >= 5 or not crypto.check_keyed_digest(
            (code or '').strip(), f'role:{role.pk}:{role.user_id}', role.invite_code):
        PinDelegate.objects.filter(pk=role.pk).update(invite_attempts=role.invite_attempts + 1)
        raise ValidationError(_('The code is wrong or expired.'), code='code')
    result = service.verify_pin(user, pin, request=request, scope='role')
    if result:
        result = service.verify_second_factor(user, otp, request=request, scope='role')
    if not result:
        raise ValidationError(_('PIN or 2FA code is not correct.'), code='verify')
    if role.role != RoleKind.CORE:
        current = department_of(user)
        if current is not None and current.pk != role.department_id:
            raise ValidationError(_('You belong to another department. Ask to be moved first.'))
    with transaction.atomic():
        role = PinDelegate.objects.select_for_update().get(pk=role.pk)
        if role.status != RoleStatus.PENDING:
            raise ValidationError(_('The invitation is no longer valid. Ask for a new one.'))
        if role.role != RoleKind.CORE:
            DepartmentMember.objects.get_or_create(user=user, defaults={'department': role.department,
                                                                        'added_by': role.invited_by})
        role.status = RoleStatus.ACTIVE
        role.accepted = timezone.now()
        role.invite_code = ''
        role.save(update_fields=['status', 'accepted', 'invite_code'])
        original = role.substitute_for
        if original is not None and original.status in EFFECTIVE_ROLE_STATUSES:
            original.status = RoleStatus.ON_LEAVE
            original.save(update_fields=['status'])
            service.log_event(PinEventAction.ROLE_ON_LEAVE, user=original.user, actor=user, request=request,
                              detail=f'{original} until {_fmt(role.temporary_until)} -> {user}')
        replaced = role.replaces
    service.log_event(PinEventAction.ROLE_ACCEPTED, user=user, actor=user, request=request, detail=str(role))
    if replaced is not None and replaced.status in OPEN_ROLE_STATUSES:
        end_role(replaced, user, _('replaced by {user}').format(user=user), request=request)
    _announce_accepted(role, replaced, request)
    _settle_resigning(request)
    _sync()
    return role


def _announce_accepted(role, replaced, request):
    inviter = get_user_model().objects.filter(username=role.invited_by).first()
    _mail([inviter], _('Role accepted: {role}').format(role=role_title(role)),
          _('{user} accepted the role {role}.').format(user=_label(role.user), role=role_title(role)), request)
    if role.role != RoleKind.HEAD:
        return
    department = role.department
    if role.is_temporary:
        body = _('{user} is now the head (superadmin) of the department {department}. The rights end on {until} and '
                 'then return to {head}.').format(
            user=_label(role.user), department=department, until=_fmt(role.temporary_until),
            head=_label(role.substitute_for.user) if role.substitute_for_id else 'CORE')
    elif replaced is not None:
        body = _('The head {old} was removed. The rights were moved to {user}, who is now the head (superadmin) of the '
                 'department {department}.').format(old=_label(replaced.user), user=_label(role.user),
                                                   department=department)
    else:
        body = _('{user} is now the head (superadmin) of the department {department}.').format(
            user=_label(role.user), department=department)
    _mail_department(department, _('New head of the department {department}').format(department=department), body,
                     request, extra=core_users())


def decline(role, user, request=None):
    if role.user_id != user.pk or role.status != RoleStatus.PENDING:
        raise ValidationError(_('This invitation is not open.'))
    PinDelegate.objects.filter(pk=role.pk).update(status=RoleStatus.DECLINED, invite_code='', ended=timezone.now())
    service.log_event(PinEventAction.ROLE_DECLINED, user=user, actor=user, request=request, detail=str(role))
    inviter = get_user_model().objects.filter(username=role.invited_by).first()
    _mail([inviter], _('Invitation declined: {role}').format(role=role_title(role)),
          _('{user} declined the role {role}.').format(user=_label(user), role=role_title(role)), request)


#
# Ending roles
#

def end_role(role, actor, reason='', request=None, notify=True):
    """End a role now (no minimum check – callers check). A temporary head's end returns the rights."""
    role.refresh_from_db()
    if role.status not in OPEN_ROLE_STATUSES:
        return
    was_effective = role.status in EFFECTIVE_ROLE_STATUSES
    PinDelegate.objects.filter(pk=role.pk).update(status=RoleStatus.ENDED, ended=timezone.now(),
                                                   end_reason=(reason or '')[:500], invite_code='')
    service.log_event(PinEventAction.ROLE_ENDED, user=role.user, actor=actor, request=request,
                      detail=f'{role}' + (f' – {reason}' if reason else ''))
    if notify and was_effective:
        _mail([role.user], _('Your role ended: {role}').format(role=role_title(role)),
              _('Your role {role} ended.').format(role=role_title(role)) + (
                  '\n' + _('Reason: {reason}').format(reason=reason) if reason else ''), request)
    if role.role == RoleKind.HEAD and role.is_temporary and was_effective:
        _return_rights(role, request)
    _sync()


def _return_rights(temporary, request):
    department = temporary.department
    original = PinDelegate.objects.filter(pk=temporary.substitute_for_id).first()
    if original is not None and original.status == RoleStatus.ON_LEAVE:
        PinDelegate.objects.filter(pk=original.pk).update(status=RoleStatus.ACTIVE)
        service.log_event(PinEventAction.ROLE_RETURNED, user=original.user, request=request,
                          detail=f'{department}: from {temporary.user}')
        body = _('The temporary hand-over to {user} ended. The head of the department {department} is again {head}.'
                 ).format(user=_label(temporary.user), department=department, head=_label(original.user))
    else:
        body = _('The temporary hand-over to {user} ended. The department {department} is managed by CORE until a '
                 'new head is appointed.').format(user=_label(temporary.user), department=department)
    _mail_department(department, _('Rights returned – department {department}').format(department=department),
                     body, request, extra=[temporary.user])


def resign(role, user, reason, pin, otp, request=None):
    """The holder gives the role up. Below the minimum it stays in force ('resigning') until replaced."""
    if role.user_id != user.pk or role.status not in (RoleStatus.ACTIVE, RoleStatus.PENDING, RoleStatus.ON_LEAVE):
        raise ValidationError(_('This role cannot be given up.'))
    if not (reason or '').strip():
        raise ValidationError(_('A reason is required.'), code='reason')
    result = service.verify_pin(user, pin, request=request, scope='role')
    if result:
        result = service.verify_second_factor(user, otp, request=request, scope='role')
    if not result:
        raise ValidationError(_('PIN or 2FA code is not correct.'), code='verify')
    reason = reason.strip()
    superiors = _superiors(role)
    if role.status == RoleStatus.PENDING:
        decline(role, user, request)
        return 'ended'
    if below_minimum_without(role):
        PinDelegate.objects.filter(pk=role.pk).update(status=RoleStatus.RESIGNING, end_reason=reason[:500])
        service.log_event(PinEventAction.ROLE_RESIGNING, user=user, actor=user, request=request,
                          detail=f'{role} – {reason}')
        text = _('{user} wants to give up the role {role}: {reason}\nThe role stays in force until a replacement '
                 'accepts – invite one.').format(user=_label(user), role=role_title(role), reason=reason)
        role.refresh_from_db()
        _bell(superiors, role, _('Resignation: {user}').format(user=user))
        _mail(superiors, _('Resignation: {role}').format(role=role_title(role)), text, request)
        return 'resigning'
    end_role(role, user, reason, request=request, notify=False)
    _bell(superiors, role, _('Resigned: {user}').format(user=user))
    _mail(superiors, _('Resigned: {role}').format(role=role_title(role)),
          _('{user} gave up the role {role}: {reason}').format(user=_label(user), role=role_title(role),
                                                               reason=reason), request)
    return 'ended'


def remove_role(role, actor, replacement=None, hours=24, reason='', request=None):
    """
    End ``role`` (e.g. the person left). Below the minimum only together with a replacement: the old holder stays
    until the new one accepts – except a regular head, who ends at once (CORE manages the department meanwhile).
    """
    if role.status not in OPEN_ROLE_STATUSES:
        raise ValidationError(_('This role has already ended.'))
    if replacement is not None:
        new = invite(replacement, role.role, actor, department=role.department, hours=hours,
                     can_edit=role.can_edit_settings, replaces=role, reason=reason, request=request)
        if role.role == RoleKind.HEAD and not role.is_temporary:
            end_role(role, actor, _('replaced by {user}').format(user=replacement), request=request)
        else:
            PinDelegate.objects.filter(pk=role.pk, status=RoleStatus.ACTIVE).update(status=RoleStatus.RESIGNING)
        return new
    if below_minimum_without(role):
        raise ValidationError(_('A replacement is needed – without it the minimum (head, {n} delegates, {c} CORE '
                                'deputies) would not be met.').format(n=MIN_DEPARTMENT_DELEGATES, c=MIN_CORE))
    end_role(role, actor, reason or _('removed by {user}').format(user=actor), request=request)
    return None


def hand_over(department, user, until, actor, hours=24, reason='', request=None):
    """Temporary hand-over of the head's rights to ``user`` (a member of the department) until ``until``."""
    head = effective_head(department)
    if head is not None and head.user_id == user.pk:
        raise ValidationError(_('{user} already is the head.').format(user=user))
    if department_of(user) is None or department_of(user).pk != department.pk:
        raise ValidationError(_('{user} is not a member of the department {department}.').format(
            user=user, department=department))
    if not (is_core(actor) or is_head(actor, department)):
        limit = timezone.now() + timedelta(days=MAX_TEMPORARY_DAYS)
        if until > limit:
            raise ValidationError(_('Delegates can hand the rights over for at most {days} days.').format(
                days=MAX_TEMPORARY_DAYS))
    return invite(user, RoleKind.HEAD, actor, department=department, hours=hours, temporary_until=until,
                  reason=reason, request=request)


#
# Departments and members
#

def create_department(name, actor, description='', request=None):
    name = (name or '').strip()
    if not name:
        raise ValidationError(_('Enter a name.'))
    if Department.objects.filter(name__iexact=name).exists():
        raise ValidationError(_('A department with this name already exists.'))
    department = Department.objects.create(name=name, description=(description or '').strip(),
                                           created_by=_username(actor))
    service.log_event(PinEventAction.DEPARTMENT_CREATED, actor=actor, request=request, detail=name)
    return department


def delete_department(department, actor, request=None):
    members = department_members(department)
    for role in PinDelegate.objects.filter(department=department, status__in=OPEN_ROLE_STATUSES):
        end_role(role, actor, _('department dissolved'), request=request, notify=False)
    name = department.name
    _mail(members, _('Department {department} dissolved').format(department=name),
          _('The department {department} was dissolved by {user}. Your own PIN is not affected.').format(
              department=name, user=_label(actor)), request)
    TransferRequest.objects.filter(Q(from_department=department) | Q(to_department=department)).delete()
    department.delete()
    service.log_event(PinEventAction.DEPARTMENT_DELETED, actor=actor, request=request, detail=name)
    _sync()


def _leave_department(user, department, actor, request):
    """End the department roles of ``user`` before leaving; refuses when it would break the minimum."""
    roles = PinDelegate.objects.filter(user=user, department=department, status__in=OPEN_ROLE_STATUSES)
    for role in roles:
        if role.role == RoleKind.HEAD and role.status in (*EFFECTIVE_ROLE_STATUSES, RoleStatus.ON_LEAVE) \
                and not role.is_temporary:
            raise ValidationError(_('{user} is the head of {department}. Appoint a new head first.').format(
                user=user, department=department))
        if below_minimum_without(role):
            raise ValidationError(_('{user} is needed as a delegate of {department} (minimum {n}). Invite a '
                                    'replacement first.').format(user=user, department=department,
                                                                 n=MIN_DEPARTMENT_DELEGATES))
    for role in roles:
        end_role(role, actor, _('left the department'), request=request)


def move_member(user, department, actor, request=None, transfer=None):
    """Put ``user`` into ``department`` (None = no department)."""
    old = department_of(user)
    if old is not None and department is not None and old.pk == department.pk:
        return
    if old is not None:
        _leave_department(user, old, actor, request)
        DepartmentMember.objects.filter(user=user).delete()
        service.log_event(PinEventAction.MEMBER_REMOVED, user=user, actor=actor, request=request, detail=old.name)
    if department is not None:
        DepartmentMember.objects.create(user=user, department=department, added_by=_username(actor))
        service.log_event(PinEventAction.MEMBER_ADDED, user=user, actor=actor, request=request,
                          detail=department.name + (f' (from {old.name})' if old else ''))
    subject = _('Department change: {user}').format(user=user.username)
    if old is not None and department is not None:
        body = _('{user} moved from the department {old} to the department {new}.').format(
            user=_label(user), old=old, new=department)
    elif department is not None:
        body = _('{user} joined the department {new}.').format(user=_label(user), new=department)
    else:
        body = _('{user} left the department {old}.').format(user=_label(user), old=old)
    recipients = [user]
    for dep in (old, department):
        if dep is not None:
            recipients += department_members(dep)
            head = effective_head(dep)
            if head:
                recipients.append(head.user)
    _mail(recipients, subject, body, request)
    _sync()


def add_member(user, department, actor, request=None):
    move_member(user, department, actor, request=request)


def remove_member(user, actor, request=None):
    move_member(user, None, actor, request=request)


def request_transfer(user, to_department, actor, request=None):
    """A head asks to move ``user`` into or out of their department; the head of the other one approves."""
    from_department = department_of(user)
    if from_department is not None and from_department.pk == to_department.pk:
        raise ValidationError(_('{user} is already in {department}.').format(user=user, department=to_department))
    actor_heads_from = from_department is not None and is_head(actor, from_department)
    actor_heads_to = is_head(actor, to_department)
    if not (actor_heads_from or actor_heads_to or is_core(actor)):
        raise ValidationError(_('Only a head of one of the departments can ask for this move.'))
    if TransferRequest.objects.filter(user=user, status=TransferStatus.PENDING, expires__gt=timezone.now()).exists():
        raise ValidationError(_('A move of {user} is already waiting.').format(user=user))
    approving = from_department if actor_heads_to and not actor_heads_from else to_department
    if approving is not None and not effective_head(approving):
        approving = None  # CORE decides
    settings = service.get_settings()
    transfer = TransferRequest.objects.create(
        user=user, from_department=from_department, to_department=to_department, requested_by=actor,
        requested_by_name=_username(actor), approving_department=approving,
        expires=timezone.now() + timedelta(minutes=settings.approval_valid_minutes),
    )
    service.log_event(PinEventAction.TRANSFER_REQUESTED, user=user, actor=actor, request=request,
                      detail=f'{from_department or "-"} -> {to_department}')
    approvers = [effective_head(approving).user] if approving else core_users()
    approvers = [u for u in approvers if u.pk != actor.pk] or core_users()
    _bell(approvers, transfer, _('Move {user} to {department}').format(user=user, department=to_department))
    _mail(approvers, _('Move between departments: {user}').format(user=user.username),
          _('{actor} asks to move {user} from {old} to {new}. Approve or reject it in NetBox > User PIN > '
            'Departments until {time}.').format(actor=_label(actor), user=_label(user),
                                              old=from_department or '—', new=to_department,
                                              time=_fmt(transfer.expires)), request)
    return transfer


def can_decide_transfer(transfer, user):
    if not transfer.is_open:
        return False
    if is_core(user):
        return True
    if user.pk == transfer.requested_by_id:
        return False
    return transfer.approving_department_id is not None and is_head(user, transfer.approving_department)


def decide_transfer(transfer, actor, approve, request=None):
    if not can_decide_transfer(transfer, actor):
        raise ValidationError(_('You cannot decide this move.'))
    if approve:
        move_member(transfer.user, transfer.to_department, actor, request=request, transfer=transfer)
    TransferRequest.objects.filter(pk=transfer.pk).update(
        status=TransferStatus.APPROVED if approve else TransferStatus.REJECTED, decided=timezone.now(),
        decided_by=_username(actor))
    service.log_event(PinEventAction.TRANSFER_APPROVED if approve else PinEventAction.TRANSFER_REJECTED,
                      user=transfer.user, actor=actor, request=request,
                      detail=f'{transfer.from_department or "-"} -> {transfer.to_department}')
    if not approve:
        _mail([transfer.requested_by], _('Move rejected: {user}').format(user=transfer.user.username),
              _('{actor} rejected the move of {user} to {department}.').format(
                  actor=_label(actor), user=_label(transfer.user), department=transfer.to_department), request)


#
# Four-eyes switch
#

def four_eyes_changed(enabled, actor, request=None):
    """Inform the CORE deputies; switching four-eyes off ends the CORE delegation."""
    deputies = [r.user for r in PinDelegate.objects.filter(role=RoleKind.CORE, status__in=OPEN_ROLE_STATUSES)
                .select_related('user')]
    if enabled:
        _mail(deputies, _('Four-eyes approval switched on'),
              _('{user} switched four-eyes approval on. Sensitive changes now need two people.').format(
                  user=_label(actor)), request)
        return
    for role in PinDelegate.objects.filter(role=RoleKind.CORE, status__in=OPEN_ROLE_STATUSES):
        end_role(role, actor, _('four-eyes approval switched off'), request=request, notify=False)
    _mail(deputies, _('Four-eyes approval switched off'),
          _('Four-eyes approval was switched off, the delegation ended. From now on you manage only your own PIN.'),
          request)


#
# Housekeeping (hourly system job; also run lazily by the plugin's pages)
#

def process_due(request=None):
    """Expire invitations and moves, send reminders, return rights after temporary hand-overs."""
    now = timezone.now()
    with translation.override(service.get_settings().language or 'en'):
        for role in PinDelegate.objects.filter(status=RoleStatus.PENDING, invite_expires__lte=now):
            PinDelegate.objects.filter(pk=role.pk).update(status=RoleStatus.EXPIRED, invite_code='')
            service.log_event(PinEventAction.ROLE_EXPIRED, user=role.user, request=request, detail=str(role))
            inviter = get_user_model().objects.filter(username=role.invited_by).first()
            _mail([inviter], _('Invitation expired: {role}').format(role=role_title(role)),
                  _('{user} did not accept the role {role} in time. You can send the invitation again.').format(
                      user=_label(role.user), role=role_title(role)), request)
        for role in PinDelegate.objects.filter(status=RoleStatus.ACTIVE, temporary_until__lte=now):
            end_role(role, None, _('temporary hand-over ended'), request=request)
        soon = now + timedelta(days=1)
        for role in PinDelegate.objects.filter(status=RoleStatus.ACTIVE, temporary_until__lte=soon,
                                               reminder_sent=None).select_related('substitute_for__user'):
            PinDelegate.objects.filter(pk=role.pk).update(reminder_sent=now)
            original = role.substitute_for.user if role.substitute_for_id else None
            _mail([role.user, original], _('Hand-over ends tomorrow – {department}').format(
                department=role.department),
                _('The temporary hand-over of the department {department} to {user} ends on {until}.').format(
                    department=role.department, user=_label(role.user), until=_fmt(role.temporary_until)), request)
        TransferRequest.objects.filter(status=TransferStatus.PENDING, expires__lte=now).update(
            status=TransferStatus.EXPIRED)


def due_work_exists():
    now = timezone.now()
    return (PinDelegate.objects.filter(Q(status=RoleStatus.PENDING, invite_expires__lte=now)
                                       | Q(status=RoleStatus.ACTIVE, temporary_until__lte=now + timedelta(days=1),
                                           reminder_sent=None)
                                       | Q(status=RoleStatus.ACTIVE, temporary_until__lte=now)).exists()
            or TransferRequest.objects.filter(status=TransferStatus.PENDING, expires__lte=now).exists())


def _sync():
    from . import delegation
    delegation.sync_permissions()
