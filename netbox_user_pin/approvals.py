"""
Four-eyes approval of administrative changes.

The requester and one other person (CORE, or for a department request also its head / delegates) both confirm with their own PIN (+ 2FA). They can do it
live at the same time (each in their own session, the request page refreshes itself) or one after another until
the request expires. Only then the change is executed. Optionally the master may execute alone ("break-glass")
with a reason; all administrators are informed.
"""
import logging
from datetime import timedelta

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext as _
from utilities.request import get_client_ip

from . import roles, service
from .models import (
    ApprovalAction, ApprovalRequest, ApprovalStatus, ApprovalVote, Department, PinAccess, PinDelegate,
    PinEventAction, PinSettings, RoleKind,
)

__all__ = (
    'EVENT_TYPE',
    'break_glass',
    'cancel',
    'create',
    'eligible_approvers',
    'refresh',
    'required_for',
    'vote',
)

logger = logging.getLogger('netbox_user_pin')

EVENT_TYPE = 'netbox_user_pin_approval'
REQUIRED_CONFIRMATIONS = 2

CATEGORY = {
    ApprovalAction.DELEGATE_ADD: 'four_eyes_delegates',
    ApprovalAction.DELEGATE_REMOVE: 'four_eyes_delegates',
    ApprovalAction.DELEGATE_TOGGLE: 'four_eyes_delegates',
    ApprovalAction.SETTINGS: 'four_eyes_settings',
    ApprovalAction.MAIL_SETTINGS: 'four_eyes_settings',
    ApprovalAction.ACCESS: 'four_eyes_access',
    ApprovalAction.DOMAIN_ADD: 'four_eyes_settings',
    ApprovalAction.DEPARTMENT_DELETE: 'four_eyes_delegates',
}


def required_for(action, settings=None):
    settings = settings or service.get_settings()
    return bool(settings.four_eyes and getattr(settings, CATEGORY[action]))


def eligible_approvers(settings=None, department=None):
    """
    People able to confirm (PIN, and 2FA when required, not suspended): the master and CORE deputies; for a
    department request also the department's head and delegates.
    """
    settings = settings or service.get_settings()
    candidates = roles.core_users()
    if department is not None:
        head = roles.effective_head(department)
        candidates += [head.user] if head else []
        candidates += [r.user for r in roles.department_delegates(department)]
    result = []
    for user in candidates:
        if user in result:
            continue
        user_pin = getattr(user, 'user_pin', None)
        if not user_pin or not user_pin.is_set or user_pin.suspended:
            continue
        if settings.require_2fa_admin and not user_pin.has_2fa:
            continue
        result.append(user)
    return result


def _ip(request):
    try:
        ip = get_client_ip(request) if request is not None else None
    except ValueError:
        return None
    return str(ip) if ip else None


def _notify(req, users, text):
    """NetBox notification (bell) + e-mail for each user."""
    from core.models import ObjectType
    from extras.models import Notification
    for user in users:
        try:
            Notification.objects.update_or_create(
                user=user, object_type=ObjectType.objects.get_for_model(ApprovalRequest), object_id=req.pk,
                defaults={'event_type': EVENT_TYPE, 'read': None, 'object_repr': str(req)[:200]},
            )
        except Exception as exc:  # notifications are a convenience only
            logger.warning('Cannot create NetBox notification for %s: %s', user, exc)
        service.send_user_mail(user, _('Four-eyes request #{pk}').format(pk=req.pk), text)


def refresh(req):
    """Mark an expired request as such. Returns the request."""
    if req.status == ApprovalStatus.PENDING and req.expires <= timezone.now():
        req.status = ApprovalStatus.EXPIRED
        req.finished = timezone.now()
        req.save(update_fields=['status', 'finished'])
    return req


def create(action, payload, summary, requester, approver=None, reason='', request=None, department=None):
    settings = service.get_settings()
    others = [u for u in eligible_approvers(settings, department) if u.pk != requester.pk]
    if approver is not None:
        if approver not in others:
            raise ValidationError(_('{user} cannot confirm this request.').format(user=approver))
        others = [approver]
    if not others:
        raise ValidationError(_('There is no other person with PIN and 2FA who could confirm (CORE, or the head / '
                                'delegates of the department).'))
    req = ApprovalRequest.objects.create(
        action=action, payload=payload, summary=summary[:500], reason=reason[:500], requested_by=requester,
        requested_by_name=requester.username, approver=approver, department=department,
        expires=timezone.now() + timedelta(minutes=settings.approval_valid_minutes),
    )
    service.log_event(PinEventAction.APPROVAL_REQUESTED, actor=requester, request=request,
                      detail=f'#{req.pk} {summary}')
    _notify(req, others, _('{user} asks you to confirm: {summary}\n\nOpen NetBox > User PIN > Approvals (#{pk}) and '
                           'confirm with your PIN and 2FA until {time}.').format(
        user=requester, summary=summary, pk=req.pk,
        time=timezone.localtime(req.expires).strftime('%Y-%m-%d %H:%M')))
    return req


def _verify(user, pin, otp, request):
    result = service.verify_pin(user, pin, request=request, scope='four-eyes')
    if result and service.get_settings().require_2fa_admin:
        result = service.verify_second_factor(user, otp, request=request, scope='four-eyes')
    if not result:
        raise ValidationError(_('PIN or 2FA code is not correct.'), code='verify')


def can_vote(req, user):
    if not req.is_open or req.votes.filter(user=user).exists():
        return False
    if user.pk == (req.requested_by_id or 0):
        return True
    if req.approver_id and req.approver_id != user.pk:
        return False
    return user in eligible_approvers(department=req.department)


def vote(req, user, approve, pin, otp=None, reason=None, request=None):
    refresh(req)
    if not can_vote(req, user):
        raise ValidationError(_('You cannot confirm this request (already confirmed, expired or not permitted).'))
    _verify(user, pin, otp, request)
    with transaction.atomic():
        req = ApprovalRequest.objects.select_for_update().get(pk=req.pk)
        if req.status != ApprovalStatus.PENDING:
            raise ValidationError(_('The request is no longer open.'))
        if reason is not None and user.pk == req.requested_by_id and reason.strip():
            req.reason = reason.strip()[:500]
            req.save(update_fields=['reason'])
        ApprovalVote.objects.create(request=req, user=user, username=user.username, approve=approve,
                                    ip_address=_ip(request))
    if not approve:
        req.status = ApprovalStatus.REJECTED
        req.finished = timezone.now()
        req.save(update_fields=['status', 'finished'])
        service.log_event(PinEventAction.APPROVAL_REJECTED, actor=user, request=request, detail=f'#{req.pk}')
        _notify(req, [u for u in [req.requested_by] if u and u.pk != user.pk],
                _('{user} rejected: {summary}').format(user=user, summary=req.summary))
        return req
    service.log_event(PinEventAction.APPROVAL_CONFIRMED, actor=user, request=request, detail=f'#{req.pk}')
    approvals = set(req.votes.filter(approve=True).values_list('user_id', flat=True))
    if len(approvals) >= REQUIRED_CONFIRMATIONS and req.requested_by_id in approvals:
        _execute(req, request=request)
    return req


def cancel(req, user, request=None):
    if not req.is_open or not (user.pk == req.requested_by_id or user.is_superuser):
        raise ValidationError(_('You cannot cancel this request.'))
    req.status = ApprovalStatus.CANCELLED
    req.finished = timezone.now()
    req.save(update_fields=['status', 'finished'])
    service.log_event(PinEventAction.APPROVAL_CANCELLED, actor=user, request=request, detail=f'#{req.pk}')


def break_glass(req, user, reason, pin, otp=None, request=None):
    refresh(req)
    if not (service.get_settings().break_glass and user.is_superuser and req.is_open):
        raise ValidationError(_('Break-glass is not available.'))
    if not (reason or '').strip():
        raise ValidationError(_('A reason is required.'), code='reason')
    _verify(user, pin, otp, request)
    req.break_glass = True
    req.reason = f'BREAK-GLASS: {reason.strip()}'[:500]
    req.save(update_fields=['break_glass', 'reason'])
    ApprovalVote.objects.get_or_create(request=req, user=user, defaults={
        'username': user.username, 'approve': True, 'ip_address': _ip(request)})
    service.log_event(PinEventAction.BREAK_GLASS, actor=user, request=request,
                      detail=f'#{req.pk} {req.summary} – reason: {reason.strip()}')
    _execute(req, request=request)
    admins = [u for u in eligible_approvers(department=req.department) if u.pk != user.pk]
    _notify(req, admins, _('BREAK-GLASS: {user} executed alone: {summary}\nReason: {reason}').format(
        user=user, summary=req.summary, reason=reason.strip()))
    return req


#
# Execution
#

def _execute(req, request=None):
    actor = req.requested_by
    try:
        result = EXECUTORS[req.action](req.payload, actor, request)
    except Exception as exc:
        logger.exception('Four-eyes request #%s failed', req.pk)
        req.status, req.result = ApprovalStatus.FAILED, str(exc)
    else:
        req.status, req.result = ApprovalStatus.EXECUTED, result or ''
    req.finished = timezone.now()
    req.save(update_fields=['status', 'result', 'finished'])
    approvers = ', '.join(req.votes.filter(approve=True).values_list('username', flat=True))
    service.log_event(PinEventAction.APPROVAL_EXECUTED, actor=actor, request=request,
                      detail=f'#{req.pk} {req.summary} – {req.get_status_display()} – confirmed by {approvers}'
                             f'{" – " + req.result if req.result else ""}')


def _user(pk):
    from django.contrib.auth import get_user_model
    return get_user_model().objects.get(pk=pk) if pk else None


def _delegate_add(payload, actor, request):
    """Invite to a role (CORE deputy, head, temporary head or department delegate)."""
    from django.utils.dateparse import parse_datetime
    if not payload.get('user_id'):
        raise ValidationError('Delegating to a group is no longer supported; invite the members one by one.')
    user = _user(payload['user_id'])
    department = Department.objects.get(pk=payload['department_id']) if payload.get('department_id') else None
    replaces = PinDelegate.objects.filter(pk=payload.get('replaces_id')).first() if payload.get('replaces_id') else None
    kind = payload.get('role') or RoleKind.CORE
    until = parse_datetime(payload['temporary_until']) if payload.get('temporary_until') else None
    if until is not None:
        role = roles.hand_over(department, user, until, actor, hours=payload.get('hours', 24),
                               reason=payload.get('reason', ''), request=request)
    elif replaces is not None:
        role = roles.remove_role(replaces, actor, replacement=user, hours=payload.get('hours', 24),
                                 reason=payload.get('reason', ''), request=request)
    else:
        role = roles.invite(user, kind, actor, department=department, hours=payload.get('hours', 24),
                            can_edit=payload.get('can_edit', False), reason=payload.get('reason', ''),
                            request=request)
    return f'{role}: invitation sent'


def _delegate_remove(payload, actor, request):
    role = PinDelegate.objects.get(pk=payload['delegate_id'])
    text = str(role)
    roles.remove_role(role, actor, reason=payload.get('reason', ''), request=request)
    return f'{text} ended'


def _delegate_toggle(payload, actor, request):
    delegate = PinDelegate.objects.get(pk=payload['delegate_id'])
    delegate.can_edit_settings = bool(payload['can_edit'])
    delegate.save()
    roles._sync()
    service.log_event(PinEventAction.DELEGATE_CHANGED, user=delegate.user, actor=actor, request=request,
                      detail=f'{delegate}: can edit settings = {delegate.can_edit_settings}')
    return str(delegate)


def _department_delete(payload, actor, request):
    department = Department.objects.get(pk=payload['department_id'])
    name = department.name
    roles.delete_department(department, actor, request=request)
    return f'{name} dissolved'


def _settings(payload, actor, request):
    settings = PinSettings.load()
    changes = []
    for name, value in payload['changes'].items():
        old = getattr(settings, name)
        setattr(settings, name, value)
        changes.append(f'{name}: changed' if 'password' in name else f'{name}: {old!r} -> {value!r}')
    four_eyes_before = PinSettings.load().four_eyes
    settings.full_clean()
    settings.save()
    service.log_event(PinEventAction.SETTINGS_CHANGED, actor=actor, request=request, detail='\n'.join(changes))
    if settings.four_eyes != four_eyes_before:
        roles.four_eyes_changed(settings.four_eyes, actor, request=request)
    return '; '.join(changes)


def _access(payload, actor, request):
    user = _user(payload['user_id'])
    service.set_access(user, payload['access'], actor=actor, request=request)
    return f'{user}: {PinAccess(payload["access"]).label}'


def _domain_add(payload, actor, request):
    domain = service.add_domain(payload['domain'], actor, request=request)
    return f'{domain} added (must be verified before use)'


EXECUTORS = {
    ApprovalAction.DOMAIN_ADD: _domain_add,
    ApprovalAction.DELEGATE_ADD: _delegate_add,
    ApprovalAction.DELEGATE_REMOVE: _delegate_remove,
    ApprovalAction.DELEGATE_TOGGLE: _delegate_toggle,
    ApprovalAction.SETTINGS: _settings,
    ApprovalAction.MAIL_SETTINGS: _settings,
    ApprovalAction.ACCESS: _access,
    ApprovalAction.DEPARTMENT_DELETE: _department_delete,
}
