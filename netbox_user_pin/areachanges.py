"""
What the users working in the protected areas changed: the audit log records it and the administrators are e-mailed.

A change counts when it is made by an ordinary NetBox user (not a protection keeper, not a PIN-only person: those have
their own e-mails) to an object whose type a protected area covers. The keepers and the manager of the section that
covers the type get the e-mail, either at every change or as a summary every N minutes (never both).
"""
import logging
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone, translation
from django.utils.translation import gettext as _

from . import areas, service
from .models import PinEventAction, PinGuest

logger = logging.getLogger('netbox_user_pin')

MAIL_EVERY = (5, 15, 30, 60, 120, 240, 1440)
MAX_PER_REPORT = 500


def _target(change):
    kind = change.changed_object_type
    return (kind.app_label, kind.model) if kind is not None else (None, None)


def area_of(change):
    """The protected area of the changed object, or None (also None for a change nobody here watches)."""
    app_label, model = _target(change)
    if not app_label:
        return None
    return areas.area_for(app_label, model, package=app_label)


def watched_user(user):
    """An ordinary account: no keeper, no PIN-only person (those are watched elsewhere)."""
    if user is None or not user.is_active:
        return False
    if areas.is_keeper(user) or PinGuest.objects.filter(user=user).exists():
        return False
    return True


def recipients(area, change):
    """The keepers and the manager of the section that covers the type (only those with an address)."""
    app_label, model = _target(change)
    people = list(areas.keepers())
    for manager in areas.managers_for(area, f'{app_label}.{model}'):
        if manager not in people:
            people.append(manager)
    return [p for p in people if p.is_active and p.pk != getattr(change.user, 'pk', None)]


def _lines(change):
    from .guests import _change_lines
    return _change_lines(change)


def _who(user):
    return service.user_label(user)


def watched(change):
    """``area`` when this change is to be recorded, else None."""
    if change.user_id is None or not watched_user(change.user):
        return None
    return area_of(change)


def record(change):
    """The audit record of one change; returns the area (None: not watched)."""
    area = watched(change)
    if area is None:
        return None
    action = {'create': _('added'), 'update': _('changed'), 'delete': _('deleted')}.get(str(change.action), '')
    service.log_event(PinEventAction.AREA_OBJECT_CHANGED, user=change.user, scope=area.key,
                      detail=f'{change.changed_object_type.app_label}.{change.changed_object_type.model} '
                             f'"{change.object_repr}" {action}'[:300])
    return area


def _send(changes_by_area, settings):
    """E-mail the changes; every recipient gets what concerns him in one message."""
    per_person = {}
    for area, change in changes_by_area:
        for person in recipients(area, change):
            per_person.setdefault(person.pk, (person, []))[1].append((area, change))
    sent = []
    for person, items in per_person.values():
        with translation.override(settings.language or 'en'):
            first_area, first = items[0]
            if len(items) == 1:
                subject = _('%(user)s made a change in "%(area)s"') % {'user': _who(first.user), 'area': first_area.name}
            else:
                subject = _('Changes in the protected areas (%(n)d)') % {'n': len(items)}
            blocks = []
            for area, change in items:
                head = _('%(user)s – area "%(area)s"') % {'user': _who(change.user), 'area': area.name}
                blocks.append('\n'.join([head, *_lines(change)]))
            body = '\n\n'.join(blocks)
        if service.send_user_mail(person, subject, body):
            sent.append(person.username)
    return sent


def _changed(sender, instance, created, **kwargs):
    """post_save of a change record: the audit record at once; the e-mail now ('every change') or in the summary."""
    if not created or not instance.user_id:
        return
    try:
        area = record(instance)
    except Exception:  # noqa: BLE001 - a record that cannot be written must not break the user's save
        logger.exception('Cannot record the change in a protected area')
        return
    if area is None:
        return
    settings = service.get_settings()
    if not settings.area_mail_changes or settings.area_mail_mode != 'each':
        return
    pk = instance.pk

    def enqueue():
        try:
            from django_rq import get_queue
            get_queue('default').enqueue(send_change_mail, pk)
        except Exception:  # noqa: BLE001 - no queue: nothing is lost, the audit log has it
            logger.exception('Cannot queue the e-mail of a change in a protected area')
    transaction.on_commit(enqueue)


def send_change_mail(change_pk):
    """Job of netbox-rq: the e-mail of one change."""
    from core.models import ObjectChange
    change = ObjectChange.objects.select_related('changed_object_type', 'user').filter(pk=change_pk).first()
    if change is None:
        return
    area = watched(change)
    if area is not None:
        _send([(area, change)], service.get_settings())


def report(force=False):
    """
    The summary of the changes in the protected areas, every ``area_mail_every`` minutes (the job runs every 5
    minutes). The first run only sets the mark (nothing from the past is mailed).
    """
    from core.models import ObjectChange
    settings = service.get_settings()
    now = timezone.now()
    mark = settings.area_changes_mailed
    if mark is None or not settings.area_mail_changes or settings.area_mail_mode == 'each':
        settings.area_changes_mailed = now  # nothing piles up while it is switched off or sent at once
        settings.save(update_fields=['area_changes_mailed'])
        return 0
    if not force and now - mark < timedelta(minutes=settings.area_mail_every):
        return 0
    keepers = [k.pk for k in areas.keepers()]
    changes = (ObjectChange.objects.filter(time__gt=mark, time__lte=now, user__isnull=False, user__is_active=True)
               .exclude(user__in=keepers).exclude(user__pin_guest__isnull=False)
               .select_related('changed_object_type', 'user').order_by('time')[:MAX_PER_REPORT * 4])
    wanted = []
    for change in changes:
        area = area_of(change)
        if area is not None:
            wanted.append((area, change))
        if len(wanted) >= MAX_PER_REPORT:
            break
    sent = _send(wanted, settings) if wanted else []
    if wanted:
        service.log_event(PinEventAction.MAIL_SENT if sent else PinEventAction.MAIL_FAILED,
                          detail=f'{len(wanted)} change(s) in the protected areas reported to '
                                 f'{", ".join(sent) or "nobody (no verified e-mail)"}')
    settings.area_changes_mailed = now
    settings.save(update_fields=['area_changes_mailed'])
    return len(wanted)


def _grant_saved(sender, instance, created, **kwargs):
    """Removed from a group: the user is told (being added is e-mailed where the access is granted)."""
    user = instance.user
    if created or user is None or not user.is_active or PinGuest.objects.filter(user=user).exists():
        return
    if instance.revoked is None or timezone.now() - instance.revoked >= timedelta(minutes=1):
        return
    who = getattr(instance, 'revoked_by_name', '') or instance.granted_by_name
    pk = instance.pk

    def send():
        from .models import AreaGrant
        grant = AreaGrant.objects.select_related('user', 'profile', 'area').filter(pk=pk).first()
        settings = service.get_settings()
        if grant is None or not settings.area_mail_users:
            return
        try:
            with translation.override(settings.language or 'en'):
                what = _('You were removed from the group %(group)s.') % {
                    'group': f'{grant.profile.name} ({grant.area.name})'}
                admin = get_user_model().objects.filter(username=who).first()
                name = (admin.get_full_name() or admin.username) if admin else (who or '-')
                subject = _('Your NetBox access was changed')
                body = _('Hello %(name)s,\n\n%(admin)s changed your access to NetBox:\n\n%(what)s') % {
                    'name': grant.user.get_full_name() or grant.user.username, 'admin': name, 'what': what}
            service.send_user_mail(grant.user, subject, body)
        except Exception:  # noqa: BLE001 - a mail that cannot be sent must not break the change of the access
            logger.exception('Cannot e-mail the change of an access')
    transaction.on_commit(send)


def install():
    from django.db.models.signals import post_save

    from core.models import ObjectChange
    post_save.connect(_changed, sender=ObjectChange, dispatch_uid='userpin_area_changes')
    from .models import AreaGrant
    post_save.connect(_grant_saved, sender=AreaGrant, dispatch_uid='userpin_area_grant_mail')
