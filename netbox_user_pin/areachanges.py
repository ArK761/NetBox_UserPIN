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


def detail_of(change, who):
    """The audit text: the first line says who did what (as the subject of the mail), then one bullet per field."""
    from .guests import change_headline, change_rows
    return '\n'.join([change_headline(who, change), *change_rows(change)])[:3000]


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
    service.log_event(PinEventAction.AREA_OBJECT_CHANGED, user=change.user, scope=area.key,
                      detail=detail_of(change, _who(change.user)))
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
            from .guests import change_block, change_headline
            if len(items) == 1:
                subject = change_headline(_who(first.user), first)
            else:
                subject = _('Changes in the protected areas (%(n)d)') % {'n': len(items)}
            blocks = []
            for area, change in items:
                head = _('%(user)s – area "%(area)s"') % {'user': 'USER PIN : ' + _who(change.user), 'area': area.name}
                blocks.append('\n'.join([head, *change_block(change)]))
            body = '\n\n'.join(blocks)
        if service.send_user_mail(person, subject, body):
            sent.append(person.username)
    return sent


def rules_for(change):
    """The e-mail rules of the groups the author of the change is a member of (for the type of the changed object)."""
    from .models import AreaGrant, AreaMailRule
    app_label, model = _target(change)
    if not app_label or not change.user_id:
        return []
    now = timezone.now()
    profiles = {g.profile_id for g in AreaGrant.objects.filter(user_id=change.user_id, revoked__isnull=True,
                                                               profile__target=f'{app_label}.{model}')
                if g.expires is None or g.expires > now}
    if not profiles:
        return []
    return [r for r in AreaMailRule.objects.filter(profile_id__in=profiles).select_related('profile')
            if r.mode == 'each' and r.wants(change.action)]


def send_rule_mails(change_pk):
    """Job of netbox-rq: the e-mails of the group rules for one change (the other e-mails are not touched by this)."""
    from core.models import ObjectChange
    from .guests import change_block, change_headline
    change = ObjectChange.objects.select_related('changed_object_type', 'user').filter(pk=change_pk).first()
    if change is None:
        return
    settings = service.get_settings()
    if not service.email_configured(settings):
        return
    guest = PinGuest.objects.filter(user_id=change.user_id).first()
    who = (guest.person_number or guest.label) if guest else _who(change.user)
    for rule in rules_for(change):
        addresses = [a for a in rule.address_list if a.rsplit('@', 1)[-1].lower() in service.allowed_domains()]
        if not addresses:
            continue
        with translation.override(settings.language or 'en'):
            subject = change_headline(who, change)
            body = '\n'.join([f'USER PIN : {who}', _('%(user)s – area "%(area)s"') % {'user': rule.profile.name,
                                                                                    'area': rule.area.name},
                              '', *change_block(change)])
        try:
            service._deliver(settings, addresses, subject, body)
            service.log_event(PinEventAction.MAIL_SENT, detail=f'{rule.profile.name} / {rule.name}: {subject} -> '
                                                              f'{", ".join(addresses)}')
        except Exception as exc:  # noqa: BLE001 - a mail that cannot be sent must not break anything
            logger.warning('Cannot send the e-mail of the rule %s: %s', rule, exc)
            service.log_event(PinEventAction.MAIL_FAILED, detail=f'{rule.profile.name} / {rule.name}: {exc}')


def report_rule_mails(force=False):
    """The rules with a summary: every ``every`` minutes one e-mail with the changes that piled up (the job runs every
    5 minutes). The first run of a rule only sets the mark (nothing from the past is mailed)."""
    from core.models import ObjectChange
    from .guests import change_block, change_headline
    from .models import AreaGrant, AreaMailRule
    settings = service.get_settings()
    now = timezone.now()
    for rule in AreaMailRule.objects.filter(mode='summary', active=True).select_related('profile', 'area'):
        if rule.last_sent is None:
            rule.last_sent = now
            rule.save(update_fields=['last_sent'])
            continue
        if not force and now - rule.last_sent < timedelta(minutes=rule.every):
            continue
        since = rule.last_sent
        rule.last_sent = now
        rule.save(update_fields=['last_sent'])
        members = {g.user_id for g in AreaGrant.objects.filter(profile=rule.profile, revoked__isnull=True)
                   if g.expires is None or g.expires > now}
        app_label, _dot, model = rule.profile.target.partition('.')
        changes = [c for c in ObjectChange.objects.filter(
            user_id__in=members, time__gt=since, time__lte=now, changed_object_type__app_label=app_label,
            changed_object_type__model=model).select_related('changed_object_type', 'user').order_by('time')[:MAX_PER_REPORT]
            if rule.wants(c.action)]
        addresses = [a for a in rule.address_list if a.rsplit('@', 1)[-1].lower() in service.allowed_domains()]
        if not changes or not addresses or not service.email_configured(settings):
            continue
        blocks = []
        with translation.override(settings.language or 'en'):
            for change in changes:
                guest = PinGuest.objects.filter(user_id=change.user_id).first()
                who = (guest.person_number or guest.label) if guest else _who(change.user)
                blocks.append('\n'.join([change_headline(who, change), *change_block(change)]))
            subject = _('%(rule)s : changes (%(n)d)') % {'rule': rule.profile.name, 'n': len(changes)}
            body = '\n'.join([_('%(user)s – area "%(area)s"') % {'user': rule.profile.name, 'area': rule.area.name}, '',
                              '\n\n'.join(blocks)])
        try:
            service._deliver(settings, addresses, subject, body)
            service.log_event(PinEventAction.MAIL_SENT, detail=f'{rule.profile.name} / {rule.name}: {len(changes)} '
                                                              f'change(s) -> {", ".join(addresses)}')
        except Exception as exc:  # noqa: BLE001
            logger.warning('Cannot send the summary of the rule %s: %s', rule, exc)
            service.log_event(PinEventAction.MAIL_FAILED, detail=f'{rule.profile.name} / {rule.name}: {exc}')


def _queue_rule_mails(change):
    try:
        if not rules_for(change):
            return
    except Exception:  # noqa: BLE001
        logger.exception('Cannot look up the e-mail rules of a group')
        return
    pk = change.pk

    def enqueue():
        try:
            from django_rq import get_queue
            get_queue('default').enqueue(send_rule_mails, pk)
        except Exception:  # noqa: BLE001 - no queue: the audit log has the change
            logger.exception('Cannot queue the e-mail of a group rule')
    transaction.on_commit(enqueue)


def _changed(sender, instance, created, **kwargs):
    """post_save of a change record: the audit record at once; the e-mail now ('every change') or in the summary."""
    if not created or not instance.user_id:
        return
    _queue_rule_mails(instance)  # separate from everything below: the extra addresses of the group rules
    try:
        if PinGuest.objects.filter(user_id=instance.user_id).exists():
            # a person with a PIN only: the e-mail is the guests' own (PIN-only page); the audit log gets it here
            guest = PinGuest.objects.filter(user_id=instance.user_id).first()
            who = (guest.person_number or guest.label) if guest else _who(instance.user)
            service.log_event(PinEventAction.AREA_OBJECT_CHANGED, user=instance.user, scope='guest',
                              detail=detail_of(instance, who))
            return
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
