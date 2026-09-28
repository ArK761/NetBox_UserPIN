from django.db import migrations


def convert_delegates(apps, schema_editor):
    """
    Existing delegates become CORE deputies. Delegates with PIN + 2FA stay active; the others (and the members of
    delegated groups) wait for an invitation (sent from the CORE page) and must accept it.
    """
    PinDelegate = apps.get_model('netbox_user_pin', 'PinDelegate')
    UserPin = apps.get_model('netbox_user_pin', 'UserPin')

    def ready(user):
        user_pin = UserPin.objects.filter(user=user).first()
        return bool(user_pin and user_pin.pin_hash and user_pin.totp_secret)

    for delegate in PinDelegate.objects.all():
        if delegate.user_id is None:
            for user in delegate.group.users.filter(is_active=True, is_superuser=False):
                if not PinDelegate.objects.filter(user=user).exists():
                    PinDelegate.objects.create(
                        user=user, role='core', status='pending', can_edit_settings=delegate.can_edit_settings,
                        created_by=delegate.created_by, invited_by=delegate.created_by,
                    )
            delegate.delete()
            continue
        delegate.role = 'core'
        if ready(delegate.user):
            delegate.status = 'active'
            delegate.accepted = delegate.created
        else:
            delegate.status = 'pending'
            delegate.invited_by = delegate.created_by
        delegate.save()


class Migration(migrations.Migration):
    """Data only – kept separate so that PostgreSQL commits the row changes before the table is altered."""

    dependencies = [
        ("netbox_user_pin", "0010_departments_roles"),
    ]

    operations = [
        migrations.RunPython(convert_delegates, migrations.RunPython.noop),
    ]
