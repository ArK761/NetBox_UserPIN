import re

from django.db import migrations, models


def account_ids(apps, schema_editor):
    """Every PIN-only account gets a stable ID as its username (PinUser0001 ...); the old name becomes the alias."""
    PinGuest = apps.get_model('netbox_user_pin', 'PinGuest')
    User = apps.get_model(*__import__('django.conf', fromlist=['settings']).settings.AUTH_USER_MODEL.split('.'))
    taken = [int(m.group(1)) for m in (re.fullmatch(r'PinUser(\d+)', u) for u in
                                       User.objects.values_list('username', flat=True)) if m]
    number = max(taken, default=0)
    for guest in PinGuest.objects.select_related('user').order_by('created', 'pk'):
        if re.fullmatch(r'PinUser\d+', guest.user.username):
            continue
        old = guest.user.username
        number += 1
        guest.user.username = f'PinUser{number:04d}'
        guest.user.save(update_fields=['username'])
        if not old.startswith(('pin-', 'pin.')):
            guest.alias = old
            guest.save(update_fields=['alias'])


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_user_pin", "0033_guest_wrong_pin_rules"),
    ]

    operations = [
        migrations.AddField(model_name="pinguest", name="alias", field=models.CharField(blank=True, max_length=100)),
        migrations.AddField(model_name="pinguest", name="pin_language",
                            field=models.CharField(blank=True, max_length=5)),
        migrations.AddField(model_name="pinguest", name="ui_language",
                            field=models.CharField(blank=True, max_length=5)),
        migrations.RunPython(account_ids, migrations.RunPython.noop),
    ]
