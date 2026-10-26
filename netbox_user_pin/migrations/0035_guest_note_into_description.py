from django.db import migrations


def note_into_description(apps, schema_editor):
    """The note is no longer used: its text moves into the description (kept when both exist)."""
    PinGuest = apps.get_model('netbox_user_pin', 'PinGuest')
    for guest in PinGuest.objects.exclude(note=''):
        guest.description = ' – '.join(x for x in (guest.description, guest.note) if x)[:150]
        guest.note = ''
        guest.save(update_fields=['description', 'note'])


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_user_pin", "0034_guest_account_id_alias_language"),
    ]

    operations = [
        migrations.RunPython(note_into_description, migrations.RunPython.noop),
    ]
