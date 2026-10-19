from django.db import migrations

DEFAULT_NAMES = ('Read', 'Edit', 'Full')


def drop_defaults(apps, schema_editor):
    """The Read / Edit / Full profiles that every own area got are not used: access goes through groups."""
    AreaProfile = apps.get_model('netbox_user_pin', 'AreaProfile')
    for profile in AreaProfile.objects.filter(name__in=DEFAULT_NAMES, private=False, target='', area__plugin=False):
        if not profile.grants.exists() and not profile.field_rules.exists():
            profile.delete()


class Migration(migrations.Migration):

    dependencies = [
        ('netbox_user_pin', '0021_profile_unique_per_type'),
    ]

    operations = [
        migrations.RunPython(drop_defaults, migrations.RunPython.noop),
    ]
