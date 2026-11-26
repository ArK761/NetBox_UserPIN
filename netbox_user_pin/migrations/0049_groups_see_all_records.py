"""3.3.0: a group sees every record of its type; the conditions on the records and the denials are gone from the page,
so the groups (not the private profiles of one access) lose them: what the group may see is set by the access level and
the rules of the fields."""
from django.db import migrations


def forward(apps, schema_editor):
    AreaProfile = apps.get_model('netbox_user_pin', 'AreaProfile')
    AreaProfile.objects.filter(private=False).exclude(target='').update(
        records='all', filters={}, deny_filters={}, denied=[])


class Migration(migrations.Migration):
    dependencies = [('netbox_user_pin', '0048_area_mail_rule_schedule')]
    operations = [migrations.RunPython(forward, migrations.RunPython.noop)]
