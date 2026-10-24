from django.db import migrations, models


def mark_existing(apps, schema_editor):
    """What was configured keeps its meaning: a profile with conditions is "by conditions", the others "all"."""
    AreaProfile = apps.get_model('netbox_user_pin', 'AreaProfile')
    for profile in AreaProfile.objects.all():
        spec = (profile.filters or {}).get(profile.target) if profile.target else None
        if not profile.target:
            spec = next((v for v in (profile.filters or {}).values() if v), None)
        profile.records = 'filtered' if spec else 'all'
        profile.save(update_fields=['records'])


class Migration(migrations.Migration):

    dependencies = [
        ('netbox_user_pin', '0024_merge_same_field_conditions'),
    ]

    operations = [
        migrations.AddField(
            model_name='areaprofile', name='records',
            field=models.CharField(choices=[('unset', 'Not set'), ('all', 'All records'), ('filtered', 'By conditions')],
                                   default='all', max_length=10),
        ),
        migrations.AddField(
            model_name='areaprofile', name='deny_filters', field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddField(
            model_name='areaprofile', name='denied', field=models.JSONField(blank=True, default=list),
        ),
        migrations.RunPython(mark_existing, migrations.RunPython.noop),
    ]
