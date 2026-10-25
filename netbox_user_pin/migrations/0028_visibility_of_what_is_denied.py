from django.db import migrations, models


def follow_settings(apps, schema_editor):
    """The switch of an area was "False = door" before; now None means "as the settings say" (the same: a door)."""
    ProtectedArea = apps.get_model('netbox_user_pin', 'ProtectedArea')
    ProtectedArea.objects.filter(hide_denied=False).update(hide_denied=None)


class Migration(migrations.Migration):

    dependencies = [
        ('netbox_user_pin', '0027_area_hide_denied'),
    ]

    operations = [
        migrations.AddField(
            model_name='pinsettings', name='denied_view',
            field=models.CharField(choices=[('doors', 'A: shown, and blocked by the PIN notice'),
                                            ('hidden', 'B: the user sees nothing he is not allowed (only the password '
                                                       'and the PIN)')], default='doors', max_length=10),
        ),
        migrations.AddField(
            model_name='pinsettings', name='allow_requests', field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name='pinsettings', name='allow_own_tokens', field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='protectedarea', name='hide_denied',
            field=models.BooleanField(blank=True, default=None, null=True),
        ),
        migrations.RunPython(follow_settings, migrations.RunPython.noop),
    ]
