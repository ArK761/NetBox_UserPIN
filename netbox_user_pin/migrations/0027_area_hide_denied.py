from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('netbox_user_pin', '0026_field_rule_default_mode'),
    ]

    operations = [
        migrations.AddField(
            model_name='protectedarea', name='hide_denied', field=models.BooleanField(default=False),
        ),
    ]
