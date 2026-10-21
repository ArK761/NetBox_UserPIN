from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('netbox_user_pin', '0022_drop_unused_default_profiles'),
    ]

    operations = [
        migrations.AddField(
            model_name='userpin',
            name='failed_2fa',
            field=models.PositiveSmallIntegerField(default=0),
        ),
    ]
