from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('netbox_user_pin', '0042_exception_allowed'),
    ]

    operations = [
        migrations.AddField(
            model_name='policyexception',
            name='active',
            field=models.BooleanField(default=True),
        ),
    ]
