from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('netbox_user_pin', '0041_sections_work_time'),
    ]

    operations = [
        migrations.AddField(
            model_name='policyexception',
            name='allowed',
            field=models.CharField(blank=True, default='password', max_length=200),
        ),
    ]
