from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('netbox_user_pin', '0025_profile_records_and_denies'),
    ]

    operations = [
        migrations.AlterField(
            model_name='areafieldrule', name='mode',
            field=models.CharField(choices=[('default', 'By rights'), ('hidden', 'Hidden'), ('read', 'Read only'),
                                            ('write', 'Read and write')], default='write', max_length=10),
        ),
    ]
