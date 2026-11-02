from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('netbox_user_pin', '0045_area_mail_users')]
    operations = [
        migrations.AddField(model_name='pinguest', name='person_number',
                            field=models.CharField(blank=True, default=None, max_length=40, null=True, unique=True)),
        migrations.AddField(model_name='pinsettings', name='guest_number_required',
                            field=models.BooleanField(default=False, verbose_name='PIN-only people sign in with the personal number and the PIN')),
        migrations.AddField(model_name='pinsettings', name='guest_pin_min',
                            field=models.PositiveSmallIntegerField(default=8, verbose_name='Shortest PIN of the PIN-only people')),
        migrations.AddField(model_name='pinsettings', name='guest_pin_letter',
                            field=models.BooleanField(default=False, verbose_name='The PIN must contain a letter')),
        migrations.AddField(model_name='pinsettings', name='guest_pin_digit',
                            field=models.BooleanField(default=False, verbose_name='The PIN must contain a digit')),
    ]
