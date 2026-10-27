from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_user_pin", "0036_guest_expiry_warned"),
    ]

    operations = [
        migrations.AddField(model_name="pinsettings", name="guest_mail_person",
                            field=models.BooleanField(default=True)),
        migrations.AddField(model_name="pinsettings", name="guest_mail_changes",
                            field=models.BooleanField(default=True)),
        migrations.AddField(model_name="pinguest", name="mail_person", field=models.BooleanField(default=True)),
        migrations.AddField(model_name="pinguest", name="mail_changes", field=models.BooleanField(default=True)),
        migrations.AddField(model_name="pinguest", name="changes_mailed",
                            field=models.DateTimeField(blank=True, null=True)),
    ]
