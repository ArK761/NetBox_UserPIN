from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_user_pin", "0039_guest_mail_mode"),
    ]

    def to_pin(apps, schema_editor):
        apps.get_model("netbox_user_pin", "PinSettings").objects.update(protect_scope="pin")

    operations = [
        migrations.AddField(model_name="pinsettings", name="protect_scope",
                            field=models.CharField(default="pin", max_length=10,
                                                   choices=[("all", "Everybody"), ("pin", "Only people with a PIN")])),
        migrations.RunPython(to_pin, migrations.RunPython.noop),
    ]
