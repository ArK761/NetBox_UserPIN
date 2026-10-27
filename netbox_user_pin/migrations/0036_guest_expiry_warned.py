from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_user_pin", "0035_guest_note_into_description"),
    ]

    operations = [
        migrations.AddField(model_name="pinguest", name="expiry_warned",
                            field=models.CharField(blank=True, max_length=10)),
    ]
