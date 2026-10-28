from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_user_pin", "0037_guest_mails"),
    ]

    operations = [
        migrations.AlterField(model_name="areafieldrule", name="contains", field=models.TextField(blank=True)),
    ]
