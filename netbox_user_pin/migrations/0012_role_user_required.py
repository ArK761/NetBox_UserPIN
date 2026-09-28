import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_user_pin", "0011_convert_delegates"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.RemoveField(model_name="pindelegate", name="group"),
        migrations.AlterField(
            model_name="pindelegate", name="user",
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="pin_roles",
                                    to=settings.AUTH_USER_MODEL),
        ),
    ]
