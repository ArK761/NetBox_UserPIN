from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_user_pin", "0038_field_rule_conditions"),
    ]

    operations = [
        migrations.AddField(model_name="pinsettings", name="guest_mail_mode",
                            field=models.CharField(default="summary", max_length=10,
                                                   choices=[("summary", "Summary"), ("each", "At every change")])),
        migrations.AddField(model_name="pinsettings", name="guest_mail_every",
                            field=models.PositiveIntegerField(default=60, validators=[MinValueValidator(5),
                                                                                      MaxValueValidator(1440)])),
    ]
