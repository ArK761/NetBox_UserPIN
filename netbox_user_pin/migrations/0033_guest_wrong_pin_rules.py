import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_user_pin", "0032_guest_path"),
    ]

    operations = [
        migrations.AlterField(model_name="pinsettings", name="guest_path",
                              field=models.CharField(default="pin", max_length=100)),
        migrations.AddField(model_name="pinsettings", name="guest_step_attempts",
                            field=models.PositiveSmallIntegerField(default=5, validators=[
                                django.core.validators.MinValueValidator(1),
                                django.core.validators.MaxValueValidator(50)])),
        migrations.AddField(model_name="pinsettings", name="guest_waits",
                            field=models.CharField(default="10,20,30", max_length=100)),
        migrations.AddField(model_name="pinguest", name="description",
                            field=models.CharField(blank=True, max_length=150)),
        migrations.AddField(model_name="pinguest", name="blocked",
                            field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name="pinguest", name="step_attempts",
                            field=models.PositiveSmallIntegerField(blank=True, null=True)),
        migrations.AddField(model_name="pinguest", name="waits",
                            field=models.CharField(blank=True, max_length=100)),
    ]
