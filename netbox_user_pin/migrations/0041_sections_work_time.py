import datetime

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_user_pin", "0040_protect_scope"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(model_name="areaowner", name="targets",
                            field=models.JSONField(blank=True, default=list)),
        migrations.AddField(model_name="pinguest", name="manager",
                            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                                                    related_name="+", to=settings.AUTH_USER_MODEL)),
        migrations.AddField(model_name="pinguest", name="work_mode", field=models.CharField(default="general", max_length=7)),
        migrations.AddField(model_name="pinguest", name="work_country", field=models.CharField(blank=True, max_length=2)),
        migrations.AddField(model_name="pinguest", name="work_days", field=models.CharField(blank=True, max_length=7)),
        migrations.AddField(model_name="pinguest", name="work_from", field=models.TimeField(blank=True, null=True)),
        migrations.AddField(model_name="pinguest", name="work_to", field=models.TimeField(blank=True, null=True)),
        migrations.AddField(model_name="pinsettings", name="guest_work_on", field=models.BooleanField(default=False)),
        migrations.AddField(model_name="pinsettings", name="guest_work_country",
                            field=models.CharField(default="SK", max_length=2)),
        migrations.AddField(model_name="pinsettings", name="guest_work_days",
                            field=models.CharField(default="01234", max_length=7)),
        migrations.AddField(model_name="pinsettings", name="guest_work_from",
                            field=models.TimeField(default=datetime.time(6, 0))),
        migrations.AddField(model_name="pinsettings", name="guest_work_to",
                            field=models.TimeField(default=datetime.time(16, 0))),
    ]
