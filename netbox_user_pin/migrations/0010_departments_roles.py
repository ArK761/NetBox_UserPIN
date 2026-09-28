import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_user_pin", "0009_show_full_names"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Department",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("name", models.CharField(max_length=100, unique=True)),
                ("description", models.CharField(blank=True, max_length=200)),
                ("created", models.DateTimeField(auto_now_add=True)),
                ("created_by", models.CharField(blank=True, max_length=150)),
            ],
            options={"ordering": ("name",)},
        ),
        migrations.CreateModel(
            name="DepartmentMember",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("added", models.DateTimeField(auto_now_add=True)),
                ("added_by", models.CharField(blank=True, max_length=150)),
                ("department", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="members",
                                                 to="netbox_user_pin.department")),
                ("user", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE,
                                              related_name="pin_membership", to=settings.AUTH_USER_MODEL)),
            ],
            options={"ordering": ("user__username",)},
        ),
        migrations.CreateModel(
            name="TransferRequest",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("requested_by_name", models.CharField(max_length=150)),
                ("status", models.CharField(default="pending", max_length=10)),
                ("created", models.DateTimeField(auto_now_add=True)),
                ("expires", models.DateTimeField()),
                ("decided", models.DateTimeField(blank=True, null=True)),
                ("decided_by", models.CharField(blank=True, max_length=150)),
                ("user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="+",
                                           to=settings.AUTH_USER_MODEL)),
                ("from_department", models.ForeignKey(blank=True, null=True,
                                                      on_delete=django.db.models.deletion.CASCADE, related_name="+",
                                                      to="netbox_user_pin.department")),
                ("to_department", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="+",
                                                    to="netbox_user_pin.department")),
                ("approving_department", models.ForeignKey(blank=True, null=True,
                                                           on_delete=django.db.models.deletion.CASCADE,
                                                           related_name="+", to="netbox_user_pin.department")),
                ("requested_by", models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL,
                                                   related_name="+", to=settings.AUTH_USER_MODEL)),
            ],
            options={"ordering": ("-created",)},
        ),
        migrations.AlterModelOptions(name="pindelegate", options={"ordering": ("created",)}),
        migrations.RemoveConstraint(model_name="pindelegate", name="netbox_user_pin_delegate_user_xor_group"),
        migrations.AlterField(
            model_name="pindelegate", name="user",
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE,
                                    related_name="pin_roles", to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(model_name="pindelegate", name="role",
                            field=models.CharField(default="core", max_length=10)),
        migrations.AddField(model_name="pindelegate", name="status",
                            field=models.CharField(default="pending", max_length=10)),
        migrations.AddField(
            model_name="pindelegate", name="department",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE,
                                    related_name="roles", to="netbox_user_pin.department"),
        ),
        migrations.AddField(model_name="pindelegate", name="temporary_until",
                            field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(
            model_name="pindelegate", name="substitute_for",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                                    related_name="substitutes", to="netbox_user_pin.pindelegate"),
        ),
        migrations.AddField(
            model_name="pindelegate", name="replaces",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                                    related_name="replaced_by", to="netbox_user_pin.pindelegate"),
        ),
        migrations.AddField(model_name="pindelegate", name="reason",
                            field=models.CharField(blank=True, max_length=500)),
        migrations.AddField(model_name="pindelegate", name="invited_by",
                            field=models.CharField(blank=True, max_length=150)),
        migrations.AddField(model_name="pindelegate", name="invite_hours",
                            field=models.PositiveSmallIntegerField(default=24)),
        migrations.AddField(model_name="pindelegate", name="invite_code",
                            field=models.CharField(blank=True, max_length=128)),
        migrations.AddField(model_name="pindelegate", name="invite_expires",
                            field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name="pindelegate", name="invite_sent",
                            field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name="pindelegate", name="invite_attempts",
                            field=models.PositiveSmallIntegerField(default=0)),
        migrations.AddField(model_name="pindelegate", name="reminder_sent",
                            field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name="pindelegate", name="accepted",
                            field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name="pindelegate", name="ended",
                            field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name="pindelegate", name="end_reason",
                            field=models.CharField(blank=True, max_length=500)),
        migrations.AddField(
            model_name="approvalrequest", name="department",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                                    related_name="+", to="netbox_user_pin.department"),
        ),
    ]
