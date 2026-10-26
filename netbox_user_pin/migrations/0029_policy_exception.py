import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('netbox_user_pin', '0028_visibility_of_what_is_denied'),
    ]

    operations = [
        migrations.CreateModel(
            name='PolicyException',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('since', models.DateTimeField(default=django.utils.timezone.now)),
                ('expires', models.DateTimeField(blank=True, null=True)),
                ('added_by_name', models.CharField(blank=True, max_length=150)),
                ('note', models.CharField(blank=True, max_length=200)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE,
                                              related_name='policy_exception', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'protection exception',
                'verbose_name_plural': 'protection exceptions',
                'ordering': ('user__username',),
            },
        ),
    ]
