# Generated by Django 4.2.3 on 2023-07-31 22:52

from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('teams', '0004_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='team',
            name='players',
            field=models.ManyToManyField(blank=True, related_name='members', to=settings.AUTH_USER_MODEL),
        ),
    ]
