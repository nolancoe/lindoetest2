# Generated by Django 4.2.3 on 2023-12-04 16:04

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('teams', '0012_team_disbanded'),
    ]

    operations = [
        migrations.AddField(
            model_name='team',
            name='eligible',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='team',
            name='eligible_at',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
    ]
