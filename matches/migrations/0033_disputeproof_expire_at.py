# Generated by Django 4.2.3 on 2024-01-02 01:26

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('matches', '0032_match_match_type'),
    ]

    operations = [
        migrations.AddField(
            model_name='disputeproof',
            name='expire_at',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
    ]
