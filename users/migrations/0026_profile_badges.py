# Generated by Django 4.2.3 on 2023-12-09 14:36

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0025_badge'),
    ]

    operations = [
        migrations.AddField(
            model_name='profile',
            name='badges',
            field=models.ManyToManyField(blank=True, related_name='users', to='users.badge'),
        ),
    ]
