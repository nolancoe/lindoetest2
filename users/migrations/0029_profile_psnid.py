# Generated by Django 4.2.3 on 2023-12-21 17:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0028_profile_gamertag'),
    ]

    operations = [
        migrations.AddField(
            model_name='profile',
            name='psnid',
            field=models.CharField(blank=True, max_length=16, null=True),
        ),
    ]
