# Generated by Django 4.2.3 on 2023-08-04 16:24

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0008_alter_profile_mu'),
    ]

    operations = [
        migrations.RenameField(
            model_name='profile',
            old_name='mu',
            new_name='rating',
        ),
        migrations.RemoveField(
            model_name='profile',
            name='phi',
        ),
        migrations.RemoveField(
            model_name='profile',
            name='sigma',
        ),
    ]
