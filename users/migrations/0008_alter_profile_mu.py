# Generated by Django 4.2.3 on 2023-08-02 15:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0007_profile_mu_profile_phi_profile_sigma'),
    ]

    operations = [
        migrations.AlterField(
            model_name='profile',
            name='mu',
            field=models.FloatField(default=1000),
        ),
    ]
