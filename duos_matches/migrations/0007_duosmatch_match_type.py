# Generated by Django 4.2.3 on 2023-12-31 19:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('duos_matches', '0006_duosmatchsupport_duosdispute'),
    ]

    operations = [
        migrations.AddField(
            model_name='duosmatch',
            name='match_type',
            field=models.CharField(choices=[('duos', 'Duos')], default='duos', max_length=10),
        ),
    ]
