# Generated by Django 4.2.3 on 2023-08-03 02:52

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('matches', '0002_challenge'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='match',
            name='result',
        ),
        migrations.AddField(
            model_name='match',
            name='team1_result',
            field=models.CharField(blank=True, choices=[('', 'Not Available'), ('win', 'Win'), ('loss', 'Loss'), ('draw', 'Draw')], max_length=10),
        ),
        migrations.AddField(
            model_name='match',
            name='team2_result',
            field=models.CharField(blank=True, choices=[('', 'Not Available'), ('win', 'Win'), ('loss', 'Loss'), ('draw', 'Draw')], max_length=10),
        ),
    ]