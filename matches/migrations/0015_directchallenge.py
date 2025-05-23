# Generated by Django 4.2.3 on 2023-11-26 02:43

from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('teams', '0012_team_disbanded'),
        ('matches', '0014_match_match_disputed'),
    ]

    operations = [
        migrations.CreateModel(
            name='DirectChallenge',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('date_created', models.DateTimeField(default=django.utils.timezone.now)),
                ('scheduled_date', models.DateTimeField(blank=True, null=True)),
                ('accepted', models.BooleanField(default=False)),
                ('challenged_team', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='challenged_direct_challenges', to='teams.team')),
                ('challenging_team', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='direct_challenges', to='teams.team')),
            ],
        ),
    ]
