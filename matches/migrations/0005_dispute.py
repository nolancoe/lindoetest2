# Generated by Django 4.2.3 on 2023-08-04 19:42

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('matches', '0004_match_match_completed_matchresult'),
    ]

    operations = [
        migrations.CreateModel(
            name='Dispute',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('challenger_claim', models.TextField()),
                ('respondent_claim', models.TextField()),
                ('challenger_screenshot', models.ImageField(blank=True, null=True, upload_to='dispute_screenshots/')),
                ('respondent_screenshot', models.ImageField(blank=True, null=True, upload_to='dispute_screenshots/')),
                ('challenger_additional_evidence', models.URLField(blank=True, null=True)),
                ('respondent_additional_evidence', models.URLField(blank=True, null=True)),
                ('resolved', models.BooleanField(default=False)),
                ('challenger', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='challenger', to=settings.AUTH_USER_MODEL)),
                ('match', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='matches.match')),
                ('respondent', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='respondent', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]