# Generated by Django 4.2.3 on 2023-08-04 20:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('matches', '0006_alter_dispute_challenger_additional_evidence_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='disputechallenger',
            name='additional_evidence',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='disputerespondent',
            name='additional_evidence',
            field=models.TextField(blank=True, null=True),
        ),
    ]
