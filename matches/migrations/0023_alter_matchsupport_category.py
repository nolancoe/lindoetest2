# Generated by Django 4.2.3 on 2023-12-10 21:02

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('matches', '0022_supportcategory'),
    ]

    operations = [
        migrations.AlterField(
            model_name='matchsupport',
            name='category',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='matches.supportcategory'),
        ),
    ]
