# Generated by Django 3.2.9 on 2024-12-04 17:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rbac_app', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='auditlog',
            name='id',
            field=models.CharField(default='', max_length=50, primary_key=True, serialize=False, unique=True),
        ),
        migrations.AlterField(
            model_name='permission',
            name='id',
            field=models.AutoField(primary_key=True, serialize=False),
        ),
        migrations.AlterField(
            model_name='role',
            name='id',
            field=models.AutoField(primary_key=True, serialize=False),
        ),
        migrations.AlterField(
            model_name='user',
            name='id',
            field=models.AutoField(primary_key=True, serialize=False),
        ),
        migrations.AlterModelTable(
            name='auditlog',
            table='audit_logs',
        ),
    ]