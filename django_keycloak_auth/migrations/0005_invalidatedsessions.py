# Generated by Django 3.1.5 on 2021-02-24 16:27

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('django_keycloak_auth', '0004_logoutstate'),
    ]

    operations = [
        migrations.CreateModel(
            name='InvalidatedSessions',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('session_id', models.UUIDField(default=uuid.uuid4, unique=True)),
            ],
        ),
    ]
