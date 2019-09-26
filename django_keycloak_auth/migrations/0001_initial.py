# Generated by Django 2.2.1 on 2019-09-22 17:51

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="Nonce",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("state", models.UUIDField(default=uuid.uuid4, unique=True)),
                ("redirect_uri", models.CharField(max_length=255)),
                ("next_path", models.CharField(max_length=255, null=True)),
            ],
        ),
        migrations.CreateModel(
            name="RemoteUserOpenIdConnectProfile",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("access_token", models.TextField(null=True)),
                ("expires_before", models.DateTimeField(null=True)),
                ("refresh_token", models.TextField(null=True)),
                ("refresh_expires_before", models.DateTimeField(null=True)),
                ("sub", models.CharField(max_length=255, unique=True)),
            ],
        ),
    ]
