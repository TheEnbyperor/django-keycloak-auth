import django.conf
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('django_keycloak_auth', '0002_service_account')]

    operations = [
        migrations.AlterField(
            model_name='Nonce',
            name='next_path',
            field=models.TextField(null=True),
        ),
    ]
