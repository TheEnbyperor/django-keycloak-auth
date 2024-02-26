from django.db import migrations, models
import uuid


class Migration(migrations.Migration):
    dependencies = [('django_keycloak_auth', '0005_invalidatedsessions')]

    operations = [
        migrations.AddField(
            model_name='RemoteUserOpenIdConnectProfile',
            name='id_token',
            field=models.TextField(blank=True, null=True)
        ),
    ]
