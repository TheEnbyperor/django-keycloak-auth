import django.conf
import django.contrib.auth
import django.core.exceptions
import django.utils.timezone
from django.db import models
import uuid
from . import clients


class Nonce(models.Model):
    state = models.UUIDField(default=uuid.uuid4, unique=True)
    redirect_uri = models.CharField(max_length=255)
    next_path = models.TextField(null=True)


class LogoutState(models.Model):
    state = models.UUIDField(default=uuid.uuid4, unique=True)
    next_path = models.TextField(null=True)


class InvalidatedSessions(models.Model):
    session_id = models.UUIDField(default=uuid.uuid4, unique=True)


class RemoteUserOpenIdConnectProfile(models.Model):
    access_token = models.TextField(null=True)
    expires_before = models.DateTimeField(null=True)

    refresh_token = models.TextField(null=True)
    refresh_expires_before = models.DateTimeField(null=True)

    sub = models.CharField(max_length=255, unique=True)

    user = models.OneToOneField(
        django.conf.settings.AUTH_USER_MODEL,
        related_name="oidc_profile",
        on_delete=models.CASCADE,
    )

    is_service_account = models.BooleanField(blank=True, default=False)

    @property
    def is_active(self):
        if not self.access_token or not self.expires_before:
            return False

        return self.expires_before > django.utils.timezone.now()

    @property
    def jwt(self):
        """
        :rtype: dict
        """
        if not self.is_active:
            return None
        client = clients.get_openid_connect_client()
        return clients.get_openid_connect_client().decode_token(
            token=self.access_token,
            keys=client.certs(),
            algorithms=client.well_known["id_token_signing_alg_values_supported"],
        )
