import base64
import hashlib
import uuid
import keycloak
import django.urls
import django.conf

from . import clients


def _make_cial_redirect_url(
        request, oauth_client: keycloak.realm.KeycloakOpenidConnect, access_token: str, broker: str
):
    cert = client.certs()["keys"][0]
    token_object = client.decode_token(
        token=access_token,
        key=cert,
        algorithms=client.well_known["id_token_signing_alg_values_supported"],
        issuer=client.well_known["issuer"],
        options={
            "verify_aud": False
        }
    )
    nonce = str(uuid.uuid4())
    hash_data = nonce + token_object.get("session_state") + token_object.get("sub") + broker
    hash = base64.urlsafe_b64encode(
        hashlib.sha256(hash_data.encode).digest()
    ).decode()

    redirect_uri = request.build_absolute_uri(
        location=django.urls.reverse("cial_link_complete")
    )

    url = f"{django.conf.settings.KEYCLOAK_SERVER_URL}auth/realms/{django.conf.settings.KEYCLOAK_REALM}/" \
          f"broker/{broker}/link?client_id={django.conf.settings.OIDC_CLIENT_ID}" \
          f"&redirect_uri={}&nonce={nonce}&hash={hash}"
