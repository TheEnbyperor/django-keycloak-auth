import datetime

import django.contrib.auth
import django.db.transaction
import django.utils.timezone
import keycloak.realm
import keycloak.exceptions
import keycloak.admin.realm
import django.conf
import jose.jwk
import jose.jwt
import base64
import typing

from . import models

_realm_client = None  # type: typing.Optional[keycloak.realm.KeycloakRealm]
_admin_client = None  # type: typing.Optional[keycloak.admin.realm.Realm]
_oidc_client = None  # type: typing.Optional[keycloak.realm.KeycloakOpenidConnect]
_authz_client = None  # type: typing.Optional[keycloak.realm.KeycloakAuthz]
_uma_client = None  # type: typing.Optional[keycloak.realm.KeycloakUMA]


class TokensExpired(Exception):
    pass


def get_keycloak_client() -> keycloak.realm.KeycloakRealm:
    global _realm_client
    if not _realm_client:
        _realm_client = keycloak.realm.KeycloakRealm(
            server_url=django.conf.settings.KEYCLOAK_SERVER_URL,
            realm_name=django.conf.settings.KEYCLOAK_REALM,
        )
    return _realm_client


def get_keycloak_admin_client() -> keycloak.admin.realm.Realm:
    global _admin_client
    if not _admin_client:
        _admin_client = get_keycloak_client().admin
    _admin_client.set_token(get_access_token())
    return _admin_client.realms.by_name(django.conf.settings.KEYCLOAK_REALM)


def get_openid_connect_client() -> keycloak.realm.KeycloakOpenidConnect:
    global _oidc_client
    if not _oidc_client:
        _oidc_client = get_keycloak_client().open_id_connect(
            django.conf.settings.OIDC_CLIENT_ID, django.conf.settings.OIDC_CLIENT_SECRET
        )
    return _oidc_client


def get_authz_client():
    global _authz_client
    if not _authz_client:
        _authz_client = get_keycloak_client().authz(
            client_id=django.conf.settings.OIDC_CLIENT_ID
        )
    return _authz_client


def get_uma_client():
    global _uma_client
    if not _uma_client:
        _uma_client = get_keycloak_client().uma()
    return _uma_client


def get_service_account_profile():
    UserModel = django.contrib.auth.get_user_model()
    user = UserModel.objects.filter(email__startswith=f"service-account-{django.conf.settings.OIDC_CLIENT_ID}").first()
    if user:
        try:
            oidc_profile = user.oidc_profile
            return oidc_profile
        except UserModel.oidc_profile.RelatedObjectDoesNotExist:
            pass
    token_response, initiate_time = get_new_access_token()

    oidc_profile = update_or_create(
        token_response=token_response, initiate_time=initiate_time
    )

    return oidc_profile


def get_new_access_token():
    scope = "openid"

    initiate_time = django.utils.timezone.now()
    token_response = get_openid_connect_client().client_credentials(scope=scope)

    return token_response, initiate_time


def get_access_token():
    oidc_profile = get_service_account_profile()

    try:
        return get_active_access_token(oidc_profile=oidc_profile)
    except TokensExpired:
        token_reponse, initiate_time = get_new_access_token()
        oidc_profile = update_tokens(
            token_model=oidc_profile,
            token_response=token_reponse,
            initiate_time=initiate_time,
        )
        return oidc_profile.access_token


def update_or_create_user_and_oidc_profile(id_token_object):
    with django.db.transaction.atomic():
        UserModel = django.contrib.auth.get_user_model()
        email_field_name = UserModel.get_email_field_name()
        roles = (
            id_token_object.get("resource_access", {})
            .get(django.conf.settings.OIDC_CLIENT_ID, {})
            .get("roles", [])
        )
        user, _ = UserModel.objects.update_or_create(
            username=id_token_object["sub"],
            defaults={
                email_field_name: id_token_object.get("email", ""),
                "first_name": id_token_object.get("given_name", ""),
                "last_name": id_token_object.get("family_name", ""),
            },
        )
        user.is_staff = "staff" in roles
        user.save()

        oidc_profile, _ = models.RemoteUserOpenIdConnectProfile.objects.update_or_create(
            sub=id_token_object["sub"], defaults={"user": user}
        )

    return oidc_profile


def update_or_create(token_response, initiate_time):
    token_response_key = "id_token" if "id_token" in token_response else "access_token"

    client = get_openid_connect_client()
    cert = client.certs()["keys"][0]
    token_object = client.decode_token(
        token=token_response[token_response_key],
        key=cert,
        algorithms=client.well_known["id_token_signing_alg_values_supported"],
        issuer=client.well_known["issuer"],
    )

    oidc_profile = update_or_create_user_and_oidc_profile(id_token_object=token_object)

    return update_tokens(
        token_model=oidc_profile,
        token_response=token_response,
        initiate_time=initiate_time,
    )


def update_tokens(token_model, token_response, initiate_time):
    expires_before = initiate_time + datetime.timedelta(
        seconds=token_response["expires_in"]
    )
    refresh_expires_before = initiate_time + datetime.timedelta(
        seconds=token_response["refresh_expires_in"]
    ) if token_response["refresh_expires_in"] else None

    token_model.access_token = token_response["access_token"]
    token_model.expires_before = expires_before
    token_model.refresh_token = token_response["refresh_token"]
    token_model.refresh_expires_before = refresh_expires_before

    token_model.save(
        update_fields=[
            "access_token",
            "expires_before",
            "refresh_token",
            "refresh_expires_before",
        ]
    )
    return token_model


def get_active_access_token(oidc_profile):
    initiate_time = django.utils.timezone.now()

    if (
        oidc_profile.refresh_expires_before is not None
        and initiate_time > oidc_profile.refresh_expires_before
    ):
        raise TokensExpired()

    if initiate_time > oidc_profile.expires_before:
        if not oidc_profile.refresh_token:
            raise TokensExpired()
        # Refresh token
        try:
            token_response = get_openid_connect_client().refresh_token(
                refresh_token=oidc_profile.refresh_token
            )
        except keycloak.exceptions.KeycloakClientError:
            raise TokensExpired()

        oidc_profile = update_tokens(
            token_model=oidc_profile,
            token_response=token_response,
            initiate_time=initiate_time,
        )

    return oidc_profile.access_token


def get_entitlement(oidc_profile):
    access_token = get_active_access_token(oidc_profile=oidc_profile)
    get_openid_connect_client()
    return get_authz_client().get_permissions(access_token)


def verify_token(token):
    client = get_openid_connect_client()
    certs = client.certs()
    try:
        return jose.jwt.decode(token, certs, audience=django.conf.settings.OIDC_CLIENT_ID)
    except jose.jwt.JWTError as e:
        raise keycloak.exceptions.KeycloakClientError(e)
