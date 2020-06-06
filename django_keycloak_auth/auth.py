import django.conf
import django.contrib.auth
import django.contrib.auth.models
import django.core.exceptions
import django.middleware.csrf
import django.utils.timezone
import django.utils.text

from . import clients, models

REMOTE_SESSION_KEY = "_auth_remote_user_id"


def _get_user_session_key(request):
    return str(request.session[REMOTE_SESSION_KEY])


def get_remote_user(session):
    sub = session.get(REMOTE_SESSION_KEY)

    user = None

    try:
        oidc_profile = models.RemoteUserOpenIdConnectProfile.objects.get(sub=sub)
    except models.RemoteUserOpenIdConnectProfile.DoesNotExist:
        pass
    else:
        if oidc_profile.refresh_expires_before > django.utils.timezone.now():
            clients.get_active_access_token(oidc_profile)
            user = oidc_profile.user

    return user or django.contrib.auth.models.AnonymousUser()


def remote_user_login(request, user, backend=None):
    """
    Creates a session for the user.
    Based on the login function django.contrib.auth.login but uses a slightly
    different approach since the user is not backed by a database model.
    :param request:
    :param user:
    :param backend:
    :return:
    """
    session_auth_hash = ""
    if user is None:
        user = request.user

    if REMOTE_SESSION_KEY in request.session:
        if _get_user_session_key(request) != user.identifier:
            request.session.flush()
    else:
        request.session.cycle_key()

    try:
        backend = backend or user.backend
    except AttributeError:
        backends = django.contrib.auth._get_backends(return_tuples=True)
        if len(backends) == 1:
            _, backend = backends[0]
        else:
            raise ValueError(
                "You have multiple authentication backends configured and "
                "therefore must provide the `backend` argument or set the "
                "`backend` attribute on the user."
            )

    if not hasattr(user, "identifier"):
        raise ValueError(
            "The user does not have an identifier or the identifier is empty."
        )

    request.session[REMOTE_SESSION_KEY] = user.identifier
    request.session[django.contrib.auth.BACKEND_SESSION_KEY] = backend
    request.session[django.contrib.auth.HASH_SESSION_KEY] = session_auth_hash
    if hasattr(request, "user"):
        request.user = user
    django.middleware.csrf.rotate_token(request)


class KeycloakAuthorization:
    def get_user(self, user_id):
        UserModel = django.contrib.auth.get_user_model()
        try:
            user_obj = UserModel.objects.get(pk=user_id)

            try:
                clients.get_entitlement(oidc_profile=user_obj.oidc_profile)
            except clients.TokensExpired:
                return None

            return user_obj
        except UserModel.DoesNotExist:
            return None

    def get_all_permissions(self, user_obj, obj=None):
        if not user_obj.is_active or user_obj.is_anonymous or obj is not None:
            return set()
        if not hasattr(user_obj, "_keycloak_perm_cache"):
            user_obj._keycloak_perm_cache = self.get_keycloak_permissions(
                user_obj=user_obj
            )
        return user_obj._keycloak_perm_cache

    def get_keycloak_permissions(self, user_obj):
        if not hasattr(user_obj, "oidc_profile"):
            return set()

        rpt_decoded = clients.get_entitlement(oidc_profile=user_obj.oidc_profile)

        permissions = []
        for p in rpt_decoded.get("permissions", []):
            if p.get("scopes"):
                for scope in p["scopes"]:
                    permission = p["rsname"]  # type: str
                    parts = permission.rsplit(".", 1)
                    if len(parts) != 2:
                      continue
                    app, model = parts
                    permissions.append(f"{app}.{scope}_{model}")
            else:
                permissions.append(p["rsname"])

        return permissions

    def has_perm(self, user_obj, perm, obj=None):
        if not user_obj.is_active:
            return False

        granted_perms = self.get_all_permissions(user_obj, obj)
        return perm in granted_perms

    def has_module_perms(self, user_obj, model):
        if not user_obj.is_active:
            return False

        granted_perms = self.get_all_permissions(user_obj)
        for perm in granted_perms:
            if perm.startswith(model):
                return True
        return False

    def authenticate(self, request, code, redirect_uri):
        client = clients.get_openid_connect_client()

        initiate_time = django.utils.timezone.now()
        token_response = client.authorization_code(code=code, redirect_uri=redirect_uri)

        return clients.update_or_create(
            token_response=token_response, initiate_time=initiate_time
        ).user
