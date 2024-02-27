import logging
import uuid
import datetime

import urllib.parse
import django.contrib.auth
import django.http
import django.shortcuts
import django.urls
import django.conf
import django.views.generic
import django.views.decorators.csrf

import keycloak.exceptions

from . import models
from . import clients
from . import auth

logger = logging.getLogger(__name__)


@django.views.decorators.csrf.csrf_exempt
def oidc_backchannel(request, action):
    if action == "k_logout":
        now = datetime.datetime.utcnow().timestamp()
        try:
            logout_token = clients.verify_token(request.body)
        except keycloak.exceptions.KeycloakClientError:
            return django.http.HttpResponseBadRequest()

        if logout_token["action"] == "LOGOUT":
            if logout_token["expiration"] < now:
                return django.http.HttpResponseBadRequest()
            if logout_token["resource"] != django.conf.settings.OIDC_CLIENT_ID:
                return django.http.HttpResponseBadRequest()

            for session_id in logout_token["adapterSessionIds"]:
                models.InvalidatedSessions.objects.create(
                    session_id=session_id
                )

    return django.http.HttpResponse(status=200)


class Login(django.views.generic.RedirectView):
    def get_redirect_url(self, *args, **kwargs):
        nonce = models.Nonce.objects.create(
            redirect_uri=self.request.build_absolute_uri(
                location=django.urls.reverse("oidc_login_complete")
            ),
            next_path=self.request.GET.get("next"),
        )

        self.request.session["oidc_state"] = str(nonce.state)

        kwargs = {}
        if self.request.GET.get("key"):
            kwargs["key"] = self.request.GET.get("key")
        if self.request.GET.get("kc_action"):
            kc_action = self.request.GET.get("kc_action")
            kwargs["kc_action"] = kc_action
            self.request.session["oidc_kc_action"] = kc_action
        if self.request.GET.get("prompt"):
            prompt = self.request.GET.get("prompt")
            kwargs["prompt"] = prompt
            self.request.session["oidc_prompt"] = prompt


        authorization_url = clients.get_openid_connect_client().authorization_url(
            redirect_uri=nonce.redirect_uri,
            scope=django.conf.settings.OIDC_SCOPES,
            state=str(nonce.state),
            **kwargs
        )

        return authorization_url


class LoginComplete(django.views.generic.RedirectView):
    def get(self, *args, **kwargs):
        request = self.request

        if "state" not in request.GET:
            return django.http.HttpResponseBadRequest()

        login_url = django.urls.reverse("oidc_login")
        login_url_params = {}

        if "oidc_prompt" in login_url:
            login_url_params["prompt"] = request.session["oidc_prompt"]
        if "oidc_kc_action" in login_url:
            login_url_params["kc_action"] = request.session["oidc_kc_action"]

        login_url = f"{login_url}?{urllib.parse.urlencode(login_url_params)}"

        if (
                "oidc_state" not in request.session
                or request.GET["state"] != request.session["oidc_state"]
        ):
            return django.http.HttpResponseRedirect(login_url)

        try:
            nonce = auth.models.Nonce.objects.get(state=request.GET["state"])
        except auth.models.Nonce.DoesNotExist:
            return django.http.HttpResponseRedirect(login_url)

        if "error" in request.GET:
            error = request.GET["error"]
            if error in ("login_required", "access_denied"):
                return django.http.HttpResponseRedirect(nonce.next_path or "/")

            return django.http.HttpResponseServerError(request.GET["error"])

        if "code" not in request.GET:
            return django.http.HttpResponseBadRequest()

        session_state = uuid.uuid4()
        user = django.contrib.auth.authenticate(
            request=request, code=request.GET["code"], redirect_uri=nonce.redirect_uri,
            session_state=session_state
        )
        django.contrib.auth.login(request, user)
        request.session["oidc_session_id"] = str(session_state)

        nonce.delete()

        return django.http.HttpResponseRedirect(nonce.next_path or "/")


class Logout(django.views.generic.RedirectView):
    def get_redirect_url(self, *args, **kwargs):
        next = self.request.GET.get("next")
        if not next and django.conf.settings.LOGOUT_REDIRECT_URL:
            next = django.shortcuts.resolve_url(
                django.conf.settings.LOGOUT_REDIRECT_URL
            )

        logout_state = models.LogoutState.objects.create(
            next_path=next
        )

        oidc_logout_url = clients.get_openid_connect_client().get_url("end_session_endpoint")
        oidc_logout_url_params = urllib.parse.urlencode({
            "client_id": django.conf.settings.OIDC_CLIENT_ID,
            "state": str(logout_state.state),
            "post_logout_redirect_uri": self.request.build_absolute_uri(
                location=django.urls.reverse("oidc_logout_complete")
            )
        })

        django.contrib.auth.logout(self.request)

        return f"{oidc_logout_url}?{oidc_logout_url_params}"


class LogoutComplete(django.views.generic.RedirectView):
    def get(self, *args, **kwargs):
        request = self.request

        if "state" not in request.GET:
            return django.http.HttpResponseRedirect(django.urls.reverse(
                django.conf.settings.LOGOUT_REDIRECT_URL
            ))

        try:
            nonce = auth.models.LogoutState.objects.get(state=request.GET["state"])
        except auth.models.Nonce.DoesNotExist:
            return django.http.HttpResponseRedirect(django.urls.reverse(
                django.conf.settings.LOGOUT_REDIRECT_URL
            ))

        nonce.delete()

        return django.http.HttpResponseRedirect(nonce.next_path or "/")
