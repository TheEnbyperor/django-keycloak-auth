import logging

import django.contrib.auth
import django.http
import django.shortcuts
import django.urls
import django.conf
import django.views.generic

from . import models
from . import clients
from . import auth

logger = logging.getLogger(__name__)


class Login(django.views.generic.RedirectView):
    def get_redirect_url(self, *args, **kwargs):
        nonce = models.Nonce.objects.create(
            redirect_uri=self.request.build_absolute_uri(
                location=django.urls.reverse("oidc_login_complete")
            ),
            next_path=self.request.GET.get("next"),
        )

        self.request.session["oidc_state"] = str(nonce.state)

        authorization_url = clients.get_openid_connect_client().authorization_url(
            redirect_uri=nonce.redirect_uri,
            scope=django.conf.settings.OIDC_SCOPES,
            state=str(nonce.state),
            key=self.request.GET.get("key")
        )

        return authorization_url


class LoginComplete(django.views.generic.RedirectView):
    def get(self, *args, **kwargs):
        request = self.request

        if "error" in request.GET:
            return django.http.HttpResponseServerError(request.GET["error"])

        if "code" not in request.GET and "state" not in request.GET:
            return django.http.HttpResponseBadRequest()

        if (
            "oidc_state" not in request.session
            or request.GET["state"] != request.session["oidc_state"]
        ):
            return django.http.HttpResponseRedirect(django.urls.reverse("oidc_login"))

        nonce = auth.models.Nonce.objects.get(state=request.GET["state"])

        user = django.contrib.auth.authenticate(
            request=request, code=request.GET["code"], redirect_uri=nonce.redirect_uri
        )
        django.contrib.auth.login(request, user)

        nonce.delete()

        return django.http.HttpResponseRedirect(nonce.next_path or "/")


class Logout(django.views.generic.RedirectView):
    def get_redirect_url(self, *args, **kwargs):
        if hasattr(self.request.user, "oidc_profile"):
            clients.get_openid_connect_client().logout(
                self.request.user.oidc_profile.refresh_token
            )
            self.request.user.oidc_profile.access_token = None
            self.request.user.oidc_profile.expires_before = None
            self.request.user.oidc_profile.refresh_token = None
            self.request.user.oidc_profile.refresh_expires_before = None
            self.request.user.oidc_profile.save(
                update_fields=[
                    "access_token",
                    "expires_before",
                    "refresh_token",
                    "refresh_expires_before",
                ]
            )

        django.contrib.auth.logout(self.request)

        if django.conf.settings.LOGOUT_REDIRECT_URL:
            return django.shortcuts.resolve_url(
                django.conf.settings.LOGOUT_REDIRECT_URL
            )

        return django.urls.reverse("oidc_login")
