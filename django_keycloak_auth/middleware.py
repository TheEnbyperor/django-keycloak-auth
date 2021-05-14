import django.contrib.auth.models
import django.utils.functional
import django.shortcuts
from django.db import close_old_connections
from . import auth, models

class OIDCRedirect(Exception):
    def __init__(self, url):
        self.url = url


def get_user(session, origin_user):
    # Check for the user as set by
    # django.contrib.auth.middleware.AuthenticationMiddleware
    if (
        not isinstance(origin_user, django.contrib.auth.models.AnonymousUser)
        and origin_user is not None
    ):
        return origin_user

    try:
        return auth.get_remote_user(session)
    except:
        return django.contrib.auth.models.AnonymousUser()


class OIDCMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        origin_user = getattr(request, "user", None)

        request.user = django.utils.functional.SimpleLazyObject(
            lambda: get_user(request.session, origin_user=origin_user)
        )

        if "oidc_session_id" in request.session:
            sessions = models.InvalidatedSessions.objects.filter(session_id=request.session["oidc_session_id"])
            if len(sessions):
                django.contrib.auth.logout(request)
                sessions.delete()

        return self.get_response(request)

    @staticmethod
    def process_exception(_request, exception):
        if isinstance(exception, OIDCRedirect):
            return django.shortucts.redirect(exception.url)


class OIDCChannelsMiddleware:
    def __init__(self, inner):
        self.inner = inner

    def __call__(self, scope, *args, **kwargs):
        close_old_connections()

        origin_user = scope.get("user")

        user = django.utils.functional.SimpleLazyObject(
            lambda: get_user(scope.get("session"), origin_user=origin_user)
        )

        return self.inner(dict(scope, user=user), *args, **kwargs)
