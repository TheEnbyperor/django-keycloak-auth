import django.contrib.auth.models
import django.utils.functional
from django.db import close_old_connections
from . import auth


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

        return self.get_response(request)


class OIDCChannelsMiddleware:
    def __init__(self, inner):
        self.inner = inner

    def __call__(self, scope):
        close_old_connections()

        origin_user = scope.get("user")

        user = django.utils.functional.SimpleLazyObject(
            lambda: get_user(scope.get("session"), origin_user=origin_user)
        )

        return self.inner(dict(scope, user=user))
