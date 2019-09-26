from django.urls import path

from . import views

urlpatterns = [
    path("login/", views.Login.as_view(), name="oidc_login"),
    path("callback/", views.LoginComplete.as_view(), name="oidc_login_complete"),
    path("logout/", views.Logout.as_view(), name="oidc_logout"),
]
