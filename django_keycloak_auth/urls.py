from django.urls import path

from . import views

urlpatterns = [
    path("login/", views.Login.as_view(), name="oidc_login"),
    path("callback/", views.LoginComplete.as_view(), name="oidc_login_complete"),
    path("logout/", views.Logout.as_view(), name="oidc_logout"),
    path("logout_callback/", views.LogoutComplete.as_view(), name="oidc_logout_complete"),
    path("backchannel/<str:action>", views.oidc_backchannel, name="oidc_backchannel"),
    path("cial_callback/", views.LoginComplete.as_view(), name="cial_link_complete"),
]
