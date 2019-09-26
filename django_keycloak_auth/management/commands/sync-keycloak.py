import collections

import django.apps
import django.conf
import django.utils.text
import keycloak.exceptions
from django.core.management.base import BaseCommand, CommandError
from keycloak_auth import clients


class Command(BaseCommand):
    help = "Synchronises models to keylcloak"
    requires_migrations_checks = True

    def handle(self, *args, **options):
        uma_client = clients.get_uma_client()
        access_token = clients.get_access_token()

        resources = list(
            map(
                lambda r: uma_client.resource_set_read(token=access_token, id=r),
                uma_client.resource_set_list(token=access_token),
            )
        )

        def resource_exists(res_type):
            for res in resources:
                if res.get("type") == res_type:
                    return res
            return None

        for app_config in django.apps.apps.get_app_configs():
            if not app_config.models_module:
                continue

            for klass in app_config.get_models():
                scopes = klass._meta.default_permissions

                try:
                    res_type = "urn:{client}:resources:{model}".format(
                        client=django.utils.text.slugify(
                            django.conf.settings.OIDC_CLIENT_ID
                        ),
                        model=klass._meta.label_lower,
                    )
                    res = resource_exists(res_type)

                    if res is None:
                        uma_client.resource_set_create(
                            token=access_token,
                            name=klass._meta.label_lower,
                            type=res_type,
                            scopes=scopes,
                        )
                    else:
                        uma_client.resource_set_update(
                            token=access_token,
                            id=res.get("_id"),
                            name=klass._meta.label_lower,
                            type=res_type,
                            scopes=scopes,
                        )
                except keycloak.exceptions.KeycloakClientError as e:
                    raise CommandError(e)
