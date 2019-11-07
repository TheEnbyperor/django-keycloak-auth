from . import clients
import keycloak.admin.users
import keycloak.admin.clientroles
import secrets

BASIC_FIELDS = ("email", "email_verified", "first_name", "last_name")


def get_user_by_id(user_id: str) -> keycloak.admin.users.User:
    admin_client = clients.get_keycloak_admin_client()
    return admin_client.users.by_id(user_id)


def link_roles_to_user(user_id: str, roles=None) -> None:
    if roles is None:
        roles = []

    user = get_user_by_id(user_id)
    role_manager = user.role_mappings.realm

    current_roles = list(
        map(
            lambda r: r.get("name"),
            role_manager.get()
        )
    )
    available_roles = role_manager.available()
    roles_to_add = set()

    for role in roles:
        if role not in current_roles:
            new_role = next(map(lambda r: r.get("id"), filter(lambda r: r.get("name") == role, available_roles)), None)
            if new_role is not None:
                roles_to_add.add(new_role)

    if len(roles_to_add):
        role_manager.add(list(roles_to_add))


def get_or_create_user(federated_user_id=None, federated_user_name=None, federated_provider=None,
                       check_federated_user=None, email=None, **kwargs) -> keycloak.admin.users.User:
    if not callable(check_federated_user):
        raise TypeError("check_federated_user must be callable")

    admin_client = clients.get_keycloak_admin_client()

    users = list(
        map(
            # Get a list of all user ID, then expand each ID to a full user object
            lambda u: admin_client.users.by_id(u.get("id")).user,
            admin_client.users.all(),
        )
    )
    # If a federated identity is provided to check against
    if federated_user_id or check_federated_user:
        for user in users:
            # Get the first matching identity or None
            federated_identity = next(
                filter(
                    # If a function to check the user ID is passed use that,
                    # else check that the user ID is the passed user ID
                    check_federated_user if check_federated_user else lambda i: i.get("userId") == federated_user_id,
                    filter(
                        # Filter through identities for one matching the requested provider,
                        # else if none is requested get all
                        (
                            lambda i: i.get("identityProvider") == federated_provider
                        ) if federated_provider else lambda _: True,
                        user.get("federatedIdentities", []),  # Get all identities
                    ),
                ),
                None,
            )
            if federated_identity:
                return user

    # If on email is provided to check against
    if email:
        for user in users:
            if user.get("email") == email:
                # If a federated user ID is provided link it to the user
                if federated_provider and federated_user_id and federated_user_name:
                    # Make user object to operate one
                    user_o = admin_client.users.by_id(user.get("id"))
                    # Get current federated identities
                    federated_identities = user.get("federatedIdentities")
                    # Add new identity
                    federated_identities.append({
                        "identityProvider": federated_provider,
                        "userId": federated_user_id,
                        "userName": federated_user_name,
                    })
                    # Push user to server
                    user_o.update(federated_identities=federated_identities)

                return user

    # If neither worked and the appropriate data is available; create a new user
    if email and federated_provider and federated_user_id and federated_user_name:
        def username_exists(username):
            return next(
                filter(
                    lambda u: u.get("username") == username,
                    users
                ),
                None
            ) is None

        preferred_username = email
        while username_exists(preferred_username):
            preferred_username = secrets.token_hex(16)

        attributes = {}
        fields = {}
        for k, v in kwargs.items():
            if k in BASIC_FIELDS:
                fields[k] = v
            else:
                attributes[k] = v

        admin_client.users.create(
            username=preferred_username,
            email=email,
            federated_identities=[{
                "identityProvider": federated_provider,
                "userId": federated_user_id,
                "userName": federated_user_name,
            }],
            attributes=attributes,
            **fields
        )


def link_federated_identity_if_not_exists(user_id: str, federated_user_id=None, federated_user_name=None,
                                          federated_provider=None) -> None:
    admin_client = clients.get_keycloak_admin_client()
    user = admin_client.users.by_id(user_id)

    federated_identities = user.user.get("federatedIdentities")
    federated_identity = next(
        filter(
            lambda i: i.get("identityProvider") == federated_provider and i.get("userId") == federated_user_id,
            user.user.get("federatedIdentities", []),
        ),
        None,
    )
    if not federated_identity:
        federated_identities.push(
            {
                "identityProvider": federated_provider,
                "userId": federated_user_id,
                "userName": federated_user_name,
            }
        )

    user.update(federated_identities=federated_identities)


def update_user(user_id: str, force_update=False, **kwargs) -> None:
    admin_client = clients.get_keycloak_admin_client()
    user = admin_client.users.by_id(user_id)
    attributes = user.user.get("attributes", {})

    new_values = {}

    for k, v in kwargs.items():
        if k in BASIC_FIELDS:
            current_value = user.user.get(keycloak.admin.clientroles.to_camel_case(k))
            if (not current_value and v is not None) or force_update:
                new_values[k] = v
        else:
            current_value = attributes.get(k)
            if (not current_value and v is not None) or force_update:
                attributes[k] = v
    user.update(
        attributes=attributes,
        **kwargs
    )
