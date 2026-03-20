import pytest

from opaque_ke.errors import InvalidLoginError
from opaque_ke.types import (
    ClientLoginFinishParameters,
    ClientRegistrationFinishParameters,
    Identifiers,
    KeyStretching,
    ServerLoginParameters,
)


def _register_high_level(client, server, server_setup, password, credential_identifier, params=None):
    request, state = client.start_registration(password)
    response = server.start_registration(server_setup, request, credential_identifier)
    upload, export_key = client.finish_registration(state, password, response, params)
    password_file = server.finish_registration(upload)
    return password_file, export_key


def _login_high_level(
    client,
    server,
    server_setup,
    password,
    credential_identifier,
    password_file,
    server_params=None,
    client_params=None,
):
    request, state = client.start_login(password)
    response, server_state = server.start_login(
        server_setup, password_file, request, credential_identifier, server_params
    )
    finalization, session_key, export_key, server_s_pk = client.finish_login(
        state, password, response, client_params
    )
    server_session_key = server.finish_login(server_state, finalization, server_params)
    return session_key, server_session_key, export_key, server_s_pk


def test_high_level_roundtrip(client, server, server_setup, password, credential_identifier):
    password_file, _ = _register_high_level(
        client, server, server_setup, password, credential_identifier
    )

    session_key, server_session_key, export_key, server_s_pk = _login_high_level(
        client,
        server,
        server_setup,
        password,
        credential_identifier,
        password_file,
    )

    assert session_key == server_session_key
    assert export_key
    assert server_s_pk


def test_high_level_with_context_and_identifiers(
    client, server, server_setup, password, credential_identifier
):
    identifiers = Identifiers(client=b"client", server=b"server")
    reg_params = ClientRegistrationFinishParameters(identifiers, None)
    password_file, _ = _register_high_level(
        client, server, server_setup, password, credential_identifier, reg_params
    )

    context = b"opaque-python"
    server_params = ServerLoginParameters(context, identifiers)
    client_params = ClientLoginFinishParameters(context, identifiers, None, None)

    session_key, server_session_key, _, _ = _login_high_level(
        client,
        server,
        server_setup,
        password,
        credential_identifier,
        password_file,
        server_params,
        client_params,
    )

    assert session_key == server_session_key


def test_low_level_roundtrip(server_setup, password, credential_identifier):
    from opaque_ke import login, registration

    request, state = registration.client.start_registration(password)
    response = registration.server.start_registration(
        server_setup, request, credential_identifier
    )
    upload, _ = registration.client.finish_registration(state, password, response, None)
    password_file = registration.server.finish_registration(upload)

    request, state = login.client.start_login(password)
    response, server_state = login.server.start_login(
        server_setup, password_file, request, credential_identifier, None
    )
    finalization, session_key, _, _ = login.client.finish_login(
        state, password, response, None
    )
    server_session_key = login.server.finish_login(server_state, finalization, None)

    assert session_key == server_session_key


def test_verify_server_public_key_helper(client, server, server_setup, password, credential_identifier):
    password_file, _ = _register_high_level(
        client, server, server_setup, password, credential_identifier
    )
    session_key, server_session_key, _, server_s_pk = _login_high_level(
        client,
        server,
        server_setup,
        password,
        credential_identifier,
        password_file,
    )

    assert session_key == server_session_key
    type(client).verify_server_public_key(server_s_pk, server_s_pk)

    with pytest.raises(InvalidLoginError):
        type(client).verify_server_public_key(server_s_pk, b"bad-key")


def test_default_key_stretching_matches_explicit_memory_constrained_registration(
    client, server, server_setup
):
    password = b"password"
    credential_identifier = b"user"
    reg_params = ClientRegistrationFinishParameters(
        None, KeyStretching("memory_constrained", None)
    )
    password_file, _ = _register_high_level(
        client, server, server_setup, password, credential_identifier, reg_params
    )

    session_key, server_session_key, _, _ = _login_high_level(
        client,
        server,
        server_setup,
        password,
        credential_identifier,
        password_file,
    )

    assert session_key == server_session_key


def test_default_key_stretching_matches_explicit_memory_constrained_login(
    client, server, server_setup
):
    password = b"password"
    credential_identifier = b"user"
    password_file, _ = _register_high_level(
        client, server, server_setup, password, credential_identifier
    )
    client_params = ClientLoginFinishParameters(
        None, None, KeyStretching("memory-constrained", None), None
    )

    session_key, server_session_key, _, _ = _login_high_level(
        client,
        server,
        server_setup,
        password,
        credential_identifier,
        password_file,
        None,
        client_params,
    )

    assert session_key == server_session_key


def test_key_stretching_accepts_js_style_aliases():
    assert KeyStretching("memory-constrained", None).variant == "memory_constrained"
    assert KeyStretching("rfc-draft-recommended", None).variant == "rfc_recommended"
