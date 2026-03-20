from opaque_ke.client import OpaqueClient
from opaque_ke.server import OpaqueServer
from opaque_ke.types import (
    ClientLoginState,
    ClientRegistrationState,
    ServerLoginState,
    ServerRegistration,
    ServerSetup,
)

DEFAULT_SUITE = "ristretto255_sha512"


def _register(client, server, server_setup, password, credential_identifier):
    request, state = client.start_registration(password)
    response = server.start_registration(server_setup, request, credential_identifier)
    upload, _ = client.finish_registration(state, password, response, None)
    password_file = server.finish_registration(upload)
    return password_file


def test_server_setup_roundtrip():
    setup = ServerSetup()
    data = setup.serialize()
    restored = ServerSetup.deserialize(data, DEFAULT_SUITE)
    assert restored.serialize() == data


def test_server_registration_roundtrip():
    client = OpaqueClient()
    server = OpaqueServer()
    server_setup = ServerSetup()
    password_file = _register(client, server, server_setup, b"password", b"user")

    data = password_file.serialize()
    restored = ServerRegistration.deserialize(data, DEFAULT_SUITE)
    assert restored.serialize() == data


def test_client_registration_state_roundtrip():
    client = OpaqueClient()
    server = OpaqueServer()
    server_setup = ServerSetup()
    password = b"password"
    credential_identifier = b"user"

    request, state = client.start_registration(password)
    response = server.start_registration(server_setup, request, credential_identifier)
    data = state.serialize()

    restored = ClientRegistrationState.deserialize(data, DEFAULT_SUITE)
    upload, _ = client.finish_registration(restored, password, response, None)
    server.finish_registration(upload)


def test_client_login_state_roundtrip():
    client = OpaqueClient()
    server = OpaqueServer()
    server_setup = ServerSetup()
    password = b"password"
    credential_identifier = b"user"
    password_file = _register(client, server, server_setup, password, credential_identifier)

    request, state = client.start_login(password)
    response, server_state = server.start_login(
        server_setup, password_file, request, credential_identifier, None
    )
    data = state.serialize()

    restored = ClientLoginState.deserialize(data, DEFAULT_SUITE)
    finalization, session_key, _, _ = client.finish_login(
        restored, password, response, None
    )
    server_session_key = server.finish_login(server_state, finalization, None)
    assert session_key == server_session_key


def test_server_login_state_roundtrip():
    client = OpaqueClient()
    server = OpaqueServer()
    server_setup = ServerSetup()
    password = b"password"
    credential_identifier = b"user"
    password_file = _register(client, server, server_setup, password, credential_identifier)

    request, state = client.start_login(password)
    response, server_state = server.start_login(
        server_setup, password_file, request, credential_identifier, None
    )
    data = server_state.serialize()

    restored = ServerLoginState.deserialize(data, DEFAULT_SUITE)
    finalization, session_key, _, _ = client.finish_login(
        state, password, response, None
    )
    server_session_key = server.finish_login(restored, finalization, None)
    assert session_key == server_session_key
