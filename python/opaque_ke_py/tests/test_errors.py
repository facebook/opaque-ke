import pytest

from opaque_ke.client import OpaqueClient
from opaque_ke.errors import (
    InvalidLoginError,
    InvalidStateError,
    SerializationError,
    SizeError,
)
from opaque_ke.server import OpaqueServer
from opaque_ke.types import ServerSetup


def test_invalid_login_wrong_password():
    client = OpaqueClient()
    server = OpaqueServer()
    server_setup = ServerSetup()
    password = b"correct-password"
    credential_identifier = b"user"

    req, reg_state = client.start_registration(password)
    resp = server.start_registration(server_setup, req, credential_identifier)
    upload, _ = client.finish_registration(reg_state, password, resp, None)
    password_file = server.finish_registration(upload)

    req, login_state = client.start_login(b"wrong-password")
    resp, server_state = server.start_login(
        server_setup, password_file, req, credential_identifier, None
    )

    with pytest.raises(InvalidLoginError):
        client.finish_login(login_state, b"wrong-password", resp, None)

    # Server state is intentionally left unused; it should be dropped safely.
    del server_state


def test_state_reuse_raises_invalid_state():
    client = OpaqueClient()
    server = OpaqueServer()
    server_setup = ServerSetup()
    password = b"password"
    credential_identifier = b"user"

    req, reg_state = client.start_registration(password)
    resp = server.start_registration(server_setup, req, credential_identifier)

    client.finish_registration(reg_state, password, resp, None)

    with pytest.raises(InvalidStateError):
        client.finish_registration(reg_state, password, resp, None)


def test_serialization_error_helpers():
    from opaque_ke.encoding import decode_b64

    with pytest.raises(SerializationError):
        decode_b64("not-base64!")


def test_corrupted_registration_upload_raises_serialization_error():
    client = OpaqueClient()
    server = OpaqueServer()
    server_setup = ServerSetup()
    password = b"password"
    credential_identifier = b"user"

    req, reg_state = client.start_registration(password)
    resp = server.start_registration(server_setup, req, credential_identifier)
    upload, _ = client.finish_registration(reg_state, password, resp, None)

    corrupted = bytearray(upload)
    corrupted[:32] = b"\x00" * 32

    with pytest.raises(SerializationError):
        server.finish_registration(bytes(corrupted))


def test_truncated_login_response_raises_size_error():
    client = OpaqueClient()
    server = OpaqueServer()
    server_setup = ServerSetup()
    password = b"password"
    credential_identifier = b"user"

    req, reg_state = client.start_registration(password)
    resp = server.start_registration(server_setup, req, credential_identifier)
    upload, _ = client.finish_registration(reg_state, password, resp, None)
    password_file = server.finish_registration(upload)

    req, login_state = client.start_login(password)
    resp, server_state = server.start_login(
        server_setup, password_file, req, credential_identifier, None
    )

    with pytest.raises(SizeError):
        client.finish_login(login_state, password, resp[:-1], None)

    # Server state is intentionally left unused; it should be dropped safely.
    del server_state


def test_state_reuse_client_login_raises_invalid_state():
    client = OpaqueClient()
    server = OpaqueServer()
    server_setup = ServerSetup()
    password = b"password"
    credential_identifier = b"user"

    req, reg_state = client.start_registration(password)
    resp = server.start_registration(server_setup, req, credential_identifier)
    upload, _ = client.finish_registration(reg_state, password, resp, None)
    password_file = server.finish_registration(upload)

    req, login_state = client.start_login(password)
    resp, server_state = server.start_login(
        server_setup, password_file, req, credential_identifier, None
    )
    finalization, session_key, _, _ = client.finish_login(
        login_state, password, resp, None
    )
    server_session_key = server.finish_login(server_state, finalization, None)

    assert session_key == server_session_key

    with pytest.raises(InvalidStateError):
        client.finish_login(login_state, password, resp, None)


def test_state_reuse_server_login_raises_invalid_state():
    client = OpaqueClient()
    server = OpaqueServer()
    server_setup = ServerSetup()
    password = b"password"
    credential_identifier = b"user"

    req, reg_state = client.start_registration(password)
    resp = server.start_registration(server_setup, req, credential_identifier)
    upload, _ = client.finish_registration(reg_state, password, resp, None)
    password_file = server.finish_registration(upload)

    req, login_state = client.start_login(password)
    resp, server_state = server.start_login(
        server_setup, password_file, req, credential_identifier, None
    )
    finalization, session_key, _, _ = client.finish_login(
        login_state, password, resp, None
    )
    server_session_key = server.finish_login(server_state, finalization, None)

    assert session_key == server_session_key

    with pytest.raises(InvalidStateError):
        server.finish_login(server_state, finalization, None)


def test_corrupted_server_setup_secret_key_raises_serialization_error():
    setup = ServerSetup()
    data = bytearray(setup.serialize())
    # ServerSetup = OPRF seed (64 bytes) + secret key (32 bytes) + public key (32 bytes).
    data[64:96] = b"\x00" * 32

    with pytest.raises(SerializationError):
        ServerSetup.deserialize(bytes(data), "ristretto255_sha512")


def test_high_level_finish_registration_wrong_suite_raises_invalid_state():
    client = OpaqueClient("p256_sha256")
    server = OpaqueServer("p256_sha256")
    server_setup = ServerSetup("p256_sha256")

    req, reg_state = client.start_registration(b"password")
    resp = server.start_registration(server_setup, req, b"user")
    upload, _ = client.finish_registration(reg_state, b"password", resp, None)

    with pytest.raises(InvalidStateError):
        OpaqueServer("p384_sha384").finish_registration(upload)


def test_deserialize_rejects_trailing_bytes():
    client = OpaqueClient()
    server = OpaqueServer()
    server_setup = ServerSetup()

    with pytest.raises(SizeError):
        ServerSetup.deserialize(server_setup.serialize() + b"junk", "ristretto255_sha512")

    req, reg_state = client.start_registration(b"password")
    resp = server.start_registration(server_setup, req, b"user")

    with pytest.raises(SizeError):
        client.finish_registration(reg_state, b"password", resp + b"junk", None)

    req, reg_state = client.start_registration(b"password")
    resp = server.start_registration(server_setup, req, b"user")
    upload, _ = client.finish_registration(reg_state, b"password", resp, None)
    with pytest.raises(SizeError):
        server.finish_registration(upload + b"junk")

    password_file = server.finish_registration(upload)
    req, login_state = client.start_login(b"password")

    with pytest.raises(SizeError):
        server.start_login(server_setup, password_file, req + b"junk", b"user", None)

    resp, server_state = server.start_login(
        server_setup, password_file, req, b"user", None
    )

    with pytest.raises(SizeError):
        client.finish_login(login_state, b"password", resp + b"junk", None)

    req, login_state = client.start_login(b"password")
    resp, server_state = server.start_login(
        server_setup, password_file, req, b"user", None
    )
    finalization, _, _, _ = client.finish_login(login_state, b"password", resp, None)
    with pytest.raises(SizeError):
        server.finish_login(server_state, finalization + b"junk", None)


def test_deserialize_requires_explicit_suite_for_ambiguous_blobs():
    with pytest.raises(ValueError, match="ambiguous ServerSetup deserialization"):
        ServerSetup.deserialize(ServerSetup().serialize())


def test_wrong_suite_client_login_state_deserialize_raises_serialization_error():
    client = OpaqueClient("p521_sha512")
    _, state = client.start_login(b"password")

    with pytest.raises(SerializationError):
        type(state).deserialize(state.serialize(), "ristretto255_sha512")
