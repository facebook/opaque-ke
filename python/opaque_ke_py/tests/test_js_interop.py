import base64
import json
import os
import re
import subprocess
from pathlib import Path

import pytest

from opaque_ke.client import OpaqueClient
from opaque_ke.server import OpaqueServer
from opaque_ke.types import (
    ClientRegistrationFinishParameters,
    Identifiers,
    ServerRegistration,
    ServerSetup,
)

OPAQUE_JS_INTEROP = os.getenv("OPAQUE_JS_INTEROP")

if not OPAQUE_JS_INTEROP:
    pytest.skip(
        "Set OPAQUE_JS_INTEROP=1 and configure JS harness to run interop tests",
        allow_module_level=True,
    )

BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def assert_base64url(value: str) -> None:
    assert "=" not in value
    assert BASE64URL_RE.match(value)


def js_call(action: str, **kwargs):
    node = os.getenv("OPAQUE_JS_NODE", "node")
    harness = Path(__file__).parent / "js" / "interop.mjs"
    if not harness.exists():
        pytest.skip("JS interop harness missing", allow_module_level=True)

    payload = {"action": action, "args": kwargs}
    try:
        result = subprocess.run(
            [node, str(harness)],
            input=json.dumps(payload).encode("utf-8"),
            capture_output=True,
            check=False,
            cwd=harness.parent,
        )
    except FileNotFoundError as exc:
        pytest.skip(f"Node not available: {exc}", allow_module_level=True)

    if not result.stdout:
        raise AssertionError(
            {
                "action": action,
                "returncode": result.returncode,
                "stderr": result.stderr.decode("utf-8", errors="replace"),
            }
        )

    data = json.loads(result.stdout.decode("utf-8"))
    if not data.get("ok"):
        if data.get("error") == "missing_dependency":
            pytest.skip(
                "@serenity-kit/opaque is not installed in python/opaque_ke_py/tests/js",
                allow_module_level=True,
            )
        raise AssertionError(data)
    if result.returncode != 0:
        raise AssertionError(
            {
                "action": action,
                "returncode": result.returncode,
                "stderr": result.stderr.decode("utf-8", errors="replace"),
                "result": data,
            }
        )
    return data["result"]


PASSWORD_BYTES = b"interop-password"
PASSWORD_STR = PASSWORD_BYTES.decode("ascii")
USER_IDENTIFIER = "opaque-user-123"
CLIENT_IDENTIFIER_BYTES = b"opaque-test-client@example.com"
SERVER_IDENTIFIER_BYTES = b"opaque-test-server@example.org"
IDENTIFIERS_JS = {
    "client": CLIENT_IDENTIFIER_BYTES.decode("ascii"),
    "server": SERVER_IDENTIFIER_BYTES.decode("ascii"),
}
CONTEXT_STR = "opaque-ke-py-test"
DEFAULT_SUITE = "ristretto255_sha512"


def test_python_registration_js_login_with_context_and_identifiers():
    client = OpaqueClient()

    server_setup = ServerSetup()
    server_setup_str = b64url_encode(server_setup.serialize())
    assert_base64url(server_setup_str)

    request_bytes, state = client.start_registration(PASSWORD_BYTES)
    request_str = b64url_encode(request_bytes)

    response = js_call(
        "serverCreateRegistrationResponse",
        serverSetup=server_setup_str,
        userIdentifier=USER_IDENTIFIER,
        registrationRequest=request_str,
    )
    registration_response = response["registrationResponse"]
    assert_base64url(registration_response)

    identifiers = Identifiers(
        client=CLIENT_IDENTIFIER_BYTES, server=SERVER_IDENTIFIER_BYTES
    )
    reg_params = ClientRegistrationFinishParameters(identifiers, None)
    upload_bytes, _ = client.finish_registration(
        state,
        PASSWORD_BYTES,
        b64url_decode(registration_response),
        reg_params,
    )

    registration_record = b64url_encode(upload_bytes)
    assert_base64url(registration_record)

    login_start = js_call(
        "clientStartLogin",
        password=PASSWORD_STR,
    )
    assert_base64url(login_start["clientLoginState"])
    assert_base64url(login_start["startLoginRequest"])

    login_response = js_call(
        "serverStartLogin",
        userIdentifier=USER_IDENTIFIER,
        registrationRecord=registration_record,
        serverSetup=server_setup_str,
        startLoginRequest=login_start["startLoginRequest"],
        identifiers=IDENTIFIERS_JS,
        context=CONTEXT_STR,
    )
    assert_base64url(login_response["loginResponse"])
    assert_base64url(login_response["serverLoginState"])

    login_finish = js_call(
        "clientFinishLogin",
        clientLoginState=login_start["clientLoginState"],
        loginResponse=login_response["loginResponse"],
        password=PASSWORD_STR,
        identifiers=IDENTIFIERS_JS,
        context=CONTEXT_STR,
    )
    assert_base64url(login_finish["finishLoginRequest"])
    assert_base64url(login_finish["sessionKey"])

    server_finish = js_call(
        "serverFinishLogin",
        finishLoginRequest=login_finish["finishLoginRequest"],
        serverLoginState=login_response["serverLoginState"],
        context=CONTEXT_STR,
    )
    assert_base64url(server_finish["sessionKey"])

    assert login_finish["sessionKey"] == server_finish["sessionKey"]


def test_js_registration_python_login_baseline():
    server = OpaqueServer()

    server_setup = js_call("createServerSetup")
    server_setup_str = server_setup["serverSetup"]
    assert_base64url(server_setup_str)

    reg_start = js_call(
        "clientStartRegistration",
        password=PASSWORD_STR,
    )
    assert_base64url(reg_start["clientRegistrationState"])
    assert_base64url(reg_start["registrationRequest"])

    reg_response = js_call(
        "serverCreateRegistrationResponse",
        serverSetup=server_setup_str,
        userIdentifier=USER_IDENTIFIER,
        registrationRequest=reg_start["registrationRequest"],
    )
    assert_base64url(reg_response["registrationResponse"])

    reg_finish = js_call(
        "clientFinishRegistration",
        clientRegistrationState=reg_start["clientRegistrationState"],
        registrationResponse=reg_response["registrationResponse"],
        password=PASSWORD_STR,
    )
    assert_base64url(reg_finish["registrationRecord"])

    server_setup_py = ServerSetup.deserialize(
        b64url_decode(server_setup_str), DEFAULT_SUITE
    )
    password_file = ServerRegistration.deserialize(
        b64url_decode(reg_finish["registrationRecord"]), DEFAULT_SUITE
    )

    start_login = js_call(
        "clientStartLogin",
        password=PASSWORD_STR,
    )
    assert_base64url(start_login["clientLoginState"])
    assert_base64url(start_login["startLoginRequest"])

    response_bytes, server_state = server.start_login(
        server_setup_py,
        password_file,
        b64url_decode(start_login["startLoginRequest"]),
        USER_IDENTIFIER.encode("ascii"),
        None,
    )

    finish_login = js_call(
        "clientFinishLogin",
        clientLoginState=start_login["clientLoginState"],
        loginResponse=b64url_encode(response_bytes),
        password=PASSWORD_STR,
    )
    assert_base64url(finish_login["finishLoginRequest"])
    assert_base64url(finish_login["sessionKey"])

    session_key = server.finish_login(
        server_state, b64url_decode(finish_login["finishLoginRequest"]), None
    )

    assert session_key == b64url_decode(finish_login["sessionKey"])
