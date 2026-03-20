# opaque-ke Python bindings

These bindings expose a Python API for the Rust `opaque-ke` implementation using PyO3.
They default to the Ristretto255 + SHA-512 suite and provide both high-level and low-level APIs.
See `docs/python.md` in the repo root for additional details.

## Local development install

From this directory:

```sh
.venv/bin/python -m pip install -U pip
.venv/bin/python -m maturin develop
```

## Quick start (high-level API)

```python
from opaque_ke.client import OpaqueClient
from opaque_ke.server import OpaqueServer
from opaque_ke.types import ServerSetup

client = OpaqueClient()
server = OpaqueServer()
server_setup = ServerSetup()

password = b"correct horse battery staple"
credential_identifier = b"user@example.com"

# Registration
reg_request, reg_state = client.start_registration(password)
reg_response = server.start_registration(server_setup, reg_request, credential_identifier)
upload, export_key = client.finish_registration(reg_state, password, reg_response, None)
password_file = server.finish_registration(upload)

# Login
login_request, login_state = client.start_login(password)
login_response, server_state = server.start_login(
    server_setup, password_file, login_request, credential_identifier, None
)
finalization, session_key, export_key, server_s_pk = client.finish_login(
    login_state, password, login_response, None
)
server_session_key = server.finish_login(server_state, finalization, None)

assert session_key == server_session_key
```

## Notes

- Supported cipher suites: `ristretto255_sha512`, `p256_sha256`, `p384_sha384`,
  `p521_sha512`, `ml_kem_768_ristretto255_sha512`
  (see `opaque_ke.ciphersuites.available()`).
- Wheels target CPython 3.11 through 3.14 on Linux, macOS, and Windows for AMD64 and ARM64.
- If no suite is provided, the default is `ristretto255_sha512`.
- Protocol messages and state blobs are bytes in Python. Use base64 helpers for transport:
  `opaque_ke.encoding.encode_b64` returns URL-safe base64 without padding, and
  `opaque_ke.encoding.decode_b64` accepts URL-safe or standard base64 with or without padding.
- Persist the cipher suite alongside serialized `ServerSetup`, `ServerRegistration`, and `*State`
  blobs, and pass it back to `deserialize(...)`. These blobs do not encode the suite for you.
- Key stretching uses Argon2 and is always enabled in the bindings. When omitted,
  the client uses the JS-compatible memory-constrained preset by default.
- `KeyStretching` accepts both Python-style names (`memory_constrained`,
  `rfc_recommended`) and JS-style aliases (`memory-constrained`,
  `rfc-draft-recommended`).
- State objects are single-use. Reusing a state raises `InvalidStateError`.
- Errors raised by the core library are mapped to `opaque_ke.errors` exceptions.
- Python `bytes` are immutable and not zeroized; keep secret data lifetimes short.

## Running tests

```sh
.venv/bin/python -m pytest
```

JS interop tests are gated behind `OPAQUE_JS_INTEROP=1` and use the harness in
`python/opaque_ke_py/tests/js/`. The checked-in harness pins Node `24.14.0` and
`@serenity-kit/opaque` `1.1.0`.
