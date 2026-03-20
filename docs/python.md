# Python bindings

The `opaque-ke` Python bindings expose a high-level API (`OpaqueClient`/`OpaqueServer`)
plus lower-level functions that mirror the JS SDK naming. The default suite is
`ristretto255_sha512`, with optional support for additional suites listed below.

## Supported cipher suites

The bindings compile multiple suites by default. You can list them with
`opaque_ke.ciphersuites.available()`:

- `ristretto255_sha512` (default)
- `p256_sha256`
- `p384_sha384`
- `p521_sha512`
- `ml_kem_768_ristretto255_sha512`

Most APIs accept an optional `suite` string. For deserialization helpers such as
`ServerSetup.deserialize(...)`, `ServerRegistration.deserialize(...)`, and the
`*State.deserialize(...)` methods, you should pass the suite that produced the
blob. These serialized blobs are not self-describing, so omitting `suite` is
only safe when the bytes uniquely match a single supported suite.

## Build configuration

The bindings are built with the `opaque-ke` features `std`, `ristretto255`, `argon2`,
`serde`, and `kem` (see `python/opaque_ke_py/Cargo.toml`). Argon2 is always enabled in
the bindings to support key stretching. Suite selection happens at runtime using the
suite identifier strings above; if no suite is provided, `ristretto255_sha512` is used.

Wheels are built for CPython 3.11 through 3.14 on Linux, macOS, and Windows for both
AMD64 and ARM64.

Client-side key stretching defaults to the JS-compatible memory-constrained Argon2 preset
when omitted. `KeyStretching` accepts both the Python spellings
`memory_constrained` / `rfc_recommended` and the JS spellings
`memory-constrained` / `rfc-draft-recommended`.

## Install (local dev)

```sh
.venv/bin/python -m pip install -U pip
cd python/opaque_ke_py
.venv/bin/python -m maturin develop
```

## High-level API

```python
from opaque_ke.client import OpaqueClient
from opaque_ke.server import OpaqueServer
from opaque_ke.types import ServerSetup

client = OpaqueClient()
server = OpaqueServer()
server_setup = ServerSetup()

password = b"password"
credential_identifier = b"user@example.com"

# Registration
req, reg_state = client.start_registration(password)
resp = server.start_registration(server_setup, req, credential_identifier)
upload, export_key = client.finish_registration(reg_state, password, resp, None)
password_file = server.finish_registration(upload)

# Login
req, login_state = client.start_login(password)
resp, server_state = server.start_login(
    server_setup, password_file, req, credential_identifier, None
)
finalization, session_key, export_key, server_s_pk = client.finish_login(
    login_state, password, resp, None
)
server_session_key = server.finish_login(server_state, finalization, None)

assert session_key == server_session_key

# Specify an alternate suite (example)
client = OpaqueClient("p256_sha256")
server = OpaqueServer("p256_sha256")
server_setup = ServerSetup("p256_sha256")
```

## Low-level API

```python
from opaque_ke import registration, login
from opaque_ke.types import ServerSetup

server_setup = ServerSetup()
password = b"password"
credential_identifier = b"user@example.com"

req, reg_state = registration.client.start_registration(password)
resp = registration.server.start_registration(server_setup, req, credential_identifier)
upload, _ = registration.client.finish_registration(reg_state, password, resp, None)
password_file = registration.server.finish_registration(upload)

req, login_state = login.client.start_login(password)
resp, server_state = login.server.start_login(
    server_setup, password_file, req, credential_identifier, None
)
finalization, session_key, _, _ = login.client.finish_login(
    login_state, password, resp, None
)
server_session_key = login.server.finish_login(server_state, finalization, None)

assert session_key == server_session_key

# Low-level calls accept an optional suite identifier:
# registration.client.start_registration(password, suite="p256_sha256")
```

## Parameters, identifiers, and context

Use the parameter objects in `opaque_ke.types` when you need identifiers, context,
key stretching (Argon2), or server public key pinning:

```python
from opaque_ke.types import (
    Identifiers,
    ClientRegistrationFinishParameters,
    ServerLoginParameters,
    ClientLoginFinishParameters,
)

identifiers = Identifiers(client=b"client", server=b"server")
reg_params = ClientRegistrationFinishParameters(identifiers, None)

context = b"opaque-python"
server_params = ServerLoginParameters(context, identifiers)
client_params = ClientLoginFinishParameters(context, identifiers, None, None)
```

## Encoding helpers

Protocol messages are bytes. Use base64 helpers for storage/transport:

```python
from opaque_ke.encoding import encode_b64, decode_b64

encoded = encode_b64(b"payload")
assert decode_b64(encoded) == b"payload"
```

## State handling

State objects are single-use. Reusing a state will raise `InvalidStateError`.
To persist across processes, serialize to bytes and store with base64.

## Security notes

- Python `bytes` are immutable and are not zeroized; treat them as sensitive and
  minimize their lifetime where possible.
- State objects and serialized blobs should be protected like other secrets.
- For server public key pinning, compare the expected key with the one returned
  from `client.finish_login`:

```python
OpaqueClient.verify_server_public_key(expected_server_s_pk, server_s_pk)
```

## Error mapping

Errors map to `opaque_ke.errors`:

- `OpaqueError` (base class)
- `InvalidLoginError`
- `InvalidStateError`
- `SerializationError`
- `SizeError`
- `ReflectedValueError`
- `LibraryError`

## Testing

```sh
cd python/opaque_ke_py
.venv/bin/python -m pytest
```

### JS interop tests

Interop tests are gated behind `OPAQUE_JS_INTEROP=1` and run against
`@serenity-kit/opaque` using the repo-local JS harness in
`python/opaque_ke_py/tests/js/`.

```sh
cd python/opaque_ke_py/tests/js
nvm use
npm install

cd ../../../../
OPAQUE_JS_INTEROP=1 .venv/bin/python -m pytest python/opaque_ke_py/tests/test_js_interop.py
```

The checked-in harness pins Node `24.14.0` and `@serenity-kit/opaque` `1.1.0`.
