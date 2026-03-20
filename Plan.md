# Python Bindings Plan (PyO3)

## Goals
- Provide a robust, user-friendly Python API for OPAQUE registration and login using the existing Rust core.
- Keep cryptographic behavior aligned with upstream Rust implementation.
- Offer safe-by-default helpers (sensible defaults, explicit byte serialization boundaries, clear error mapping).
- Make packaging and installation straightforward for end users.

## Non-goals (initial phase)
- Exposing every generic/advanced Rust type (e.g., custom groups, custom KSFs) as first-class Python objects.
- Supporting all optional features on day one (e.g., all elliptic curves, KEM variants) beyond a curated set.
- Stable ABI across Rust versions (we will ship Python wheels per release).

## Proposed crate & repo layout
- Add a dedicated PyO3 crate in the repo (e.g., `python/opaque_ke_py/` or `pyo3/opaque_ke_py/`).
- Convert the root to a Cargo workspace (root remains the core crate; new member for bindings).
- Provide `pyproject.toml` + `maturin` for building wheels and editable installs.
- Document build steps in README and AGENTS when bindings land.

## Python module structure
- `opaque_ke` (top-level module)
  - `ciphersuites` (predefined suite identifiers)
  - `registration` (client/server registration APIs)
  - `login` (client/server login APIs)
  - `types` (parameter/config types, identifiers)
  - `errors` (exception hierarchy)
  - `encoding` (base64 helpers for transport/storage)
  - `client` / `server` (high-level convenience wrappers)

## Cipher suite strategy
The bindings expose multiple **fixed suites** compiled by default:
- `RISTRETTO255_SHA512` (default)
- `P256_SHA256`
- `P384_SHA384`
- `P521_SHA512`
- `ML_KEM_768_RISTRETTO255_SHA512`

The Python API accepts an optional suite string identifier and dispatches to
the matching Rust `CipherSuite` at runtime. If omitted, it defaults to
`ristretto255_sha512`.

## Data model and API design
Python should minimize handling of Rust generics by exposing **bytes** for protocol messages and **state objects** for multi-step operations.

### Core objects
- `ServerSetup`
  - `new()` -> create with OS RNG
  - `serialize()` / `deserialize(bytes)`

- `ServerRegistration` (represents password file)
  - `serialize()` / `deserialize(bytes)`

- `ClientRegistrationState`
  - `serialize()` / `deserialize(bytes)` (optional; for persistence)

- `ClientLoginState`
  - `serialize()` / `deserialize(bytes)` (optional; for persistence)

- `ServerLoginState`
  - `serialize()` / `deserialize(bytes)` (optional; for persistence)

### High-level convenience API (primary UX)
Expose `OpaqueClient` and `OpaqueServer` wrappers that validate the cipher suite name and provide a stable API surface.
Method names should mirror the JS SDK where possible:
- `OpaqueClient.start_registration(password: bytes) -> (request_bytes, ClientRegistrationState)`
- `OpaqueClient.finish_registration(state, password: bytes, response_bytes) -> (upload_bytes, export_key)`
- `OpaqueClient.start_login(password: bytes) -> (request_bytes, ClientLoginState)`
- `OpaqueClient.finish_login(state, password: bytes, response_bytes) -> (finalization_bytes, session_key, export_key, server_public_key)`
- `OpaqueClient.verify_server_public_key(expected: bytes, actual: bytes) -> None` (raises on mismatch)
- `OpaqueServer.start_registration(server_setup, request_bytes, credential_identifier: bytes) -> response_bytes`
- `OpaqueServer.finish_registration(upload_bytes) -> ServerRegistration`
- `OpaqueServer.start_login(server_setup, password_file, request_bytes, credential_identifier: bytes) -> (response_bytes, ServerLoginState)`
- `OpaqueServer.finish_login(state, finalization_bytes) -> (session_key)`

### Low-level API (explicit params)
Keep the existing explicit function set for advanced callers, but name them to mirror JS as well. Disambiguate client/server by module or namespace:
- `registration.client.start_registration(...)`
- `registration.client.finish_registration(...)`
- `registration.server.start_registration(...)`
- `registration.server.finish_registration(...)`
- `login.client.start_login(...)`
- `login.client.finish_login(...)`
- `login.server.start_login(...)`
- `login.server.finish_login(...)`

### Registration flow
- `registration.client.start_registration(password: bytes) -> (request_bytes, ClientRegistrationState)`
- `registration.server.start_registration(server_setup, request_bytes, credential_identifier: bytes) -> response_bytes`
- `registration.client.finish_registration(state, password: bytes, response_bytes, params) -> (upload_bytes, export_key)`
- `registration.server.finish_registration(upload_bytes) -> ServerRegistration`

### Login flow
- `login.client.start_login(password: bytes) -> (request_bytes, ClientLoginState)`
- `login.server.start_login(server_setup, password_file, request_bytes, credential_identifier: bytes, params) -> (response_bytes, ServerLoginState)`
- `login.client.finish_login(state, password: bytes, response_bytes, params) -> (finalization_bytes, session_key, export_key, server_public_key)`
- `login.server.finish_login(state, finalization_bytes, params) -> (session_key)`

### Parameter objects
Expose small, explicit parameter classes mirroring Rust structs:
- `Identifiers(client: Optional[bytes], server: Optional[bytes])`
- `ClientRegistrationFinishParameters(identifiers: Optional[Identifiers], key_stretching: Optional[KeyStretching])`
- `ServerLoginParameters(context: Optional[bytes], identifiers: Optional[Identifiers])`
- `ClientLoginFinishParameters(context: Optional[bytes], identifiers: Optional[Identifiers], key_stretching: Optional[KeyStretching], server_s_pk: Optional[bytes])`
- `KeyStretching(variant: Literal["memory_constrained", "rfc_recommended"], params: Optional[Argon2Params])`
  - Align defaults with JS presets; Argon2 is always enabled in the bindings.
Note: `context` is supported in both server and client login parameters; mismatches must fail.

### KSF support
Initial support should include:
- Default KSF parameters aligned with the JS memory-constrained preset.
- Optional explicit KSF configuration (Argon2 params; always enabled in the bindings).

## Serialization boundary
- Python APIs accept/return `bytes` for protocol messages and serialized state.
- State objects are opaque on the Python side; serialization is explicit.
- Any direct exposure of secrets (session keys, export keys) is returned as `bytes` with clear docs that zeroization is not guaranteed on the Python side.
- **Encoding for interop**: protocol messages are raw `bytes` in Python. Transport/storage should use base64; provide helpers:
  - `encode_b64(data: bytes) -> str`
  - `decode_b64(text: str) -> bytes`

## State handling
- State objects are **single-use** and must not be replayed; using a stale/mismatched state raises `InvalidStateError`.
- For persistence, serialize to bytes and base64-encode for storage/transport.

## Interoperability
- Explicitly document the encoding for all protocol messages and state blobs (raw bytes in Python, base64 for transport/storage).
- Cross-stack tests validate Python ↔ JS compatibility using the same `ServerSetup`, identifiers, and context strings.

## Error mapping
Create a dedicated exception hierarchy:
- `OpaqueError` (base)
  - `InvalidLoginError`
  - `InvalidStateError` (mismatched, replayed, or wrong-state usage)
  - `SerializationError`
  - `SizeError`
  - `ReflectedValueError`
  - `LibraryError`

Rust `ProtocolError` variants map 1:1 to these Python exceptions, preserving the message where possible.

## Security considerations
- Rust-side state implements `Drop + Zeroize` where available; ensure sensitive fields are zeroized when dropped.
- Avoid exposing private keys unless necessary; provide explicit opt-in if needed.
- Document that Python `bytes` are immutable and may linger in memory; recommend callers zeroize passwords on their side when possible (e.g., use `bytearray`).
- Add server public key pinning guidance for clients, with helper `OpaqueClient.verify_server_public_key(expected)` (or `verify_server_public_key(expected, actual)`), matching JS behavior.

## Build and packaging
- Use `maturin` (PyO3 recommended path):
  - `pyproject.toml` with `pyo3` and `maturin` build backend.
  - Build features in `Cargo.toml` for enabling cipher suites; Argon2 is always enabled.
- Default feature set for bindings is pinned in `python/opaque_ke_py/Cargo.toml`
  (`std`, `ristretto255`, `argon2`, `serde`, plus KEM enabled).
- Suites are compiled in by default; there are no Python-level feature toggles
  for enabling/disabling suites.
- CI should build wheels for CPython 3.11–3.13 on Linux/macOS/Windows (manylinux
  targets for Linux), AMD64 and ARM64.

Minimal `pyproject.toml` sketch (for the plan):
```toml
[build-system]
requires = ["maturin>=1.4"]
build-backend = "maturin"

[project]
name = "opaque_ke"
requires-python = ">=3.11"

[tool.maturin]
bindings = "pyo3"
module-name = "opaque_ke"
python-source = "python"
```

## Testing plan
- Python integration tests (pytest) that mirror `examples/simple_login` for happy-path registration + login.
- Round-trip serialization tests for all message types and states.
- Negative tests:
  - Invalid login (wrong password)
  - Corrupted messages (serialization errors)
  - Invalid/replayed state (InvalidStateError)
- Optional: property-based tests mirroring Rust vectors (can be added later).
- Cross-stack tests:
  - Python registration + JS login (shared server setup + identifiers).
  - JS registration + Python login (shared server setup + identifiers).

## Documentation plan
- Add Python usage docs in `README.md` or `docs/python.md`.
- Provide a minimal end-to-end example (registration + login).
- Document feature flags, supported cipher suites, and security caveats.
- Document encoding rules (bytes in Python, base64 for transport/storage), with helper usage examples.
- State handling guidance: "state is not reusable" and "serialize to bytes; base64 for storage".
  - Define lifetime expectations for state objects (single-use, per-step).

## Implementation phases
1. **Scaffold bindings crate**: create new PyO3 crate, build system, and basic module layout.
2. **Minimal API**: Ristretto255 + SHA-512 suite, registration and login flows, serialization.
3. **Error + parameter polish**: exception hierarchy, parameter objects, identifier handling.
4. **Docs + tests**: pytest suite + documentation.
5. **CI packaging**: wheel builds for supported Python/OS targets.
6. **Expanded suites (future)**: add P-256/P-384/P-521, KEM suite as optional features.

## Open questions / decisions needed
- Should additional suites be exposed at all, and if so what Python API should select them?
- Should server key material/HSM pathways be exposed in Python initially or deferred?

## Implementation timeline
1: ~~Scaffold bindings crate, minimal PyO3 module layout, and build config (maturin/pyproject).~~
2: ~~Implement minimal API (Ristretto255 + SHA-512), registration/login flows, and serialization.~~
3: ~~Error mapping, parameter objects, context support, state handling, and encoding helpers.~~
4: ~~Cross-stack JS interop tests + pytest suite + docs polish.~~
5: ~~CI packaging (wheels for 3.11–3.13).~~
6: Expand suites (P-256/P-384/P-521, KEM if enabled).

# NOTES
Everything else in this file (and in AGENTS.md) and in any commit after a85a7be is all AI-written. And the agents working on those don't know what the JS stuff is (like you, since you are also one, if you're reading this). But basically just have a file in-repo for documenting all the JS stuff that needs clarification, but continue working. Whenever it gets clarified, implement or fix anything that needs to be implemented or fixed.
