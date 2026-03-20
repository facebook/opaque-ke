# JS Interop Clarifications

This file tracks questions and clarifications needed to align the Python bindings with the JS SDK.
Add open items here and link to the resolution once confirmed.

## Resolved items for step 4 (JS interop tests)
- JS SDK target: `@serenity-kit/opaque`.
- JS API reference: `docs/JS_README.md`.
- Encoding: JS protocol messages/state blobs are opaque strings that are base64url (URL-safe, no padding). Python should base64url-encode bytes when sending to JS and decode on receipt.
- `ServerSetup`/server public key exchange: treat as opaque strings; transport/store as UTF-8 strings without double-encoding.
- Identifiers/context fixtures: client identifier `opaque-test-client@example.com`, server identifier `opaque-test-server@example.org`, context `opaque-ke-py-test`. Cover two cases: with identifiers + context and without.
- Runtime constraints: Node `24.14.0`, ESM.
- JS interop dependency pin: `@serenity-kit/opaque` `1.1.0`.
- JS fixtures location: repo-local `python/opaque_ke_py/tests/js/`.
