# JS interop harness

This directory contains the Node.js harness used by the Python tests to run
cross-stack interoperability checks against `@serenity-kit/opaque`.

## Setup

```sh
nvm use
npm install
```

The pytest suite will invoke `interop.mjs` when `OPAQUE_JS_INTEROP=1` is set.
The harness is pinned to Node `24.14.0` and `@serenity-kit/opaque` `1.1.0`.
