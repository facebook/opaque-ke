# Repository Guidelines

## Fork Purpose & Scope
This fork’s primary goal is to add robust, user-friendly, and secure Python bindings using PyO3 while keeping the Rust core aligned with upstream.

## Project Structure & Module Organization
- `src/` holds the Rust library implementation and module tree. Avoid modifications here.
- `tests/` contains integration tests (e.g., `migration.rs`, `remote_key.rs`).
- `benches/` hosts Criterion benchmarks (see `opaque` bench target).
- `examples/` provides runnable usage samples (e.g., `simple_login`).
- `scripts/` includes helper expect scripts for demo flows.
- Project config lives in `Cargo.toml`, with tooling settings in `rustfmt.toml`, `clippy.toml`, `taplo.toml`, and `deny.toml`.
- `python/opaque_ke_py/` hosts the PyO3 bindings crate and `pyproject.toml` for maturin builds. Focus contributions here.

## Build, Test, and Development Commands
- `cargo fmt` — format Rust code per `rustfmt.toml`.
- `cargo clippy --all-targets --all-features` — lint with project Clippy settings.
- `cargo check` — check for compilation errors.
- `cargo build` — compile the library.
- `cargo test` — run unit + integration tests.
- `cargo test --all-features` — exercise feature-gated code paths.
- `cargo bench` — run Criterion benchmarks in `benches/`.
- `cd python/opaque_ke_py && maturin develop` — build and install the Python extension locally.
- `cd python/opaque_ke_py && maturin build` — build Python wheels.

## Coding Style & Naming Conventions
- Rust 2024 edition; follow `rustfmt.toml` (doc comment and string formatting enabled, Unix newlines).
- Naming follows standard Rust conventions: `snake_case` for functions/modules, `CamelCase` for types.
- Keep feature flags organized in `Cargo.toml` and document new ones in the README/examples if user-facing.
- TOML files should be formatted with Taplo (`taplo.toml`).

## Testing Guidelines
- Use Rust’s built-in test harness; add unit tests alongside modules and integration tests under `tests/`.
- Property-based tests use `proptest` (dev-dependency). Name tests descriptively for the behavior covered.
- Run `cargo test` locally; use `--all-features` when modifying feature-gated code.

## Commit & Pull Request Guidelines
- Commit messages in this repo are short, action-oriented, and often include the PR number if applicable, e.g., `Adding ml-kem re-export (#414)`.
- PRs: branch from `main`, add tests for new behavior, update docs for API changes, and ensure the test suite passes.
- If contributing back to upstream, follow its CLA and contribution requirements.
- Security issues should be reported via the Facebook whitehat program, not public issues.

## Security & Configuration Notes
- MSRV is Rust 1.85 (see `Cargo.toml`).
- Dependency policy is tracked in `deny.toml` (optional: `cargo deny check`).
- The root crate in `Cargo.toml` is dual-licensed under `Apache-2.0 OR MIT`, while the Python bindings crate in `python/opaque_ke_py` is MIT-only.

## Agent-Specific Instructions
- If a Python virtual environment exists in the repo, use it instead of system Python.
- Avoid destructive git commands unless explicitly requested.
