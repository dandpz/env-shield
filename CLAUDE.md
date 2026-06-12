# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

env-shield is a Rust CLI (installed as `evs`) that stores environment variables in an encrypted vault file and injects them into a child process's environment at launch. The crate is named `env-shield` but the binary is `evs` (see `[[bin]]` in Cargo.toml).

## Commands

```sh
make check        # everything CI runs: fmt-check + clippy (-D warnings) + tests — use before pushing
make test         # cargo test (unit + end-to-end CLI tests)
make lint         # cargo clippy --all-targets -- -D warnings
make fmt          # cargo fmt
make msrv         # verify MSRV (1.85) compiles

cargo test save_load_roundtrip          # run a single test by name
cargo test --test cli                   # run only the e2e CLI tests
```

CI (`.github/workflows/ci.yml`) runs fmt-check, clippy with warnings denied, tests on Linux + macOS, and an MSRV (1.85) check. Clippy `pedantic` is enabled as warnings via Cargo.toml lints; `unsafe_code` is forbidden.

## Releases

Fully automated via release-plz; never bump the version or tag by hand.

- Conventional commits land on `main` → `release-plz.yml` opens/updates a release PR (version bump + `CHANGELOG.md`). Merging that PR publishes to crates.io and pushes tag `v{version}`.
- The tag triggers `release.yml`, which builds 6 targets and attaches archives + `SHA256SUMS` to a GitHub Release. `release-plz.toml` sets `git_release_enable = false` so release-plz doesn't create a duplicate release.
- The binary name `evs` is coupled in three places: `[[bin]]` in Cargo.toml, the Package step in `release.yml` (`cp .../release/evs`), and `[package.metadata.binstall] bin-dir`. The archive naming `env-shield-{version}-{target}` is likewise coupled between `release.yml`, the binstall `pkg-url`/`bin-dir`, and `install.sh`. Change any of these together.
- Secrets: `RELEASE_PLZ_TOKEN` (fine-grained PAT — the default `GITHUB_TOKEN` cannot push tags that trigger other workflows). crates.io auth uses trusted publishing (OIDC via `rust-lang/crates-io-auth-action`); there is no registry token to rotate.

## Architecture

Four modules, layered with no cycles:

- `src/cli.rs` — clap derive definitions only, no logic.
- `src/main.rs` — command dispatch and all user interaction (prompts, printing). Each subcommand is a `cmd_*` function.
- `src/vault.rs` — vault file format, multi-environment data model (`Vault` holds named `Secrets` maps plus a default-env name), atomic persistence (temp file + rename, `0600` on Unix), and transparent migration of the legacy 0.1 single-map payload.
- `src/crypto.rs` — Argon2id key derivation + XChaCha20-Poly1305 AEAD. Every `save` uses a fresh random salt and nonce.
- `src/dotenv.rs` — minimal `.env` parser for `evs import` (KEY=VALUE, comments, `export ` prefix, quote stripping; no expansion). Its errors report line numbers only, never line content, since lines may hold secret values.
- `src/keychain.rs` — OS keychain storage of the master password, keyed by canonicalized vault path. `get` returns `Option` so callers fall back to prompting; only `run` reads the keychain — `set`/`view` always prompt by design.

Vault file layout: `MAGIC(8) | salt(16) | nonce(24) | ciphertext` where the plaintext is JSON `{ "default_env": ..., "envs": { name: { KEY: VALUE } } }`.

## Security invariants

These are deliberate design properties — preserve them when changing code:

- Every secret-holding value (passwords, derived keys, decrypted payloads, `Secrets` maps) is zeroized on drop (`Zeroizing`, `ZeroizeOnDrop`, or the manual `Zeroize for Secrets` impl). New code holding secrets must do the same.
- `main` calls `std::process::exit` only after `dispatch` returns, because `exit` skips destructors — secrets must already be dropped/zeroized by then.
- In `cmd_run`, the decrypted vault is dropped immediately after the child is spawned, before blocking on `wait()`. After the child exits, a leak check verifies no injected variable appears in the parent's own environment.
- Secrets are injected only via `Command::envs` into the child; never exported into env-shield's own environment and never written to disk in plaintext.
- Environments are never created implicitly — a typo'd `--env` name fails with `NoSuchEnv` instead of silently creating a fresh environment.
- Vault writes are atomic and `0600`; the temp file is `<vault>.tmp` in the same directory.

## Testing notes

- E2e tests (`tests/cli.rs`) drive the compiled binary via `env!("CARGO_BIN_EXE_evs")`, piping passwords through stdin (the password prompt falls back to a plain line read when stdin is not a terminal).
- Tests must always use `init --no-keychain` so they never touch the developer's real OS keychain.
- Tests that spawn `sh`/`true` as the child are gated `#[cfg(unix)]`.
