<p align="center">
  <img src="assets/icon.svg" width="160" alt="env-shield logo">
</p>

# env-shield

An encrypted local vault that replaces plaintext `.env` files.

`env-shield` — installed as the `evs` command (**E**nv **V**ault **S**hield) —
stores your environment variables in a single password-protected,
authenticated-encryption vault file and injects them **directly into a child
process's environment** at launch time. Secrets never sit on disk in
plaintext, are never exported into your shell, and are wiped from memory as
soon as they are no longer needed.

A vault holds **multiple named environments** (e.g. `dev`, `staging`,
`prod`); one of them is the default, and any command can target another with
`--env`.

```console
$ evs init
New master password: ********
Confirm master password: ********
Initialized vault at `.env-shield` with environment `default`

$ evs set DATABASE_URL                     # value entered via hidden prompt
Master password: ********
Value for DATABASE_URL: ********
Set `DATABASE_URL` in environment `default` (1 secrets)

$ evs env add staging
$ evs set DATABASE_URL --env staging

$ evs import .env                          # migrate an existing .env file
$ evs import .env.staging                  # file name targets the `staging` env

$ evs run -- npm start                     # inject the default environment
$ evs run --env staging -- npm start
$ evs env use staging                      # make staging the new default
```

## Installation

Prebuilt binaries (fastest, via [cargo-binstall](https://github.com/cargo-bins/cargo-binstall)):

```console
$ cargo binstall env-shield
```

Install script (Linux/macOS — downloads the latest release binary and
verifies its checksum):

```console
$ curl -fsSL https://raw.githubusercontent.com/dandpz/env-shield/main/install.sh | sh
```

Build from source:

```console
$ cargo install env-shield
```

Or download an archive for your platform from the
[releases page](https://github.com/dandpz/env-shield/releases) and verify it
against the `SHA256SUMS` file attached to the release. The binary inside is
named `evs`.

## Commands

| Command | Description |
|---|---|
| `init [--no-keychain]` | Create a new vault (in the working directory by default) with an empty `default` environment; if a `.gitignore` exists next to it, the vault file is appended to it. Stores the master password in the OS keychain unless `--no-keychain` is given |
| `set <KEY> [VALUE] [--env NAME]` | Add or update a secret (omit `VALUE` for a hidden prompt) |
| `import <FILE> [--env NAME]` | Import an existing `.env` file into an environment. A file named `.env.<name>` targets the environment `<name>` automatically; `--env` overrides the inference. Existing keys are overwritten |
| `view [--keys-only] [--env NAME]` | Decrypt and print an environment's contents |
| `run [--env NAME] -- <COMMAND> [ARGS...]` | Run a command with the secrets injected into its environment |
| `env list` | List environments (`*` marks the default) |
| `env add <NAME>` | Create a new, empty environment |
| `env remove <NAME>` | Delete an environment and wipe its secrets |
| `env use <NAME>` | Set the vault's default environment |
| `keychain store` | Store the master password (validated first) in the OS keychain — enables passwordless `run` for vaults created with `--no-keychain` or by older versions |
| `keychain forget` | Remove the stored master password; `run` prompts again |
| `keychain status` | Show whether a master password is stored for this vault |

A global `--vault <FILE>` flag (default: `./.env-shield`) selects the vault
file. Environments are never created implicitly: `set --env prdo` (or an
`import` whose target does not exist) fails loudly instead of silently
storing the secrets in a fresh environment.

`import` does not delete the source file — remove the plaintext `.env`
yourself once you have verified the import with `evs view`.

The `run` subcommand waits for the child and exits with the child's exact
exit code (or `128 + signal` if the child was killed by a signal on Unix),
so it is transparent to CI pipelines and process supervisors.

### Passwordless `run`

`run` is the hot path, so it does not prompt: `init` stores the master
password in the **OS keychain** (macOS Keychain, Windows Credential Manager,
or the Secret Service on Linux), and `run` reads it from there. `set` and
`view` — anything that writes the vault or reveals plaintext — always require
the password to be typed. If the keychain entry is missing (headless CI,
`--no-keychain`, after `keychain forget`) `run` falls back to prompting; if
it is stale (vault re-created with a new password) `run` prompts once and
re-syncs the entry.

## Security design

- **Encryption** — XChaCha20-Poly1305 (AEAD). Any tampering with the vault
  file fails the Poly1305 authentication check; there is no silent
  corruption or bit-flipping attack surface.
- **Key derivation** — Argon2id with OWASP-recommended defaults
  (19 MiB memory, 2 iterations). A fresh random 16-byte salt is generated on
  every save, and the 24-byte XChaCha20 nonce is large enough that random
  generation carries no practical collision risk.
- **Memory hygiene** — the derived key, the master password buffer, the
  decrypted payload, and every key/value string are zeroized on drop via the
  [`zeroize`](https://crates.io/crates/zeroize) crate. In `run`, the
  decrypted vault is wiped immediately after the child is spawned, before
  `env-shield` blocks waiting for it.
- **No environment pollution** — secrets are merged into the *child's*
  environment via `Command::envs`; they are never exported into the parent
  shell or written to any temporary file.
- **Post-exit verification** — after the child exits, `run` checks that none
  of the injected variable names are visible in env-shield's own environment
  (variables that already existed in the calling shell are excluded) and
  prints `parent environment verified clean` on stderr, or a loud warning if
  anything leaked. The child's copy of the environment is destroyed by the
  OS together with the process itself.
- **File hardening** — the vault is written atomically (temp file + rename)
  with `0600` owner-only permissions on Unix.

### Vault file format

```text
+-----------+-----------+------------+----------------------------+
| MAGIC (8) | salt (16) | nonce (24) | XChaCha20-Poly1305 payload |
+-----------+-----------+------------+----------------------------+
```

The payload is a JSON document holding the named environments and the
default's name, encrypted and authenticated as a single blob:

```json
{ "default_env": "dev", "envs": { "dev": { "KEY": "VALUE" } } }
```

Vaults written by env-shield 0.1 (a bare key/value map) are transparently
migrated into a single `default` environment on load and upgraded on the
next save.

## Known limitations

Be honest about the threat model:

- While the child is **running**, the secrets live in its environment. On
  Linux they are readable via `/proc/<pid>/environ` by the same user (and
  root). This is inherent to environment variables, not to env-shield. At
  exit the OS reclaims the process image, environment block included.
- `std::process::Command` keeps an internal copy of the variables passed via
  `.envs()`; that copy is not zeroized by the standard library.
- Rust may leave transient copies of secrets in reallocated buffers (e.g.
  during JSON parsing). `zeroize` wipes everything env-shield holds a handle
  to, but cannot wipe what the allocator already recycled.
- Memory is not `mlock`ed; under memory pressure secrets could be swapped to
  disk. Use full-disk encryption and/or encrypted swap.
- `view` prints secrets to stdout by design. Mind your terminal scrollback.
- With the default keychain integration, anyone with an unlocked session for
  your OS user can `run` commands against the vault without the master
  password (the keychain is encrypted at rest and gated by the OS login,
  but not by an extra prompt). Use `init --no-keychain` or
  `keychain forget` if you want a password on every invocation.

## Building

```console
$ cargo build --release
$ cargo test          # unit + end-to-end CLI tests
```

## License

MIT
