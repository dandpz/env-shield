//! End-to-end tests driving the compiled binary through its CLI.
//!
//! Passwords are piped via stdin (env-shield falls back to a plain line
//! read when stdin is not a terminal).

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const PW: &str = "test-password\n";
const PW_TWICE: &str = "test-password\ntest-password\n";

fn run(vault: &Path, args: &[&str], stdin_data: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_evs"))
        .arg("--vault")
        .arg(vault)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn env-shield");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(stdin_data.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn setup_vault(vault: &Path) {
    // --no-keychain: tests must never touch the developer's real OS keychain,
    // and `run` must exercise the prompt fallback path.
    assert!(
        run(vault, &["init", "--no-keychain"], PW_TWICE)
            .status
            .success()
    );
    assert!(
        run(vault, &["set", "GREETING", "hello-default"], PW)
            .status
            .success()
    );
    assert!(run(vault, &["env", "add", "staging"], PW).status.success());
    assert!(
        run(
            vault,
            &["set", "GREETING", "hello-staging", "--env", "staging"],
            PW
        )
        .status
        .success()
    );
}

// Tests below spawn `sh`/`true` as the child command, so they are
// Unix-only; the vault/init/view tests further down run everywhere.
#[cfg(unix)]
#[test]
fn multi_env_selection_and_default_switching() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    setup_vault(&vault);

    // Default environment is injected when no flag is given.
    let out = run(
        &vault,
        &["run", "--", "sh", "-c", "printf %s \"$GREETING\""],
        PW,
    );
    assert_eq!(stdout(&out), "hello-default");

    // --env selects a different environment for one invocation.
    let out = run(
        &vault,
        &[
            "run",
            "--env",
            "staging",
            "--",
            "sh",
            "-c",
            "printf %s \"$GREETING\"",
        ],
        PW,
    );
    assert_eq!(stdout(&out), "hello-staging");

    // `env use` changes the default persistently.
    assert!(run(&vault, &["env", "use", "staging"], PW).status.success());
    let out = run(
        &vault,
        &["run", "--", "sh", "-c", "printf %s \"$GREETING\""],
        PW,
    );
    assert_eq!(stdout(&out), "hello-staging");

    // `env list` marks the default.
    let out = run(&vault, &["env", "list"], PW);
    let listing = stdout(&out);
    assert!(listing.contains("* staging"), "listing was: {listing}");
    assert!(listing.contains("  default"), "listing was: {listing}");
}

#[cfg(unix)]
#[test]
fn child_env_is_cleaned_up_after_exit() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    setup_vault(&vault);

    // Sanity: the variable must not exist before the run...
    assert!(std::env::var_os("GREETING").is_none());

    // ...the child sees it during the run...
    let out = run(
        &vault,
        &["run", "--", "sh", "-c", "printf %s \"$GREETING\""],
        PW,
    );
    assert_eq!(stdout(&out), "hello-default");

    // ...env-shield itself verified its own environment stayed clean...
    assert!(
        stderr(&out).contains("parent environment verified clean"),
        "stderr was: {}",
        stderr(&out)
    );

    // ...and after the child exited, the variable exists nowhere upstream:
    // not in this (grandparent) process...
    assert!(std::env::var_os("GREETING").is_none());

    // ...and not in a fresh process spawned without env-shield.
    let probe = Command::new("sh")
        .arg("-c")
        .arg("printf %s \"${GREETING:-unset}\"")
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&probe.stdout), "unset");
}

#[cfg(unix)]
#[test]
fn child_exit_code_is_propagated() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    setup_vault(&vault);

    let out = run(&vault, &["run", "--", "sh", "-c", "exit 42"], PW);
    assert_eq!(out.status.code(), Some(42));
}

#[cfg(unix)]
#[test]
fn unknown_environment_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    setup_vault(&vault);

    let out = run(&vault, &["run", "--env", "prod", "--", "true"], PW);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("does not exist"),
        "stderr was: {}",
        stderr(&out)
    );

    // Same for `set` — environments are never created implicitly (a typo
    // must not silently send a secret to a fresh environment).
    let out = run(&vault, &["set", "KEY", "value", "--env", "prdo"], PW);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("does not exist"));
}

#[test]
fn init_appends_vault_to_existing_gitignore() {
    let dir = tempfile::tempdir().unwrap();
    let gitignore = dir.path().join(".gitignore");
    std::fs::write(&gitignore, "target/\n").unwrap();

    let vault = dir.path().join(".env-shield");
    let out = run(&vault, &["init", "--no-keychain"], PW_TWICE);
    assert!(out.status.success());
    assert!(stdout(&out).contains("Added vault to .gitignore"));

    let content = std::fs::read_to_string(&gitignore).unwrap();
    assert!(content.contains("target/"), "existing entries preserved");
    assert!(content.lines().any(|l| l == ".env-shield"));
    assert!(content.lines().any(|l| l == ".env-shield.tmp"));
}

#[test]
fn init_without_gitignore_does_not_create_one() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join(".env-shield");
    let out = run(&vault, &["init", "--no-keychain"], PW_TWICE);
    assert!(out.status.success());
    assert!(!stdout(&out).contains(".gitignore"));
    assert!(!dir.path().join(".gitignore").exists());
}

#[test]
fn view_shows_selected_environment() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    setup_vault(&vault);

    let out = run(&vault, &["view"], PW);
    assert_eq!(stdout(&out), "GREETING=hello-default\n");

    let out = run(&vault, &["view", "--env", "staging"], PW);
    assert_eq!(stdout(&out), "GREETING=hello-staging\n");

    let out = run(&vault, &["view", "--keys-only"], PW);
    assert_eq!(stdout(&out), "GREETING\n");
}
