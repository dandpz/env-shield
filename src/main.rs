//! env-shield: an encrypted local vault that replaces plaintext .env files.

mod cli;
mod crypto;
mod dotenv;
mod keychain;
mod vault;

use std::io::IsTerminal;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::Parser;
use zeroize::{Zeroize, Zeroizing};

use cli::{Cli, Commands, EnvAction, KeychainAction};
use vault::Vault;

fn main() {
    let cli = Cli::parse();
    let code = match dispatch(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("evs: {err:#}");
            1
        }
    };
    // process::exit skips destructors, so it must only run after every
    // secret-holding value (key, password, decrypted vault) has been dropped
    // and zeroized inside dispatch().
    std::process::exit(code);
}

fn dispatch(cli: Cli) -> Result<i32> {
    match cli.command {
        Commands::Init { no_keychain } => cmd_init(&cli.vault, no_keychain).map(|()| 0),
        Commands::Set { key, value, env } => {
            cmd_set(&cli.vault, key, value, env.as_deref()).map(|()| 0)
        }
        Commands::Import { file, env } => cmd_import(&cli.vault, &file, env.as_deref()).map(|()| 0),
        Commands::View { keys_only, env } => {
            cmd_view(&cli.vault, keys_only, env.as_deref()).map(|()| 0)
        }
        Commands::Run { env, command } => cmd_run(&cli.vault, env.as_deref(), &command),
        Commands::Env { action } => cmd_env(&cli.vault, action).map(|()| 0),
        Commands::Keychain { action } => cmd_keychain(&cli.vault, action).map(|()| 0),
    }
}

fn cmd_init(vault_path: &Path, no_keychain: bool) -> Result<()> {
    if vault_path.exists() {
        bail!("vault already exists at `{}`", vault_path.display());
    }
    let password = prompt_password("New master password: ")?;
    if password.is_empty() {
        bail!("master password must not be empty");
    }
    let confirm = prompt_password("Confirm master password: ")?;
    if *password != *confirm {
        bail!("passwords do not match");
    }
    vault::save(vault_path, password.as_bytes(), &Vault::default())?;
    println!(
        "Initialized vault at `{}` with environment `{}`",
        vault_path.display(),
        vault::DEFAULT_ENV
    );
    if ensure_gitignored(vault_path)? {
        println!("Added vault to .gitignore");
    }
    if no_keychain {
        println!("Keychain skipped; `run` will prompt for the master password");
    } else if keychain::store(vault_path, &password).is_ok() {
        println!(
            "Master password stored in the OS keychain; `run` will not prompt \
             (undo with `evs keychain forget`)"
        );
    } else {
        eprintln!("evs: no usable OS keychain; `run` will prompt for the master password");
    }
    Ok(())
}

/// If a `.gitignore` exists next to the vault, makes sure the vault file
/// (and its atomic-write temp file) are listed in it. Returns whether the
/// file was modified. A missing `.gitignore` is left alone.
fn ensure_gitignored(vault_path: &Path) -> Result<bool> {
    let dir = match vault_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let gitignore = dir.join(".gitignore");
    if !gitignore.exists() {
        return Ok(false);
    }

    let name = vault_path
        .file_name()
        .context("vault path has no file name")?
        .to_string_lossy();
    let content = std::fs::read_to_string(&gitignore)
        .with_context(|| format!("failed to read `{}`", gitignore.display()))?;

    let missing: Vec<String> = [name.to_string(), format!("{name}.tmp")]
        .into_iter()
        .filter(|entry| {
            !content
                .lines()
                .any(|line| line.trim() == entry || line.trim() == format!("/{entry}"))
        })
        .collect();
    if missing.is_empty() {
        return Ok(false);
    }

    let mut updated = content;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str("\n# env-shield vault\n");
    for entry in &missing {
        updated.push_str(entry);
        updated.push('\n');
    }
    std::fs::write(&gitignore, updated)
        .with_context(|| format!("failed to update `{}`", gitignore.display()))?;
    Ok(true)
}

fn cmd_set(vault_path: &Path, key: String, value: Option<String>, env: Option<&str>) -> Result<()> {
    if key.is_empty() || key.contains('=') || key.contains('\0') {
        bail!("invalid variable name `{key}`");
    }
    let password = prompt_password("Master password: ")?;
    let mut vault = vault::load(vault_path, password.as_bytes())?;
    let env_name = vault.resolve_name(env).to_string();

    let value = match value {
        Some(v) => Zeroizing::new(v),
        None => prompt_password(&format!("Value for {key}: "))?,
    };

    let key_display = key.clone();
    let secrets = vault.secrets_mut(env)?;
    secrets.insert(key, value.as_str().to_owned());
    let count = secrets.len();
    vault::save(vault_path, password.as_bytes(), &vault)?;
    println!("Set `{key_display}` in environment `{env_name}` ({count} secrets)");
    Ok(())
}

/// Imports a `.env` file into one environment of the vault. Existing keys
/// are overwritten (the displaced values are wiped); the environment itself
/// must already exist — import never creates one implicitly.
fn cmd_import(vault_path: &Path, file: &Path, env: Option<&str>) -> Result<()> {
    let content = Zeroizing::new(
        std::fs::read_to_string(file)
            .with_context(|| format!("failed to read `{}`", file.display()))?,
    );
    let entries =
        dotenv::parse(&content).with_context(|| format!("failed to parse `{}`", file.display()))?;
    if entries.is_empty() {
        bail!("`{}` contains no variables", file.display());
    }

    let inferred = infer_env_name(file);
    let env = env.or(inferred.as_deref());

    let password = prompt_password("Master password: ")?;
    let mut vault = vault::load(vault_path, password.as_bytes())?;
    let env_name = vault.resolve_name(env).to_string();

    let count = entries.len();
    let secrets = vault.secrets_mut(env)?;
    for (key, value) in entries {
        secrets.insert(key, value);
    }
    let total = secrets.len();
    vault::save(vault_path, password.as_bytes(), &vault)?;
    println!("Imported {count} variable(s) into environment `{env_name}` ({total} secrets)");
    Ok(())
}

/// A file named `.env.<name>` targets the environment `<name>`; any other
/// file name (including plain `.env`) targets the vault's default.
fn infer_env_name(file: &Path) -> Option<String> {
    file.file_name()?
        .to_str()?
        .strip_prefix(".env.")
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
}

fn cmd_view(vault_path: &Path, keys_only: bool, env: Option<&str>) -> Result<()> {
    let password = prompt_password("Master password: ")?;
    let vault = vault::load(vault_path, password.as_bytes())?;
    drop(password);

    let env_name = vault.resolve_name(env);
    let secrets = vault.secrets(env)?;
    eprintln!("# environment: {env_name}");

    if secrets.is_empty() {
        eprintln!("(environment is empty)");
        return Ok(());
    }
    for (key, value) in secrets.iter() {
        if keys_only {
            println!("{key}");
        } else {
            println!("{key}={value}");
        }
    }
    Ok(())
}

/// Decrypts the selected environment and runs `command` with the secrets
/// merged into the inherited environment. Returns the child's exit code
/// (128 + signal on Unix if it was killed by a signal).
///
/// After the child exits, verifies that none of the injected variables bled
/// into env-shield's own (and therefore the calling shell's) environment.
/// The child's copy is torn down by the OS together with the process itself.
fn cmd_run(vault_path: &Path, env: Option<&str>, command: &[String]) -> Result<i32> {
    let (program, args) = command
        .split_first()
        .context("no command specified; usage: evs run -- <COMMAND> [ARGS...]")?;

    // Keychain first — `run` is the hot path and must not prompt when the
    // password was stored at `init` (or via `keychain store`).
    let vault = if let Some(password) = keychain::get(vault_path) {
        match vault::load(vault_path, password.as_bytes()) {
            Ok(vault) => vault,
            Err(vault::VaultError::Crypto(_)) => {
                // Stale entry (vault re-created with a new password):
                // fall back to prompting and re-sync the keychain.
                eprintln!("evs: keychain password is stale, falling back to prompt");
                let password = prompt_password("Master password: ")?;
                let vault = vault::load(vault_path, password.as_bytes())?;
                if keychain::store(vault_path, &password).is_ok() {
                    eprintln!("evs: keychain updated");
                }
                vault
            }
            Err(e) => return Err(e.into()),
        }
    } else {
        let password = prompt_password("Master password: ")?;
        vault::load(vault_path, password.as_bytes())?
    };

    let env_name = vault.resolve_name(env).to_string();
    let secrets = vault.secrets(env)?;

    // Key names (not values) are retained past the wipe for the post-exit
    // leak check; names are not treated as secrets.
    let injected: Vec<String> = secrets.iter().map(|(k, _)| k.clone()).collect();
    let preexisting: Vec<bool> = injected
        .iter()
        .map(|k| std::env::var_os(k).is_some())
        .collect();

    eprintln!(
        "evs: injecting {} variable(s) from environment `{env_name}`",
        injected.len()
    );

    // .envs() merges the decrypted variables into the environment the child
    // inherits from us; nothing is exported into our own process environment
    // and nothing touches disk.
    let mut child = Command::new(program)
        .args(args)
        .envs(secrets.iter())
        .spawn()
        .with_context(|| format!("failed to spawn `{program}`"))?;

    // The child now owns its copy of the environment; wipe ours before
    // blocking on it for an arbitrarily long time.
    drop(vault);

    let status = child
        .wait()
        .with_context(|| format!("failed to wait for `{program}`"))?;

    // Post-exit verification: anything we injected must not be visible in
    // our own environment (variables that already existed in the calling
    // shell are excluded — those are not ours).
    let leaked: Vec<&str> = injected
        .iter()
        .zip(&preexisting)
        .filter(|&(key, &pre)| !pre && std::env::var_os(key.as_str()).is_some())
        .map(|(key, _)| key.as_str())
        .collect();
    if leaked.is_empty() {
        eprintln!("evs: child exited; parent environment verified clean");
    } else {
        eprintln!(
            "evs: WARNING: variables leaked into the parent environment: {}",
            leaked.join(", ")
        );
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return Ok(128 + signal);
        }
    }
    Ok(status.code().unwrap_or(1))
}

fn cmd_keychain(vault_path: &Path, action: KeychainAction) -> Result<()> {
    match action {
        KeychainAction::Store => {
            let password = prompt_password("Master password: ")?;
            // Validate against the vault before trusting the entry.
            vault::load(vault_path, password.as_bytes())?;
            keychain::store(vault_path, &password)?;
            println!("Master password stored in the OS keychain; `run` will not prompt");
        }
        KeychainAction::Forget => {
            if keychain::forget(vault_path)? {
                println!("Removed the master password from the OS keychain; `run` will prompt");
            } else {
                println!("No master password stored for this vault");
            }
        }
        KeychainAction::Status => {
            if keychain::get(vault_path).is_some() {
                println!("Master password stored; `run` does not prompt");
            } else {
                println!("No master password stored; `run` prompts");
            }
        }
    }
    Ok(())
}

fn cmd_env(vault_path: &Path, action: EnvAction) -> Result<()> {
    let password = prompt_password("Master password: ")?;
    let mut vault = vault::load(vault_path, password.as_bytes())?;

    match action {
        EnvAction::List => {
            for name in vault.env_names() {
                let marker = if name == vault.default_env() {
                    "*"
                } else {
                    " "
                };
                let count = vault.secrets(Some(name))?.len();
                println!("{marker} {name} ({count} secrets)");
            }
        }
        EnvAction::Add { name } => {
            vault.add_env(&name)?;
            vault::save(vault_path, password.as_bytes(), &vault)?;
            println!("Created environment `{name}`");
        }
        EnvAction::Remove { name } => {
            vault.remove_env(&name)?;
            vault::save(vault_path, password.as_bytes(), &vault)?;
            println!("Removed environment `{name}` (secrets wiped)");
        }
        EnvAction::Use { name } => {
            vault.set_default(&name)?;
            vault::save(vault_path, password.as_bytes(), &vault)?;
            println!("Default environment is now `{name}`");
        }
    }
    Ok(())
}

/// Reads a password without echoing it. Falls back to reading one line from
/// stdin when it is not a terminal (pipes, CI). The returned buffer is
/// zeroized on drop.
fn prompt_password(prompt: &str) -> Result<Zeroizing<String>> {
    let password = if std::io::stdin().is_terminal() {
        rpassword::prompt_password(prompt).context("failed to read password")?
    } else {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .context("failed to read password from stdin")?;
        let trimmed = line.trim_end_matches(['\r', '\n']).to_owned();
        line.zeroize();
        trimmed
    };
    Ok(Zeroizing::new(password))
}
