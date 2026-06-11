//! Command-line interface definition.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "evs",
    version,
    about = "Encrypted local vault that replaces plaintext .env files",
    long_about = "evs (Env Vault Shield) stores environment variables in a password-protected,\n\
                  authenticated-encryption vault and injects them directly into a\n\
                  child process's environment, so secrets never sit on disk in\n\
                  plaintext. A vault holds multiple named environments (e.g. dev,\n\
                  staging) with one of them acting as the default."
)]
pub struct Cli {
    /// Path to the vault file
    #[arg(
        long,
        global = true,
        default_value = ".env-shield",
        value_name = "FILE"
    )]
    pub vault: PathBuf,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Create a new, empty vault protected by a master password
    ///
    /// By default the master password is also stored in the OS keychain so
    /// `run` never prompts; `set` and `view` always do.
    Init {
        /// Do not store the master password in the OS keychain
        /// (`run` will prompt like every other command)
        #[arg(long)]
        no_keychain: bool,
    },

    /// Add or update a secret in an environment
    ///
    /// Prefer omitting VALUE: you will be prompted for it without echo.
    /// Values passed as arguments can leak into shell history and the
    /// process list.
    Set {
        /// Environment variable name
        key: String,

        /// Secret value (omit to enter it via a hidden prompt)
        value: Option<String>,

        /// Target environment (defaults to the vault's default environment)
        #[arg(short, long, value_name = "NAME")]
        env: Option<String>,
    },

    /// Decrypt an environment and print its contents to stdout
    View {
        /// Print only the variable names, not the values
        #[arg(short, long)]
        keys_only: bool,

        /// Environment to show (defaults to the vault's default environment)
        #[arg(short, long, value_name = "NAME")]
        env: Option<String>,
    },

    /// Run a command with the decrypted secrets injected into its environment
    ///
    /// Example: evs run --env staging -- npm start
    Run {
        /// Environment to inject (defaults to the vault's default environment)
        #[arg(short, long, value_name = "NAME")]
        env: Option<String>,

        /// Command and its arguments
        #[arg(
            required = true,
            trailing_var_arg = true,
            allow_hyphen_values = true,
            value_name = "COMMAND"
        )]
        command: Vec<String>,
    },

    /// Manage the named environments inside the vault
    Env {
        #[command(subcommand)]
        action: EnvAction,
    },

    /// Manage the master password stored in the OS keychain
    Keychain {
        #[command(subcommand)]
        action: KeychainAction,
    },
}

#[derive(Subcommand, Clone, Copy)]
pub enum KeychainAction {
    /// Store the master password for this vault (validated first);
    /// `run` will stop prompting
    Store,

    /// Remove the stored master password; `run` will prompt again
    Forget,

    /// Show whether a master password is stored for this vault
    Status,
}

#[derive(Subcommand)]
pub enum EnvAction {
    /// List all environments (the default is marked with `*`)
    List,

    /// Create a new, empty environment
    Add {
        /// Environment name (e.g. dev, staging, prod)
        name: String,
    },

    /// Delete an environment and wipe its secrets
    Remove {
        /// Environment to delete (cannot be the current default)
        name: String,
    },

    /// Set the vault's default environment
    Use {
        /// Environment to use as the default
        name: String,
    },
}
