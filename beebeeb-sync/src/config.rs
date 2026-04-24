use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// How much of the vault to sync locally.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncMode {
    /// Sync every file in the vault.
    Full,
    /// Sync recent, starred, and shared files automatically.
    #[default]
    Smart,
    /// Sync only the listed folder prefixes.
    Custom(Vec<String>),
    /// Keep everything as online-only placeholders.
    OnlineOnly,
}

/// Top-level configuration for the sync engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConfig {
    /// Local folder that mirrors the remote vault.
    pub vault_path: PathBuf,
    /// Base URL of the Beebeeb API (e.g. `https://api.beebeeb.io`).
    pub api_url: String,
    /// Bearer token for the current session.
    pub session_token: String,
    /// Which subset of the vault lives on disk.
    pub sync_mode: SyncMode,
    /// Optional upload/download rate cap in bytes per second. `None` = unlimited.
    pub bandwidth_limit: Option<u64>,
    /// When true, pause sync while on a metered (cellular / hotspot) connection.
    pub pause_on_metered: bool,
}

impl SyncConfig {
    pub fn new(vault_path: PathBuf, api_url: String, session_token: String) -> Self {
        Self {
            vault_path,
            api_url,
            session_token,
            sync_mode: SyncMode::default(),
            bandwidth_limit: None,
            pause_on_metered: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn default_sync_mode_is_smart() {
        assert_eq!(SyncMode::default(), SyncMode::Smart);
    }

    #[test]
    fn config_new_sets_defaults() {
        let cfg = SyncConfig::new(
            PathBuf::from("/vault"),
            "https://api.beebeeb.io".into(),
            "tok_abc".into(),
        );
        assert_eq!(cfg.sync_mode, SyncMode::Smart);
        assert!(cfg.bandwidth_limit.is_none());
        assert!(cfg.pause_on_metered);
    }

    #[test]
    fn config_roundtrips_through_json() {
        let cfg = SyncConfig {
            vault_path: PathBuf::from("/home/user/Beebeeb"),
            api_url: "https://api.beebeeb.io".into(),
            session_token: "tok_123".into(),
            sync_mode: SyncMode::Custom(vec!["investigations/".into(), "photos/".into()]),
            bandwidth_limit: Some(1_000_000),
            pause_on_metered: false,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: SyncConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.vault_path, cfg.vault_path);
        assert_eq!(back.sync_mode, cfg.sync_mode);
        assert_eq!(back.bandwidth_limit, Some(1_000_000));
    }
}
