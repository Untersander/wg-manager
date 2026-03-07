use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub auth: AuthConfig,
    pub wireguard: WireGuardConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardConfig {
    #[serde(default = "default_config_dir")]
    pub config_dir: String,
}

fn default_listen_addr() -> String {
    "0.0.0.0".to_string()
}

fn default_listen_port() -> u16 {
    8080
}

fn default_config_dir() -> String {
    "/etc/wireguard".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                listen_addr: default_listen_addr(),
                listen_port: default_listen_port(),
            },
            auth: AuthConfig {
                username: std::env::var("WG_USERNAME").unwrap_or_else(|_| "admin".to_string()),
                password: std::env::var("WG_PASSWORD").unwrap_or_else(|_| "admin".to_string()),
            },
            wireguard: WireGuardConfig {
                config_dir: default_config_dir(),
            },
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        // Try to load from environment variables first
        if let Ok(username) = std::env::var("WG_USERNAME") {
            if let Ok(password) = std::env::var("WG_PASSWORD") {
                tracing::info!("Loading configuration from environment variables");
                let mut config = Config::default();
                config.auth.username = username;
                config.auth.password = password;

                if let Ok(config_dir) = std::env::var("WG_CONFIG_DIR") {
                    config.wireguard.config_dir = config_dir;
                }

                return Ok(config);
            }
        }

        // Try to load from config file
        let config_path = std::env::var("CONFIG_PATH")
            .unwrap_or_else(|_| "/etc/wg-manager/config.toml".to_string());

        if Path::new(&config_path).exists() {
            tracing::info!("Loading configuration from {}", config_path);
            let content = fs::read_to_string(&config_path)
                .context("Failed to read configuration file")?;
            let config: Config = toml::from_str(&content)
                .context("Failed to parse configuration file")?;
            return Ok(config);
        }

        // Fall back to default configuration with warning
        tracing::warn!("No configuration found, using defaults (username: admin, password: admin)");
        Ok(Config::default())
    }
}
