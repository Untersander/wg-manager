pub mod parser;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interface {
    pub name: String,
    pub public_key: String,
    pub listen_port: Option<u16>,
    pub peers: Vec<Peer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    pub latest_handshake: Option<String>,
    pub transfer_rx: u64,
    pub transfer_tx: u64,
}

/// List all WireGuard interfaces
pub fn list_interfaces() -> Result<Vec<String>> {
    let output = Command::new("wg")
        .arg("show")
        .arg("interfaces")
        .output()
        .context("Failed to execute 'wg show interfaces'")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("wg command failed: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let interfaces: Vec<String> = stdout
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();

    Ok(interfaces)
}

/// Get detailed information about a specific interface
pub fn get_interface(name: &str) -> Result<Interface> {
    let output = Command::new("wg")
        .arg("show")
        .arg(name)
        .output()
        .context(format!("Failed to execute 'wg show {}'", name))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("wg command failed: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parser::parse_interface(name, &stdout)
}

/// Add a peer to an interface
pub fn add_peer(
    interface: &str,
    public_key: &str,
    allowed_ips: &[String],
    endpoint: Option<&str>,
) -> Result<()> {
    let mut cmd = Command::new("wg");
    cmd.arg("set").arg(interface).arg("peer").arg(public_key);

    if !allowed_ips.is_empty() {
        cmd.arg("allowed-ips").arg(allowed_ips.join(","));
    }

    if let Some(ep) = endpoint {
        cmd.arg("endpoint").arg(ep);
    }

    let output = cmd.output().context("Failed to execute 'wg set'")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to add peer: {}", stderr);
    }

    // Save configuration to make it persistent
    save_config(interface)?;

    Ok(())
}

/// Remove a peer from an interface
pub fn remove_peer(interface: &str, public_key: &str) -> Result<()> {
    let output = Command::new("wg")
        .arg("set")
        .arg(interface)
        .arg("peer")
        .arg(public_key)
        .arg("remove")
        .output()
        .context("Failed to execute 'wg set'")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to remove peer: {}", stderr);
    }

    // Save configuration to make it persistent
    save_config(interface)?;

    Ok(())
}

/// Save current WireGuard configuration to file
fn save_config(interface: &str) -> Result<()> {
    let output = Command::new("wg-quick")
        .arg("save")
        .arg(interface)
        .output()
        .context("Failed to execute 'wg-quick save'")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::warn!("Failed to save WireGuard config: {}", stderr);
        // Don't fail the operation if save fails
    }

    Ok(())
}

/// Bring up a WireGuard interface
pub fn interface_up(interface: &str) -> Result<()> {
    let output = Command::new("wg-quick")
        .arg("up")
        .arg(interface)
        .output()
        .context("Failed to execute 'wg-quick up'")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to bring up interface: {}", stderr);
    }

    Ok(())
}

/// Bring down a WireGuard interface
pub fn interface_down(interface: &str) -> Result<()> {
    let output = Command::new("wg-quick")
        .arg("down")
        .arg(interface)
        .output()
        .context("Failed to execute 'wg-quick down'")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to bring down interface: {}", stderr);
    }

    Ok(())
}

/// Create a new WireGuard interface configuration
pub fn create_interface(name: &str, listen_port: u16, config_dir: &str) -> Result<()> {
    use std::fs;
    use std::path::Path;

    // Generate a new keypair for the interface
    let output = Command::new("wg")
        .arg("genkey")
        .output()
        .context("Failed to generate WireGuard key")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to generate key: {}", stderr);
    }

    let private_key = String::from_utf8_lossy(&output.stdout)
        .trim()
        .to_string();

    // Create configuration directory if it doesn't exist
    let config_path = Path::new(config_dir);
    if !config_path.exists() {
        fs::create_dir_all(config_path)
            .context("Failed to create WireGuard config directory")?;
    }

    // Create the config file
    let config_file = config_path.join(format!("{}.conf", name));
    if config_file.exists() {
        anyhow::bail!("Interface {} already exists", name);
    }

    let config_content = format!(
        "[Interface]\nPrivateKey = {}\nAddress = 10.0.0.1/24, fd00::1/64\nListenPort = {}\nSaveConfig = true\n",
        private_key, listen_port
    );

    fs::write(&config_file, config_content)
        .context(format!("Failed to write config file: {:?}", config_file))?;

    // Set proper permissions (600)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(&config_file, perms)
            .context("Failed to set config file permissions")?;
    }

    tracing::info!("Created WireGuard interface {}", name);

    Ok(())
}

/// Delete a WireGuard interface
pub fn delete_interface(name: &str, config_dir: &str) -> Result<()> {
    use std::fs;
    use std::path::Path;

    // First, bring down the interface if it's up
    if let Err(e) = interface_down(name) {
        tracing::warn!("Could not bring down interface {}: {}", name, e);
        // Don't fail if interface is already down
    }

    // Remove the config file
    let config_path = Path::new(config_dir);
    let config_file = config_path.join(format!("{}.conf", name));

    if config_file.exists() {
        fs::remove_file(&config_file)
            .context(format!("Failed to delete config file: {:?}", config_file))?;
        tracing::info!("Deleted WireGuard interface {}", name);
    } else {
        anyhow::bail!("Interface {} configuration not found", name);
    }

    Ok(())
}
