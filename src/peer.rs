use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    pub name: String,
    pub private_key: String,
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub peer_endpoint: Option<String>,
    pub server_public_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerConfigContent {
    pub interface_block: String,
    pub peer_block: String,
    pub full_config: String,
}

/// Generate a new WireGuard keypair
pub fn generate_keypair() -> Result<(String, String)> {
    // Generate private key
    let output = Command::new("wg")
        .arg("genkey")
        .output()
        .context("Failed to execute 'wg genkey'")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to generate private key: {}", stderr);
    }

    let private_key = String::from_utf8_lossy(&output.stdout)
        .trim()
        .to_string();

    // Generate public key from private key
    let child = Command::new("bash")
        .arg("-c")
        .arg(format!("echo '{}' | wg pubkey", private_key))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("Failed to spawn wg pubkey command")?;

    let public_key_output = child
        .wait_with_output()
        .context("Failed to get pubkey output")?;

    if !public_key_output.status.success() {
        let stderr = String::from_utf8_lossy(&public_key_output.stderr);
        anyhow::bail!("Failed to derive public key: {}", stderr);
    }

    let public_key = String::from_utf8_lossy(&public_key_output.stdout)
        .trim()
        .to_string();

    Ok((private_key, public_key))
}

/// Build a peer configuration file content
pub fn build_peer_config(
    _peer_name: &str,
    private_key: &str,
    server_public_key: &str,
    server_endpoint: &str,
    allowed_ips: &[String],
) -> PeerConfigContent {
    let interface_block = format!(
        "[Interface]\nPrivateKey = {}\nAddress = {}\nDNS = 1.1.1.1\n",
        private_key,
        allowed_ips.join(", ")
    );

    let peer_block = format!(
        "[Peer]\nPublicKey = {}\nEndpoint = {}\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n",
        server_public_key, server_endpoint
    );

    let full_config = format!("{}\n{}", interface_block, peer_block);

    PeerConfigContent {
        interface_block,
        peer_block,
        full_config,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_peer_config() {
        let config = build_peer_config(
            "client1",
            "testPrivateKey==",
            "testServerPublicKey==",
            "vpn.example.com:51820",
            &["10.0.0.2/32".to_string(), "fd00::2/128".to_string()],
        );

        assert!(config.interface_block.contains("testPrivateKey=="));
        assert!(config.interface_block.contains("10.0.0.2/32"));
        assert!(config.peer_block.contains("testServerPublicKey=="));
        assert!(config.peer_block.contains("vpn.example.com:51820"));
        assert!(config.full_config.contains("[Interface]"));
        assert!(config.full_config.contains("[Peer]"));
    }
}
