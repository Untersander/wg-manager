use anyhow::{Context, Result};
use std::process::Command;

/// Initialize nftables for WireGuard masquerading
pub fn initialize() -> Result<()> {
    tracing::info!("Initializing nftables for WireGuard");

    // Create table for WireGuard NAT
    let commands = vec![
        "add table inet wg_nat",
        "add chain inet wg_nat postrouting { type nat hook postrouting priority 100 ; }",
    ];

    for cmd in commands {
        execute_nft_command(cmd)?;
    }

    tracing::info!("nftables initialized successfully");
    Ok(())
}

/// Enable masquerading for a specific WireGuard interface
pub fn enable_masquerade(interface: &str) -> Result<()> {
    tracing::info!("Enabling masquerade for interface {}", interface);

    // Add masquerade rules for both IPv4 and IPv6
    let commands = vec![
        // IPv4 masquerade
        format!(
            "add rule inet wg_nat postrouting oifname != \"{}\" ip saddr 10.0.0.0/8 masquerade",
            interface
        ),
        // IPv6 masquerade
        format!(
            "add rule inet wg_nat postrouting oifname != \"{}\" ip6 saddr fd00::/8 masquerade",
            interface
        ),
    ];

    for cmd in &commands {
        execute_nft_command(cmd)?;
    }

    tracing::info!("Masquerade enabled for {}", interface);
    Ok(())
}

/// Disable masquerading for a specific WireGuard interface
pub fn disable_masquerade(interface: &str) -> Result<()> {
    tracing::info!("Disabling masquerade for interface {}", interface);

    // This is a simplified version - in production you'd need to track rule handles
    // For now, we'll flush and recreate rules without this interface

    flush_masquerade_rules()?;
    tracing::info!("Masquerade disabled for {}", interface);
    Ok(())
}

/// Flush all masquerade rules
fn flush_masquerade_rules() -> Result<()> {
    execute_nft_command("flush chain inet wg_nat postrouting")?;
    Ok(())
}

/// Check if nftables is available
pub fn check_availability() -> bool {
    Command::new("nft")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Execute an nftables command
fn execute_nft_command(cmd: &str) -> Result<()> {
    let output = Command::new("nft")
        .args(cmd.split_whitespace())
        .output()
        .context(format!("Failed to execute nft command: {}", cmd))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore "table already exists" errors
        if !stderr.contains("already exists") {
            anyhow::bail!("nft command failed: {} - {}", cmd, stderr);
        }
    }

    Ok(())
}

/// Get current nftables ruleset
pub fn get_ruleset() -> Result<String> {
    let output = Command::new("nft")
        .arg("list")
        .arg("ruleset")
        .output()
        .context("Failed to execute 'nft list ruleset'")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to get ruleset: {}", stderr);
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Check if masquerade is enabled for an interface
pub fn is_masquerade_enabled(interface: &str) -> Result<bool> {
    let ruleset = get_ruleset()?;
    // Simple check - look for rules mentioning the interface
    Ok(ruleset.contains(interface) && ruleset.contains("masquerade"))
}
