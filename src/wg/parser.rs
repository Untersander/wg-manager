use anyhow::Result;
use regex::Regex;

use super::{Interface, Peer};

/// Parse the output of `wg show <interface>`
pub fn parse_interface(name: &str, output: &str) -> Result<Interface> {
    let mut interface = Interface {
        name: name.to_string(),
        public_key: String::new(),
        listen_port: None,
        peers: Vec::new(),
    };

    let mut current_peer: Option<Peer> = None;

    for line in output.lines() {
        let line = line.trim();

        if line.starts_with("public key:") {
            if let Some(key) = line.strip_prefix("public key:") {
                interface.public_key = key.trim().to_string();
            }
        } else if line.starts_with("listening port:") {
            if let Some(port_str) = line.strip_prefix("listening port:") {
                if let Ok(port) = port_str.trim().parse() {
                    interface.listen_port = Some(port);
                }
            }
        } else if line.starts_with("peer:") {
            // Save previous peer if exists
            if let Some(peer) = current_peer.take() {
                interface.peers.push(peer);
            }

            // Start new peer
            if let Some(key) = line.strip_prefix("peer:") {
                current_peer = Some(Peer {
                    public_key: key.trim().to_string(),
                    allowed_ips: Vec::new(),
                    endpoint: None,
                    latest_handshake: None,
                    transfer_rx: 0,
                    transfer_tx: 0,
                });
            }
        } else if let Some(peer) = current_peer.as_mut() {
            if line.starts_with("endpoint:") {
                if let Some(ep) = line.strip_prefix("endpoint:") {
                    peer.endpoint = Some(ep.trim().to_string());
                }
            } else if line.starts_with("allowed ips:") {
                if let Some(ips) = line.strip_prefix("allowed ips:") {
                    peer.allowed_ips = ips
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .collect();
                }
            } else if line.starts_with("latest handshake:") {
                if let Some(hs) = line.strip_prefix("latest handshake:") {
                    peer.latest_handshake = Some(hs.trim().to_string());
                }
            } else if line.starts_with("transfer:") {
                if let Some(transfer) = line.strip_prefix("transfer:") {
                    let (rx, tx) = parse_transfer(transfer.trim());
                    peer.transfer_rx = rx;
                    peer.transfer_tx = tx;
                }
            }
        }
    }

    // Save last peer if exists
    if let Some(peer) = current_peer {
        interface.peers.push(peer);
    }

    Ok(interface)
}

/// Parse transfer data (e.g., "1.23 MiB received, 4.56 GiB sent")
fn parse_transfer(transfer: &str) -> (u64, u64) {
    let re = Regex::new(r"([\d.]+)\s*([A-Za-z]*)\s*received,\s*([\d.]+)\s*([A-Za-z]*)\s*sent")
        .unwrap();

    if let Some(caps) = re.captures(transfer) {
        let rx_val: f64 = caps.get(1).and_then(|m| m.as_str().parse().ok()).unwrap_or(0.0);
        let rx_unit = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let tx_val: f64 = caps.get(3).and_then(|m| m.as_str().parse().ok()).unwrap_or(0.0);
        let tx_unit = caps.get(4).map(|m| m.as_str()).unwrap_or("");

        let rx = (rx_val * unit_multiplier(rx_unit)) as u64;
        let tx = (tx_val * unit_multiplier(tx_unit)) as u64;

        return (rx, tx);
    }

    (0, 0)
}

fn unit_multiplier(unit: &str) -> f64 {
    match unit.to_uppercase().as_str() {
        "KIB" => 1024.0,
        "MIB" => 1024.0 * 1024.0,
        "GIB" => 1024.0 * 1024.0 * 1024.0,
        "TIB" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => 1.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_interface() {
        let output = r#"
interface: wg0
  public key: serverPublicKeyHere==
  private key: (hidden)
  listening port: 51820

peer: peerPublicKey1==
  endpoint: 192.168.1.100:51820
  allowed ips: 10.0.0.2/32
  latest handshake: 1 minute, 23 seconds ago
  transfer: 1.23 MiB received, 4.56 GiB sent

peer: peerPublicKey2==
  allowed ips: 10.0.0.3/32, 10.0.1.0/24
  latest handshake: 5 minutes, 10 seconds ago
  transfer: 500.00 KiB received, 123.45 MiB sent
        "#;

        let interface = parse_interface("wg0", output).unwrap();
        assert_eq!(interface.name, "wg0");
        assert_eq!(interface.public_key, "serverPublicKeyHere==");
        assert_eq!(interface.listen_port, Some(51820));
        assert_eq!(interface.peers.len(), 2);

        let peer1 = &interface.peers[0];
        assert_eq!(peer1.public_key, "peerPublicKey1==");
        assert_eq!(peer1.endpoint, Some("192.168.1.100:51820".to_string()));
        assert_eq!(peer1.allowed_ips, vec!["10.0.0.2/32"]);

        let peer2 = &interface.peers[1];
        assert_eq!(peer2.allowed_ips, vec!["10.0.0.3/32", "10.0.1.0/24"]);
    }
}
