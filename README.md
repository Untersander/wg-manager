# WireGuard Manager

A lightweight, Rust-based web application for managing WireGuard VPN connections. Built with zero JavaScript dependencies for maximum simplicity and minimal resource usage.

## Features

- **Pure Server-Side Rendering** - No JavaScript, just HTML and CSS
- **WireGuard Management** - Add/remove peers, view connection status
- **IPv4/IPv6 NAT** - Built-in masquerading with nftables
- **Docker Ready** - Runs in a container with all dependencies
- **Basic Authentication** - Secure access with HTTP Basic Auth
- **Minimal Footprint** - Optimized Rust binary in Alpine Linux

## Quick Start

### Using Docker Compose (Recommended)

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd wg-manager
   ```

2. **Configure authentication (optional):**
   Edit `docker-compose.yml` and change the default credentials:
   ```yaml
   environment:
     - WG_USERNAME=admin
     - WG_PASSWORD=changeme
   ```

3. **Create WireGuard configuration directory:**
   ```bash
   mkdir -p wireguard
   ```

4. **Build and run:**
   ```bash
   docker-compose up -d
   ```

5. **Access the web interface:**
   Open your browser to `http://localhost:8080`

### Using Docker

```bash
# Build the image
docker build -t wg-manager .

# Run the container
docker run -d \
  --name wg-manager \
  --cap-add NET_ADMIN \
  --cap-add SYS_MODULE \
  --network host \
  -v $(pwd)/wireguard:/etc/wireguard \
  -e WG_USERNAME=admin \
  -e WG_PASSWORD=changeme \
  wg-manager
```

### Building from Source

**Requirements:**
- Rust 1.75 or later
- WireGuard tools (`wg`, `wg-quick`)
- nftables

**Build steps:**
```bash
cargo build --release
./target/release/wg-manager
```

### Docker Setup Requirements

To run WireGuard in Docker, your host system needs the following:

1. **WireGuard kernel support** - The host kernel must have WireGuard support:
   ```bash
   # Check if WireGuard is available
   modprobe wireguard
   ```
   If this fails, install WireGuard on your host:
   - **Ubuntu/Debian**: `apt-get install wireguard-tools`
   - **RHEL/CentOS**: `dnf install wireguard-tools`
   - **Alpine**: `apk add wireguard-tools`

2. **Docker permissions** - The container needs NET_ADMIN capability (already included in docker-compose.yml)

3. **Sysctl settings** - IP forwarding should be enabled on the host:
   ```bash
   sysctl -w net.ipv4.ip_forward=1
   sysctl -w net.ipv6.conf.all.forwarding=1
   ```

4. **Troubleshooting** - If you get permission errors:
   - **Option A** (recommended): Ensure host has proper sysctl settings
   - **Option B**: Edit `docker-compose.yml` and uncomment `privileged: true`
   - **Option C**: Use host network mode: set `network_mode: host` in docker-compose.yml

## WireGuard Setup

### 1. Generate Server Keys

```bash
wg genkey | tee server-private.key | wg pubkey > server-public.key
```

### 2. Create WireGuard Configuration

Create `/etc/wireguard/wg0.conf` (or `./wireguard/wg0.conf` for Docker):

```ini
[Interface]
PrivateKey = <content-of-server-private.key>
Address = 10.0.0.1/24, fd00::1/64
ListenPort = 51820
SaveConfig = true

# Optional: Add PostUp/PostDown scripts
# PostUp = nft add rule inet wg_nat postrouting oifname != "wg0" ip saddr 10.0.0.0/24 masquerade
# PostDown = nft flush table inet wg_nat
```

### 3. Start the Interface

**On host:**
```bash
wg-quick up wg0
```

**In Docker:**
The interface will be started automatically on container startup if the configuration file exists.

### 4. Add Peers via Web UI

1. Navigate to the interface detail page
2. Fill in the "Add New Peer" form:
   - **Public Key**: The peer's public key
   - **Allowed IPs**: IP addresses the peer can use (e.g., `10.0.0.2/32`)
   - **Endpoint**: Optional, only needed for site-to-site VPNs

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WG_USERNAME` | `admin` | Web UI username |
| `WG_PASSWORD` | `admin` | Web UI password |
| `WG_CONFIG_DIR` | `/etc/wireguard` | WireGuard configuration directory |
| `RUST_LOG` | - | Logging level (e.g., `info`, `debug`) |

### Configuration File

Alternatively, create `/etc/wg-manager/config.toml`:

```toml
[server]
listen_addr = "0.0.0.0"
listen_port = 8080

[auth]
username = "admin"
password = "secure-password-here"

[wireguard]
config_dir = "/etc/wireguard"
```

## NAT/Masquerading

The application uses nftables to provide IPv4 and IPv6 masquerading (NAT) for WireGuard peers.

**Enable masquerading:**
1. Navigate to the interface detail page
2. Check the "Enable IPv4/IPv6 masquerading" box
3. Click "Update Masquerade Settings"

This allows WireGuard clients to access the internet through the VPN server.

**Manual nftables configuration:**
```bash
# Create table and chain
nft add table inet wg_nat
nft add chain inet wg_nat postrouting { type nat hook postrouting priority 100 \; }

# Add masquerade rules
nft add rule inet wg_nat postrouting oifname != "wg0" ip saddr 10.0.0.0/8 masquerade
nft add rule inet wg_nat postrouting oifname != "wg0" ip6 saddr fd00::/8 masquerade
```

## Client Configuration

Generate client configuration:

```bash
# On the client machine
wg genkey | tee client-private.key | wg pubkey > client-public.key
```

Create client configuration file:

```ini
[Interface]
PrivateKey = <content-of-client-private.key>
Address = 10.0.0.2/32, fd00::2/128
DNS = 1.1.1.1, 2606:4700:4700::1111

[Peer]
PublicKey = <server-public-key>
Endpoint = <server-ip>:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

Add the client's public key through the web UI with allowed IP `10.0.0.2/32`.

## Security Considerations

**Important Security Notes:**

1. **Change default credentials** - Always change the default username/password
2. **Use HTTPS** - Consider running behind a reverse proxy with TLS (nginx, Caddy, Traefik)
3. **Firewall** - Restrict access to the web UI (port 8080)
4. **Private keys** - Keep WireGuard private keys secure and never share them
5. **Network isolation** - Run in a dedicated network namespace if possible

### Example: Running Behind Caddy

```caddyfile
wg-manager.example.com {
    reverse_proxy localhost:8080
    basicauth {
        admin $2a$14$...  # Use caddy hash-password
    }
}
```

## Troubleshooting

### WireGuard interface not appearing

```bash
# Check if WireGuard is running
wg show

# Check if the module is loaded
lsmod | grep wireguard

# Check container logs
docker logs wg-manager
```

### nftables not working

```bash
# Verify nftables is installed
nft --version

# List current ruleset
nft list ruleset

# Check if the table exists
nft list table inet wg_nat
```

### Permission errors in Docker

Make sure the container has the required capabilities:
```yaml
cap_add:
  - NET_ADMIN
  - SYS_MODULE
```

### Cannot connect to peers

1. Check firewall rules (allow UDP port 51820)
2. Verify IP forwarding is enabled:
   ```bash
   sysctl net.ipv4.ip_forward
   sysctl net.ipv6.conf.all.forwarding
   ```
3. Check WireGuard interface status: `wg show`
4. Verify NAT/masquerading rules: `nft list ruleset`

## API Endpoints

The application provides the following HTTP endpoints:

- `GET /` - Dashboard
- `GET /health` - Health check
- `GET /interfaces` - List all interfaces
- `GET /interfaces/:name` - Interface detail
- `POST /interfaces/:name/peers/add` - Add peer
- `POST /interfaces/:name/peers/:pubkey/delete` - Remove peer
- `POST /interfaces/:name/masquerade` - Toggle masquerading

All endpoints except `/health` require authentication.

## Development

### Project Structure

```
wg-manager/
|-- src/
|   |-- main.rs           # Application entry point
|   |-- auth.rs           # Authentication middleware
|   |-- config.rs         # Configuration management
|   |-- wg/               # WireGuard module
|   |   |-- mod.rs        # WireGuard commands
|   |   `-- parser.rs     # Parse wg output
|   |-- nft/              # nftables module
|   |   `-- mod.rs        # nftables management
|   `-- routes/           # HTTP routes
|       |-- mod.rs        # Route handlers
|       `-- templates.rs  # Template definitions
|-- templates/            # Askama HTML templates
|   |-- base.html
|   |-- dashboard.html
|   |-- interfaces.html
|   |-- interface_detail.html
|   `-- peers.html
|-- Dockerfile
|-- docker-compose.yml
|-- entrypoint.sh
`-- Cargo.toml
```

### Running Tests

```bash
cargo test
```

### Code Style

```bash
cargo fmt
cargo clippy
```

## License

[Add your license here]

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- [WireGuard](https://www.wireguard.com/) - Fast, modern, secure VPN tunnel
- [Axum](https://github.com/tokio-rs/axum) - Web framework
- [Askama](https://github.com/djc/askama) - Type-safe, compiled templates
