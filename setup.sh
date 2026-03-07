#!/bin/bash
set -e

echo "========================================"
echo "  WireGuard Manager Setup Script"
echo "========================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ] && [ "$1" != "--docker" ]; then
    echo "Note: Some operations may require root privileges."
    echo "Run with sudo or use --docker flag for Docker setup."
    echo ""
fi

# Function to generate WireGuard keys
generate_keys() {
    echo "Generating WireGuard server keys..."

    if ! command -v wg &> /dev/null; then
        echo "Error: WireGuard tools not found. Please install wireguard-tools first."
        exit 1
    fi

    mkdir -p ./wireguard

    # Generate server keys
    if [ ! -f ./wireguard/server-private.key ]; then
        wg genkey | tee ./wireguard/server-private.key | wg pubkey > ./wireguard/server-public.key
        chmod 600 ./wireguard/server-private.key
        echo "✓ Server keys generated"
        echo "  Private key: ./wireguard/server-private.key"
        echo "  Public key:  ./wireguard/server-public.key"
    else
        echo "✓ Server keys already exist"
    fi

    echo ""
}

# Function to create WireGuard configuration
create_wg_config() {
    echo "Creating WireGuard configuration..."

    if [ ! -f ./wireguard/wg0.conf ]; then
        SERVER_PRIVATE_KEY=$(cat ./wireguard/server-private.key)

        cat > ./wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = ${SERVER_PRIVATE_KEY}
Address = 10.0.0.1/24, fd00::1/64
ListenPort = 51820
SaveConfig = true
EOF

        chmod 600 ./wireguard/wg0.conf
        echo "✓ WireGuard configuration created: ./wireguard/wg0.conf"
    else
        echo "✓ WireGuard configuration already exists"
    fi

    echo ""
}

# Function to setup Docker environment
setup_docker() {
    echo "Setting up Docker environment..."

    # Create necessary directories
    mkdir -p ./wireguard ./config ./nftables

    # Generate keys if needed
    generate_keys

    # Create config
    create_wg_config

    # Create .env file if it doesn't exist
    if [ ! -f .env ]; then
        cat > .env <<EOF
WG_USERNAME=admin
WG_PASSWORD=changeme_$(openssl rand -hex 8)
WG_CONFIG_DIR=/etc/wireguard
RUST_LOG=wg_manager=info,tower_http=info
EOF
        echo "✓ Environment file created: .env"
        echo "  Note: Please change the password in .env file!"
    else
        echo "✓ Environment file already exists"
    fi

    echo ""
    echo "Docker setup complete!"
    echo ""
    echo "Next steps:"
    echo "  1. Review and edit .env file (change password!)"
    echo "  2. Run: docker-compose up -d"
    echo "  3. Access web UI at: http://localhost:8080"
    echo ""
}

# Function to setup local development
setup_local() {
    echo "Setting up local development environment..."

    # Check Rust installation
    if ! command -v cargo &> /dev/null; then
        echo "Error: Rust not found. Please install Rust first:"
        echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        exit 1
    fi

    echo "✓ Rust found: $(rustc --version)"

    # Generate keys
    generate_keys
    create_wg_config

    # Create config file
    mkdir -p ./config
    if [ ! -f ./config/config.toml ]; then
        cp config.toml.example ./config/config.toml
        echo "✓ Configuration file created: ./config/config.toml"
        echo "  Please edit this file to set your credentials"
    else
        echo "✓ Configuration file already exists"
    fi

    echo ""
    echo "Local setup complete!"
    echo ""
    echo "Next steps:"
    echo "  1. Build: cargo build --release"
    echo "  2. Run: sudo ./target/release/wg-manager"
    echo "  3. Access web UI at: http://localhost:8080"
    echo ""
    echo "Note: The application needs root privileges to manage WireGuard and nftables."
    echo ""
}

# Main menu
if [ "$1" == "--docker" ]; then
    setup_docker
elif [ "$1" == "--local" ]; then
    setup_local
else
    echo "WireGuard Manager Setup"
    echo ""
    echo "Usage:"
    echo "  $0 --docker   Setup for Docker deployment"
    echo "  $0 --local    Setup for local development"
    echo ""
    echo "Choose your deployment method:"
    echo "  1) Docker (recommended)"
    echo "  2) Local development"
    echo ""
    read -p "Enter choice [1-2]: " choice

    case $choice in
        1)
            setup_docker
            ;;
        2)
            setup_local
            ;;
        *)
            echo "Invalid choice"
            exit 1
            ;;
    esac
fi
