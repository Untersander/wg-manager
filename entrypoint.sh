#!/bin/bash
set -o pipefail

echo "==================================="
echo "  WireGuard Manager Starting..."
echo "==================================="

# Load WireGuard kernel module if not already loaded
if ! lsmod 2>/dev/null | grep -q wireguard; then
    echo "Loading WireGuard kernel module..."
    if modprobe wireguard 2>&1; then
        echo "WireGuard module loaded"
    else
        echo "Warning: Failed to load WireGuard module (may already be loaded or built-in)"
    fi
fi

# Enable IP forwarding (may fail in containerized environments, but that's OK)
echo "Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "Note: Could not set IPv4 forwarding (check docker-compose sysctls)"
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo "Note: Could not set IPv6 forwarding (check docker-compose sysctls)"

# Check if nftables is available
if command -v nft &> /dev/null; then
    echo "nftables detected, initializing..."

    # Check if our table already exists
    if ! nft list tables | grep -q "inet wg_nat"; then
        echo "Creating nftables NAT table..."
        nft add table inet wg_nat
        nft add chain inet wg_nat postrouting { type nat hook postrouting priority 100 \; }
        echo "nftables NAT table created"
    else
        echo "nftables NAT table already exists"
    fi
else
    echo "Warning: nftables not found!"
fi

# Bring up any existing WireGuard interfaces
if [ -d "/etc/wireguard" ]; then
    echo "Checking for WireGuard configurations..."
    for conf in /etc/wireguard/*.conf; do
        if [ -f "$conf" ]; then
            iface=$(basename "$conf" .conf)
            echo "Starting WireGuard interface: $iface"
            wg-quick up "$iface" || echo "Warning: Failed to start $iface (may already be up)"
        fi
    done
fi

echo "==================================="
echo "  WireGuard Manager Initialized"
echo "==================================="
echo ""
echo "Web UI will be available at:"
echo "  http://localhost:8080"
echo ""
echo "Default credentials:"
echo "  Username: ${WG_USERNAME:-admin}"
echo "  Password: ${WG_PASSWORD:-admin}"
echo ""
echo "==================================="
echo ""

# Execute the main command
exec "$@"
