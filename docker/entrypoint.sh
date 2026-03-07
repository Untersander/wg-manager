#!/bin/sh
set -eu

WG_CONFIG_PATH="${WG_CONFIG_PATH:-/etc/wireguard/wg0.conf}"
WG_INTERFACE_NAME="${WG_INTERFACE_NAME:-wg0}"
WG_PORT="${WG_PORT:-51820}"
WG_MTU="${WG_MTU:-1420}"
WG_EGRESS_INTERFACE="${WG_EGRESS_INTERFACE:-eth0}"
WG_SERVER_ADDRESS_V4="${WG_SERVER_ADDRESS_V4:-10.8.0.1/24}"
WG_SERVER_ADDRESS_V6="${WG_SERVER_ADDRESS_V6:-fd42:42:42::1/64}"

mkdir -p "$(dirname "$WG_CONFIG_PATH")"

if [ ! -f "$WG_CONFIG_PATH" ]; then
  umask 077
  server_priv="$(wg genkey)"
  cat > "$WG_CONFIG_PATH" <<EOF
[Interface]
Address = ${WG_SERVER_ADDRESS_V4}, ${WG_SERVER_ADDRESS_V6}
ListenPort = ${WG_PORT}
MTU = ${WG_MTU}
PrivateKey = ${server_priv}
EOF
fi

sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null

nft add table inet wg_manager 2>/dev/null || true
nft flush table inet wg_manager
nft add chain inet wg_manager postrouting "{ type nat hook postrouting priority srcnat; policy accept; }" 2>/dev/null || true
nft add rule inet wg_manager postrouting oifname "$WG_EGRESS_INTERFACE" ip saddr 10.0.0.0/8 masquerade 2>/dev/null || true
nft add rule inet wg_manager postrouting oifname "$WG_EGRESS_INTERFACE" ip6 saddr fd00::/8 masquerade 2>/dev/null || true

wg-quick up "$WG_CONFIG_PATH" 2>/dev/null || true

exec /usr/local/bin/wg-manager
