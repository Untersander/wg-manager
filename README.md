# wg-manager

Minimal Go + Docker WireGuard manager with a server-rendered web UI.

## What It Does

- Wraps `wg` and `wg-quick` for peer management.
- Persists config in `wg-quick` format (`/etc/wireguard/wg0.conf`) with peer metadata in comments.
- Uses `nftables` for IPv4/IPv6 masquerade.
- Provides basic web UI for:
  - login/logout (single password)
  - list peers
  - create peer
  - delete peer
  - download client config
  - scan QR code for mobile clients
  - update WireGuard port/mtu and egress interface

## Run

```bash
docker compose up --build
```

Then open `http://localhost:8080`.

## Required Environment Variables

- `WG_PASSWORD`: UI password.
- `WG_HOST`: Public hostname or IP used in client endpoint.

## Important Variables

- `WG_PORT` (default `51820`)
- `WG_MTU` (default `1420`)
- `WG_INTERFACE_NAME` (default `wg0`)
- `WG_EGRESS_INTERFACE` (default `eth0`)
- `WG_CONFIG_PATH` (default `/etc/wireguard/wg0.conf`)
- `WG_ALLOWED_IPS` (default `0.0.0.0/0,::/0`)
- `WG_CLIENT_DNS` (default `1.1.1.1,2606:4700:4700::1111`)
- `WG_PERSISTENT_KEEPALIVE` (default `25`)

## Notes

- The container needs `NET_ADMIN` and IP forwarding.
- Initial config is generated automatically if missing.
- This is an implementation starter with core flows; hardening and richer validation can be layered on top.
