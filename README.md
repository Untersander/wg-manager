# wg-manager

Minimal Go WireGuard manager with a web UI.

## What It Does

- Wraps `wg` and `wg-quick` for peer management.
- Persists config in `wg-quick` format (`/etc/wireguard/wg0.conf`) with peer metadata in comments.
- Uses `nftables` for IPv4/IPv6 masquerade.
- Exposes all settings via environment variables with sensible defaults.
- Provides basic web UI for:
  - login/logout (single password)
  - CRUD peers
  - download peer client config
  - scan QR code for mobile clients
  - update WireGuard port/mtu and egress interface

## Run

```bash
docker compose up --build
```

Then open `http://localhost:8080`.

## Required Environment Variables

- `HTTP_PASSWORD`: UI password.
- `WG_HOST`: Public hostname or IP used in client endpoint.

## Important Variables

- `WG_PORT` (default `51820`)
- `WG_MTU` (default `1420`)
- `WG_INTERFACE_NAME` (default `wg0`)
- `WG_EGRESS_INTERFACE` (default `eth0`)
- `WG_CONFIG_PATH` (default `/etc/wireguard`, resulting file is `<WG_INTERFACE_NAME>.conf`)
- `WG_ALLOWED_IPS` (default `0.0.0.0/0,::/0`)
- `WG_CLIENT_DNS` (default `1.1.1.1,2606:4700:4700::1111`)
- `WG_PERSISTENT_KEEPALIVE` (default `60`)

## Kubernetes Deployment

This app needs low-level network access for WireGuard (`SYS_MODULE`, `NET_ADMIN`, IP forwarding).
The example below is intended for a trusted single-node or bare-metal cluster.

1. Create namespace and UI password secret:

```bash
kubectl create namespace wg-manager
kubectl -n wg-manager create secret generic wg-manager-secrets \
  --from-literal=HTTP_PASSWORD='change-me'
```

2. Apply this manifest:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: wg-manager
  namespace: wg-manager
spec:
  replicas: 1
  selector:
    matchLabels:
      app: wg-manager
  template:
    metadata:
      labels:
        app: wg-manager
    spec:
      dnsPolicy: ClusterFirstWithHostNet
      securityContext:
        sysctls:
          - name: net.ipv4.ip_forward
            value: "1"
          - name: net.ipv6.conf.all.forwarding
            value: "1"
      containers:
        - name: wg-manager
          image: ghcr.io/<owner>/wg-manager:latest
          imagePullPolicy: IfNotPresent
          securityContext:
            capabilities:
              add:
                - NET_ADMIN
                - SYS_MODULE
          ports:
            - name: http
              containerPort: 8080
              protocol: TCP
            - name: wireguard
              containerPort: 51820
              protocol: UDP
          env:
            - name: HTTP_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: wg-manager-secrets
                  key: HTTP_PASSWORD
            - name: WG_HOST
              value: "YOUR_PUBLIC_IP_OR_DNS"
            - name: WG_PORT
              value: "51820"
            - name: WG_MTU
              value: "1420"
            - name: WG_INTERFACE_NAME
              value: "wg0"
            - name: WG_EGRESS_INTERFACE
              value: "eth0"
            - name: WG_CONFIG_PATH
              value: "/etc/wireguard"
            - name: WG_ALLOWED_IPS
              value: "0.0.0.0/0,::/0"
            - name: WG_CLIENT_DNS
              value: "1.1.1.1,2606:4700:4700::1111"
            - name: WG_PERSISTENT_KEEPALIVE
              value: "60"
            - name: HTTP_ADDR
              value: ":8080"
          volumeMounts:
            - name: wg-config
              mountPath: /etc/wireguard
      volumes:
        - name: wg-config
          hostPath:
            path: /var/lib/wg-manager/wireguard
            type: DirectoryOrCreate
```

3. Deploy and verify:

```bash
kubectl apply -f wg-manager.yaml
kubectl -n wg-manager rollout status deploy/wg-manager
kubectl -n wg-manager logs -f deploy/wg-manager
```

4. Access the UI and WireGuard endpoint:

- UI: `http://<node-ip>:8080`
- WireGuard endpoint: `<node-ip>:51820/udp`

## Notes

- The container needs `NET_ADMIN`, `SYS_MODULE`, and IP forwarding.
- Initial config is generated automatically if missing.
