package wireguard

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// buildConfig renders a WireGuard config to a string.
func buildConfig(cfg Config) string {
	var b strings.Builder
	mustWrite(&b, "[Interface]\n")
	if len(cfg.Interface.Addresses) > 0 {
		mustWrite(&b, "Address = %s\n", strings.Join(cfg.Interface.Addresses, ", "))
	}
	mustWrite(&b, "ListenPort = %d\n", cfg.Interface.ListenPort)
	if cfg.Interface.MTU > 0 {
		mustWrite(&b, "MTU = %d\n", cfg.Interface.MTU)
	}
	if cfg.Interface.PrivateKey != "" {
		mustWrite(&b, "PrivateKey = %s\n", cfg.Interface.PrivateKey)
	}

	for _, peer := range cfg.Peers {
		mustWrite(&b, "\n")
		mustWrite(&b, "[Peer]\n")
		if peer.Name != "" {
			mustWrite(&b, "# Name = %s\n", peer.Name)
		}
		if peer.PrivateKey != "" {
			mustWrite(&b, "# PrivateKey = %s\n", peer.PrivateKey)
		}
		if len(peer.DNS) > 0 {
			mustWrite(&b, "# DNS = %s\n", strings.Join(peer.DNS, ", "))
		}
		if len(peer.ClientAllowedIPs) > 0 {
			mustWrite(&b, "# ClientAllowedIPs = %s\n", strings.Join(peer.ClientAllowedIPs, ", "))
		}
		mustWrite(&b, "PublicKey = %s\n", peer.PublicKey)
		if peer.PresharedKey != "" {
			mustWrite(&b, "PresharedKey = %s\n", peer.PresharedKey)
		}
		if len(peer.AllowedIPs) > 0 {
			mustWrite(&b, "AllowedIPs = %s\n", strings.Join(peer.AllowedIPs, ", "))
		}
		if peer.PersistentKeepalive > 0 {
			mustWrite(&b, "PersistentKeepalive = %d\n", peer.PersistentKeepalive)
		}
	}
	return b.String()
}

// mustWrite wraps fmt.Fprintf for strings.Builder which never returns an error.
func mustWrite(b *strings.Builder, format string, args ...any) {
	if _, err := fmt.Fprintf(b, format, args...); err != nil {
		panic(fmt.Sprintf("strings.Builder.Write failed: %v", err))
	}
}

func LoadConfig(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			slog.Warn("failed closing config file", "path", path, "error", cerr)
		}
	}()

	cfg := Config{}
	section := ""
	var peer Peer
	inPeer := false

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "#") {
			comment := strings.TrimSpace(strings.TrimPrefix(line, "#"))
			switch {
			case strings.HasPrefix(comment, "Name =") && inPeer:
				peer.Name = strings.TrimSpace(strings.TrimPrefix(comment, "Name ="))
			case strings.HasPrefix(comment, "PrivateKey =") && inPeer:
				peer.PrivateKey = strings.TrimSpace(strings.TrimPrefix(comment, "PrivateKey ="))
			case strings.HasPrefix(comment, "DNS =") && inPeer:
				peer.DNS = splitList(strings.TrimPrefix(comment, "DNS ="))
			case strings.HasPrefix(comment, "ClientAllowedIPs =") && inPeer:
				peer.ClientAllowedIPs = splitList(strings.TrimPrefix(comment, "ClientAllowedIPs ="))
			}
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			if section == "Peer" && inPeer {
				cfg.Peers = append(cfg.Peers, peer)
				peer = Peer{}
				inPeer = false
			}
			section = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			if section == "Peer" {
				inPeer = true
			}
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])

		switch section {
		case "Interface":
			switch k {
			case "Address":
				cfg.Interface.Addresses = splitList(v)
			case "PrivateKey":
				cfg.Interface.PrivateKey = v
			case "ListenPort":
				if n, err := strconv.Atoi(v); err != nil {
					slog.Warn("ignoring invalid ListenPort in config", "value", v, "error", err)
				} else {
					cfg.Interface.ListenPort = n
				}
			case "MTU":
				if n, err := strconv.Atoi(v); err != nil {
					slog.Warn("ignoring invalid MTU in config", "value", v, "error", err)
				} else {
					cfg.Interface.MTU = n
				}
			}
		case "Peer":
			switch k {
			case "PublicKey":
				peer.PublicKey = v
			case "PresharedKey":
				peer.PresharedKey = v
			case "AllowedIPs":
				peer.AllowedIPs = splitList(v)
			case "PersistentKeepalive":
				if n, err := strconv.Atoi(v); err != nil {
					slog.Warn("ignoring invalid PersistentKeepalive in config", "value", v, "error", err)
				} else {
					peer.PersistentKeepalive = n
				}
			}
		}
	}

	if section == "Peer" && inPeer {
		cfg.Peers = append(cfg.Peers, peer)
	}

	if err := scanner.Err(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func SaveConfig(path string, cfg Config) error {
	tmpPath := path + ".tmp"
	data := buildConfig(cfg)

	if err := os.WriteFile(tmpPath, []byte(data), 0o600); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func splitList(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
