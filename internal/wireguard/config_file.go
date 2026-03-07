package wireguard

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func LoadConfig(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()

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
				cfg.Interface.ListenPort, _ = strconv.Atoi(v)
			case "MTU":
				cfg.Interface.MTU, _ = strconv.Atoi(v)
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
				peer.PersistentKeepalive, _ = strconv.Atoi(v)
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
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}

	w := bufio.NewWriter(f)
	_, _ = fmt.Fprintln(w, "[Interface]")
	if len(cfg.Interface.Addresses) > 0 {
		_, _ = fmt.Fprintf(w, "Address = %s\n", strings.Join(cfg.Interface.Addresses, ", "))
	}
	_, _ = fmt.Fprintf(w, "ListenPort = %d\n", cfg.Interface.ListenPort)
	if cfg.Interface.MTU > 0 {
		_, _ = fmt.Fprintf(w, "MTU = %d\n", cfg.Interface.MTU)
	}
	if cfg.Interface.PrivateKey != "" {
		_, _ = fmt.Fprintf(w, "PrivateKey = %s\n", cfg.Interface.PrivateKey)
	}

	for _, peer := range cfg.Peers {
		_, _ = fmt.Fprintln(w, "")
		_, _ = fmt.Fprintln(w, "[Peer]")
		if peer.Name != "" {
			_, _ = fmt.Fprintf(w, "# Name = %s\n", peer.Name)
		}
		if peer.PrivateKey != "" {
			_, _ = fmt.Fprintf(w, "# PrivateKey = %s\n", peer.PrivateKey)
		}
		_, _ = fmt.Fprintf(w, "PublicKey = %s\n", peer.PublicKey)
		if peer.PresharedKey != "" {
			_, _ = fmt.Fprintf(w, "PresharedKey = %s\n", peer.PresharedKey)
		}
		if len(peer.AllowedIPs) > 0 {
			_, _ = fmt.Fprintf(w, "AllowedIPs = %s\n", strings.Join(peer.AllowedIPs, ", "))
		}
		if peer.PersistentKeepalive > 0 {
			_, _ = fmt.Fprintf(w, "PersistentKeepalive = %d\n", peer.PersistentKeepalive)
		}
	}

	if err := w.Flush(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
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
