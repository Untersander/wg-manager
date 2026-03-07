package wireguard

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func EnableIPForwarding() error {
	paths := []string{
		"/proc/sys/net/ipv4/ip_forward",
		"/proc/sys/net/ipv6/conf/all/forwarding",
	}
	for _, p := range paths {
		if err := os.WriteFile(p, []byte("1"), 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", p, err)
		}
	}
	return nil
}

func EnsureConfig(path string, listenPort, mtu int, addressV4, addressV6 string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	privKey, err := runCmd("wg", "genkey")
	if err != nil {
		return fmt.Errorf("generating server key: %w", err)
	}

	content := fmt.Sprintf("[Interface]\nAddress = %s, %s\nListenPort = %d\nMTU = %d\nPrivateKey = %s\n",
		addressV4, addressV6, listenPort, mtu, strings.TrimSpace(privKey))

	return os.WriteFile(path, []byte(content), 0o600)
}
