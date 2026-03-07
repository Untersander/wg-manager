package wireguard

import (
	"fmt"
	"net/netip"
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

func EnsureConfig(path string, listenPort, mtu int, subnetV4, subnetV6 string) error {
	// Get expected server addresses from subnets
	serverAddrV4, err := firstUsableIP(subnetV4)
	if err != nil {
		return fmt.Errorf("invalid IPv4 subnet: %w", err)
	}
	serverAddrV6, err := firstUsableIP(subnetV6)
	if err != nil {
		return fmt.Errorf("invalid IPv6 subnet: %w", err)
	}

	// If config exists, check if subnet addresses need updating
	if _, err := os.Stat(path); err == nil {
		cfg, loadErr := LoadConfig(path)
		if loadErr != nil {
			return fmt.Errorf("loading existing config: %w", loadErr)
		}

		// Check if addresses need updating
		expectedAddrs := []string{serverAddrV4, serverAddrV6}
		needsUpdate := false
		if len(cfg.Interface.Addresses) != 2 {
			needsUpdate = true
		} else {
			for i, expected := range expectedAddrs {
				if cfg.Interface.Addresses[i] != expected {
					needsUpdate = true
					break
				}
			}
		}

		if needsUpdate {
			cfg.Interface.Addresses = expectedAddrs
			if saveErr := SaveConfig(path, cfg); saveErr != nil {
				return fmt.Errorf("updating subnet addresses in config: %w", saveErr)
			}
		}
		return nil
	}

	// Config doesn't exist, create new one
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	privKey, err := runCmd("wg", "genkey")
	if err != nil {
		return fmt.Errorf("generating server key: %w", err)
	}

	content := fmt.Sprintf("[Interface]\nAddress = %s, %s\nListenPort = %d\nMTU = %d\nPrivateKey = %s\n",
		serverAddrV4, serverAddrV6, listenPort, mtu, strings.TrimSpace(privKey))

	return os.WriteFile(path, []byte(content), 0o600)
}

// firstUsableIP returns the first usable IP address in a subnet
// For example: "10.8.0.0/24" -> "10.8.0.1/24"
func firstUsableIP(subnet string) (string, error) {
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		return "", err
	}

	// Get the network address
	networkAddr := prefix.Masked().Addr()

	// First usable IP is network address + 1
	firstIP := networkAddr.Next()
	if !firstIP.IsValid() {
		return "", fmt.Errorf("subnet %s has no usable addresses", subnet)
	}

	// Return with the same prefix length
	return fmt.Sprintf("%s/%d", firstIP.String(), prefix.Bits()), nil
}
