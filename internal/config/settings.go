package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Settings struct {
	HTTPAddr          string
	SessionCookieName string
	Password          string
	ConfigPath        string
	InterfaceName     string
	Host              string
	ListenPort        int
	MTU               int
	DefaultDNS        []string
	DefaultAllowedIPs []string
	DefaultKeepalive  int
	EgressInterface   string
	SubnetV4          string
	SubnetV6          string
}

func Load() (Settings, error) {
	port, err := intFromEnv("WG_PORT", 51820)
	if err != nil {
		return Settings{}, err
	}

	mtu, err := intFromEnv("WG_MTU", 1420)
	if err != nil {
		return Settings{}, err
	}

	keepalive, err := intFromEnv("WG_PERSISTENT_KEEPALIVE", 25)
	if err != nil {
		return Settings{}, err
	}

	interfaceName := getEnv("WG_INTERFACE_NAME", "wg0")
	configDir := getEnv("WG_CONFIG_PATH", "/etc/wireguard")
	configPath := filepath.Join(configDir, interfaceName+".conf")

	s := Settings{
		HTTPAddr:          getEnv("HTTP_ADDR", ":8080"),
		SessionCookieName: getEnv("HTTP_SESSION_COOKIE", "wg-manager-session"),
		Password:          os.Getenv("HTTP_PASSWORD"),
		ConfigPath:        configPath,
		InterfaceName:     interfaceName,
		Host:              strings.TrimSpace(os.Getenv("WG_HOST")),
		ListenPort:        port,
		MTU:               mtu,
		DefaultDNS:        splitCSV(getEnv("WG_CLIENT_DNS", "1.1.1.1,2606:4700:4700::1111")),
		DefaultAllowedIPs: splitCSV(getEnv("WG_ALLOWED_IPS", "0.0.0.0/0,::/0")),
		DefaultKeepalive:  keepalive,
		EgressInterface:   getEnv("WG_EGRESS_INTERFACE", "eth0"),
		SubnetV4:          getEnv("WG_SUBNET_V4", "10.8.0.0/24"),
		SubnetV6:          getEnv("WG_SUBNET_V6", "fd42::/64"),
	}

	if s.Password == "" {
		return Settings{}, errors.New("HTTP_PASSWORD is required")
	}
	if s.Host == "" {
		return Settings{}, errors.New("WG_HOST is required")
	}

	return s, nil
}

func intFromEnv(name string, fallback int) (int, error) {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", name, err)
	}
	return parsed, nil
}

func splitCSV(v string) []string {
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

func getEnv(name, fallback string) string {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback
	}
	return v
}
