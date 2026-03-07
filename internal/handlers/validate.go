package handlers

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

var (
	peerNameRegex  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)
	interfaceRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
)

func validatePeerName(name string) error {
	if len(name) == 0 || len(name) > 63 {
		return fmt.Errorf("name must be 1-63 characters")
	}
	if !peerNameRegex.MatchString(name) {
		return fmt.Errorf("name must start with alphanumeric and contain only alphanumerics, hyphens, or underscores")
	}
	return nil
}

func validateInterface(iface string) error {
	if len(iface) == 0 || len(iface) > 15 {
		return fmt.Errorf("interface name must be 1-15 characters")
	}
	if !interfaceRegex.MatchString(iface) {
		return fmt.Errorf("interface name contains invalid characters")
	}
	return nil
}

func validateCIDRList(s string) error {
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, err := netip.ParsePrefix(part); err != nil {
			return fmt.Errorf("invalid CIDR %q: %w", part, err)
		}
	}
	return nil
}

func validateDNSList(s string) error {
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, err := netip.ParseAddr(part); err != nil {
			return fmt.Errorf("invalid DNS address %q: %w", part, err)
		}
	}
	return nil
}
