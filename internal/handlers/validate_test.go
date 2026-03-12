package handlers

import (
	"strings"
	"testing"
)

func TestValidatePeerName(t *testing.T) {
	valid := []string{
		"alice",
		"bob-mobile",
		"peer_1",
		"A1",
		"a",
		strings.Repeat("a", 63),
	}
	for _, name := range valid {
		if err := validatePeerName(name); err != nil {
			t.Errorf("validatePeerName(%q) = %v, want nil", name, err)
		}
	}

	invalid := []string{
		"",
		"-startswithhyphen",
		"_startswithunderscore",
		"has space",
		"has.dot",
		strings.Repeat("a", 64),
	}
	for _, name := range invalid {
		if err := validatePeerName(name); err == nil {
			t.Errorf("validatePeerName(%q) = nil, want error", name)
		}
	}
}

func TestValidateInterface(t *testing.T) {
	valid := []string{"eth0", "wg0", "lo", "br-lan", strings.Repeat("a", 15)}
	for _, iface := range valid {
		if err := validateInterface(iface); err != nil {
			t.Errorf("validateInterface(%q) = %v, want nil", iface, err)
		}
	}

	invalid := []string{"", strings.Repeat("a", 16), "eth 0", "eth.0"}
	for _, iface := range invalid {
		if err := validateInterface(iface); err == nil {
			t.Errorf("validateInterface(%q) = nil, want error", iface)
		}
	}
}

func TestValidateCIDRList(t *testing.T) {
	valid := []string{
		"10.0.0.0/8",
		"10.0.0.0/8, 192.168.1.0/24",
		"0.0.0.0/0, ::/0",
		"",
	}
	for _, s := range valid {
		if err := validateCIDRList(s); err != nil {
			t.Errorf("validateCIDRList(%q) = %v, want nil", s, err)
		}
	}

	invalid := []string{
		"notacidr",
		"10.0.0.1",
		"10.0.0.0/8, bad",
	}
	for _, s := range invalid {
		if err := validateCIDRList(s); err == nil {
			t.Errorf("validateCIDRList(%q) = nil, want error", s)
		}
	}
}

func TestValidateDNSList(t *testing.T) {
	valid := []string{
		"1.1.1.1",
		"1.1.1.1, 8.8.8.8",
		"2606:4700:4700::1111",
		"",
	}
	for _, s := range valid {
		if err := validateDNSList(s); err != nil {
			t.Errorf("validateDNSList(%q) = %v, want nil", s, err)
		}
	}

	invalid := []string{
		"example.com",
		"1.1.1.1, notanip",
		"256.256.256.256",
	}
	for _, s := range invalid {
		if err := validateDNSList(s); err == nil {
			t.Errorf("validateDNSList(%q) = nil, want error", s)
		}
	}
}
