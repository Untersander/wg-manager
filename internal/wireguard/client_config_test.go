package wireguard

import (
	"strings"
	"testing"
)

func TestBuildClientConfig(t *testing.T) {
	in := ClientConfigInput{
		PrivateKey:      "CLIENTPRIV=",
		Address:         "10.8.0.2/32, fd42::2/128",
		DNS:             []string{"1.1.1.1", "2606:4700:4700::1111"},
		ServerPublicKey: "SERVERPUB=",
		Endpoint:        "example.com:51820",
		AllowedIPs:      []string{"0.0.0.0/0", "::/0"},
	}
	got := BuildClientConfig(in)

	for _, want := range []string{
		"[Interface]",
		"PrivateKey = CLIENTPRIV=",
		"Address = 10.8.0.2/32, fd42::2/128",
		"DNS = 1.1.1.1, 2606:4700:4700::1111",
		"[Peer]",
		"PublicKey = SERVERPUB=",
		"AllowedIPs = 0.0.0.0/0, ::/0",
		"Endpoint = example.com:51820",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}

	if strings.Contains(got, "PersistentKeepalive") {
		t.Errorf("PersistentKeepalive = 0 should be omitted:\n%s", got)
	}
}

func TestBuildClientConfig_WithKeepalive(t *testing.T) {
	in := ClientConfigInput{
		PrivateKey:          "PRIV=",
		Address:             "10.8.0.2/32",
		ServerPublicKey:     "PUB=",
		Endpoint:            "vpn.example.com:51820",
		AllowedIPs:          []string{"0.0.0.0/0"},
		PersistentKeepalive: 25,
	}
	got := BuildClientConfig(in)

	if !strings.Contains(got, "PersistentKeepalive = 25") {
		t.Errorf("expected PersistentKeepalive = 25 in output:\n%s", got)
	}
}

func TestBuildClientConfig_NoDNS(t *testing.T) {
	in := ClientConfigInput{
		PrivateKey:      "PRIV=",
		Address:         "10.8.0.2/32",
		ServerPublicKey: "PUB=",
		Endpoint:        "vpn.example.com:51820",
		AllowedIPs:      []string{"0.0.0.0/0"},
	}
	got := BuildClientConfig(in)

	if strings.Contains(got, "DNS") {
		t.Errorf("DNS line should be absent when no DNS provided:\n%s", got)
	}
}
