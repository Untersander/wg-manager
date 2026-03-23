package wireguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleConfig = `[Interface]
Address = 10.8.0.1/24, fd42::1/64
ListenPort = 51820
MTU = 1420
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

[Peer]
# Name = alice
# PrivateKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
# DNS = 1.1.1.1, 2606:4700:4700::1111
# ClientAllowedIPs = 0.0.0.0/0, ::/0
PublicKey = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=
AllowedIPs = 10.8.0.2/32, fd42::2/128
PersistentKeepalive = 25

[Peer]
# Name = bob
PublicKey = DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=
AllowedIPs = 10.8.0.3/32
`

func TestLoadConfig(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "wg*.conf")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(sampleConfig); err != nil {
		t.Fatal(err)
	}

	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(f.Name())
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	// Interface
	if cfg.Interface.ListenPort != 51820 {
		t.Errorf("ListenPort = %d, want 51820", cfg.Interface.ListenPort)
	}
	if cfg.Interface.MTU != 1420 {
		t.Errorf("MTU = %d, want 1420", cfg.Interface.MTU)
	}
	if len(cfg.Interface.Addresses) != 2 {
		t.Errorf("Addresses len = %d, want 2", len(cfg.Interface.Addresses))
	}
	if cfg.Interface.PrivateKey != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" {
		t.Errorf("PrivateKey mismatch: %q", cfg.Interface.PrivateKey)
	}

	// Peers
	if len(cfg.Peers) != 2 {
		t.Fatalf("Peers len = %d, want 2", len(cfg.Peers))
	}

	alice := cfg.Peers[0]
	if alice.Name != "alice" {
		t.Errorf("alice.Name = %q, want \"alice\"", alice.Name)
	}
	if alice.PublicKey != "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=" {
		t.Errorf("alice.PublicKey mismatch")
	}
	if alice.PrivateKey != "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" {
		t.Errorf("alice.PrivateKey mismatch")
	}
	if len(alice.DNS) != 2 {
		t.Errorf("alice.DNS len = %d, want 2", len(alice.DNS))
	}
	if len(alice.ClientAllowedIPs) != 2 {
		t.Errorf("alice.ClientAllowedIPs len = %d, want 2", len(alice.ClientAllowedIPs))
	}
	if alice.PersistentKeepalive != 25 {
		t.Errorf("alice.Keepalive = %d, want 25", alice.PersistentKeepalive)
	}
	if len(alice.AllowedIPs) != 2 {
		t.Errorf("alice.AllowedIPs len = %d, want 2", len(alice.AllowedIPs))
	}

	bob := cfg.Peers[1]
	if bob.Name != "bob" {
		t.Errorf("bob.Name = %q", bob.Name)
	}
	if len(bob.AllowedIPs) != 1 || bob.AllowedIPs[0] != "10.8.0.3/32" {
		t.Errorf("bob.AllowedIPs = %v", bob.AllowedIPs)
	}
}

func TestLoadConfig_NotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/path/wg0.conf")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestSaveAndLoadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wg0.conf")

	cfg := Config{
		Interface: Interface{
			Addresses:  []string{"10.8.0.1/24"},
			ListenPort: 51820,
			MTU:        1420,
			PrivateKey: "PRIVATEKEY=",
		},
		Peers: []Peer{
			{
				Name:                "test-peer",
				PublicKey:           "PUBKEY=",
				PrivateKey:          "PEERPRIV=",
				AllowedIPs:          []string{"10.8.0.2/32"},
				PersistentKeepalive: 60,
				DNS:                 []string{"1.1.1.1"},
				ClientAllowedIPs:    []string{"0.0.0.0/0"},
			},
		},
	}

	if err := SaveConfig(path, cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if loaded.Interface.ListenPort != cfg.Interface.ListenPort {
		t.Errorf("ListenPort mismatch")
	}
	if len(loaded.Peers) != 1 {
		t.Fatalf("Peers len = %d", len(loaded.Peers))
	}
	p := loaded.Peers[0]
	if p.Name != "test-peer" {
		t.Errorf("Name = %q", p.Name)
	}
	if p.PublicKey != "PUBKEY=" {
		t.Errorf("PublicKey = %q", p.PublicKey)
	}
	if p.PrivateKey != "PEERPRIV=" {
		t.Errorf("PrivateKey = %q", p.PrivateKey)
	}
	if p.PersistentKeepalive != 60 {
		t.Errorf("Keepalive = %d", p.PersistentKeepalive)
	}
	if len(p.DNS) != 1 || p.DNS[0] != "1.1.1.1" {
		t.Errorf("DNS = %v", p.DNS)
	}
	if len(p.ClientAllowedIPs) != 1 || p.ClientAllowedIPs[0] != "0.0.0.0/0" {
		t.Errorf("ClientAllowedIPs = %v", p.ClientAllowedIPs)
	}
}

func TestBuildConfig_NoPeers(t *testing.T) {
	cfg := Config{
		Interface: Interface{
			Addresses:  []string{"10.8.0.1/24"},
			ListenPort: 51820,
		},
	}
	got := buildConfig(cfg)
	if !strings.Contains(got, "ListenPort = 51820") {
		t.Errorf("missing ListenPort in output:\n%s", got)
	}
	if !strings.Contains(got, "Address = 10.8.0.1/24") {
		t.Errorf("missing Address in output:\n%s", got)
	}
	if strings.Contains(got, "[Peer]") {
		t.Errorf("unexpected [Peer] section in output:\n%s", got)
	}
}

func TestBuildConfig_ZeroKeepalive(t *testing.T) {
	cfg := Config{
		Interface: Interface{ListenPort: 51820},
		Peers: []Peer{
			{Name: "p", PublicKey: "PUB=", AllowedIPs: []string{"10.8.0.2/32"}, PersistentKeepalive: 0},
		},
	}
	got := buildConfig(cfg)
	if strings.Contains(got, "PersistentKeepalive") {
		t.Errorf("PersistentKeepalive = 0 should be omitted:\n%s", got)
	}
}
