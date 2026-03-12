package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wg-manager/internal/config"
	"wg-manager/internal/wireguard"
)

// mockRunner satisfies RunnerIface without calling any wg binaries.
type mockRunner struct {
	syncErr     error
	keyPairPriv string
	keyPairPub  string
	keyPairErr  error
	runtimeData map[string]wireguard.PeerRuntime
}

func (m *mockRunner) GenerateKeyPair() (string, string, error) {
	if m.keyPairErr != nil {
		return "", "", m.keyPairErr
	}
	priv := m.keyPairPriv
	if priv == "" {
		priv = "MOCKPRIV="
	}
	pub := m.keyPairPub
	if pub == "" {
		pub = "MOCKPUB="
	}
	return priv, pub, nil
}

func (m *mockRunner) GenerateKeyPairFromPrivate(priv string) (string, string, error) {
	return priv, "MOCKSERVERPUB=", nil
}

func (m *mockRunner) SyncConfig() error {
	return m.syncErr
}

func (m *mockRunner) ShowRuntime() (map[string]wireguard.PeerRuntime, error) {
	if m.runtimeData != nil {
		return m.runtimeData, nil
	}
	return map[string]wireguard.PeerRuntime{}, nil
}

// newTestApp builds an App backed by a temp config file and a mock runner.
func newTestApp(t *testing.T) (*App, string) {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "wg0.conf")

	cfg := wireguard.Config{
		Interface: wireguard.Interface{
			Addresses:  []string{"10.8.0.1/24"},
			ListenPort: 51820,
			MTU:        1420,
			PrivateKey: "SERVERPRIV=",
		},
	}
	if err := wireguard.SaveConfig(configPath, cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	settings := config.Settings{
		ConfigPath:        configPath,
		InterfaceName:     "wg0",
		Host:              "vpn.example.com",
		SubnetV4:          "10.8.0.0/24",
		SubnetV6:          "fd42::/64",
		DefaultDNS:        []string{"1.1.1.1"},
		DefaultAllowedIPs: []string{"0.0.0.0/0"},
		DefaultKeepalive:  0,
	}

	app := &App{
		Settings: settings,
		Runner:   &mockRunner{},
	}
	return app, configPath
}

func TestDashboard(t *testing.T) {
	app, _ := newTestApp(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	app.Dashboard(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestCreatePeer(t *testing.T) {
	app, configPath := newTestApp(t)

	form := url.Values{}
	form.Set("name", "test-peer")
	form.Set("csrf_token", "ignored-in-unit-test")

	req := httptest.NewRequest(http.MethodPost, "/peers", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	app.CreatePeer(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("status = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/" {
		t.Errorf("Location = %q, want /", loc)
	}

	// Verify peer was written to config
	cfg, err := wireguard.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Peers) != 1 {
		t.Fatalf("Peers len = %d, want 1", len(cfg.Peers))
	}
	if cfg.Peers[0].Name != "test-peer" {
		t.Errorf("peer name = %q, want \"test-peer\"", cfg.Peers[0].Name)
	}
}

func TestCreatePeer_EmptyName(t *testing.T) {
	app, _ := newTestApp(t)

	form := url.Values{}
	form.Set("name", "")

	req := httptest.NewRequest(http.MethodPost, "/peers", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	app.CreatePeer(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("status = %d, want 303", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "err=") {
		t.Errorf("expected error in redirect location, got %q", loc)
	}
}

func TestCreatePeer_DuplicateName(t *testing.T) {
	app, configPath := newTestApp(t)

	// Pre-populate a peer
	cfg, _ := wireguard.LoadConfig(configPath)
	cfg.Peers = append(cfg.Peers, wireguard.Peer{Name: "alice", PublicKey: "PUB="})
	_ = wireguard.SaveConfig(configPath, cfg)

	form := url.Values{}
	form.Set("name", "alice")

	req := httptest.NewRequest(http.MethodPost, "/peers", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	app.CreatePeer(w, req)

	loc := w.Result().Header.Get("Location")
	if !strings.Contains(loc, "err=") {
		t.Errorf("expected error redirect for duplicate name, got %q", loc)
	}
}

func TestDeletePeer(t *testing.T) {
	app, configPath := newTestApp(t)

	// Pre-populate a peer
	cfg, _ := wireguard.LoadConfig(configPath)
	cfg.Peers = append(cfg.Peers, wireguard.Peer{Name: "alice", PublicKey: "PUB="})
	_ = wireguard.SaveConfig(configPath, cfg)

	req := httptest.NewRequest(http.MethodPost, "/peers/alice/delete", nil)
	req.SetPathValue("name", "alice")
	w := httptest.NewRecorder()
	app.DeletePeer(w, req)

	if w.Result().StatusCode != http.StatusSeeOther {
		t.Errorf("status = %d, want 303", w.Result().StatusCode)
	}

	cfg, _ = wireguard.LoadConfig(configPath)
	if len(cfg.Peers) != 0 {
		t.Errorf("expected 0 peers after delete, got %d", len(cfg.Peers))
	}
}

func TestDeletePeer_NotFound(t *testing.T) {
	app, _ := newTestApp(t)

	req := httptest.NewRequest(http.MethodPost, "/peers/nobody/delete", nil)
	req.SetPathValue("name", "nobody")
	w := httptest.NewRecorder()
	app.DeletePeer(w, req)

	loc := w.Result().Header.Get("Location")
	if !strings.Contains(loc, "err=") {
		t.Errorf("expected error redirect, got %q", loc)
	}
}

func TestEditPeer_NotFound(t *testing.T) {
	app, _ := newTestApp(t)

	req := httptest.NewRequest(http.MethodGet, "/peers/nobody", nil)
	req.SetPathValue("name", "nobody")
	w := httptest.NewRecorder()
	app.EditPeer(w, req)

	if w.Result().StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Result().StatusCode)
	}
}

func TestStats(t *testing.T) {
	app, _ := newTestApp(t)

	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	w := httptest.NewRecorder()
	app.Stats(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		in   uint64
		want string
	}{
		{0, "0 B"},
		{500, "500 B"},
		{1024, "1.0 KB"},
		{1024 * 1024, "1.0 MB"},
		{1536 * 1024, "1.5 MB"},
	}
	for _, tt := range tests {
		got := formatBytes(tt.in)
		if got != tt.want {
			t.Errorf("formatBytes(%d) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSplitCSV(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"a,b,c", []string{"a", "b", "c"}},
		{" a , b ", []string{"a", "b"}},
		{"", []string{}},
		{"single", []string{"single"}},
	}
	for _, tt := range tests {
		got := splitCSV(tt.in)
		if len(got) != len(tt.want) {
			t.Errorf("splitCSV(%q) = %v, want %v", tt.in, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("splitCSV(%q)[%d] = %q, want %q", tt.in, i, got[i], tt.want[i])
			}
		}
	}
}

func TestDownloadPeerConfig(t *testing.T) {
	app, configPath := newTestApp(t)

	// Pre-populate a peer with a private key so renderablePeer works
	cfg, _ := wireguard.LoadConfig(configPath)
	cfg.Peers = append(cfg.Peers, wireguard.Peer{
		Name:       "alice",
		PublicKey:  "ALICEPUB=",
		PrivateKey: "ALICEPRIV=",
		AllowedIPs: []string{"10.8.0.2/32"},
	})
	_ = wireguard.SaveConfig(configPath, cfg)

	req := httptest.NewRequest(http.MethodGet, "/peers/alice/config", nil)
	req.SetPathValue("name", "alice")
	w := httptest.NewRecorder()
	app.DownloadPeerConfig(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	body := w.Body.String()
	if !strings.Contains(body, "[Interface]") {
		t.Errorf("expected WireGuard config in body, got:\n%s", body)
	}
	// Verify filename in Content-Disposition
	cd := resp.Header.Get("Content-Disposition")
	if !strings.Contains(cd, "alice.conf") {
		t.Errorf("Content-Disposition = %q, want alice.conf", cd)
	}
}

// TestCreatePeer_InvalidName tests that an invalid peer name is rejected.
func TestCreatePeer_InvalidName(t *testing.T) {
	app, _ := newTestApp(t)

	form := url.Values{}
	form.Set("name", "-invalid")

	req := httptest.NewRequest(http.MethodPost, "/peers", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	app.CreatePeer(w, req)

	loc := w.Result().Header.Get("Location")
	if !strings.Contains(loc, "err=") {
		t.Errorf("expected error for invalid name, got %q", loc)
	}
}

// TestCreatePeer_InvalidAddress ensures a bad CIDR address is rejected.
func TestCreatePeer_InvalidAddress(t *testing.T) {
	app, _ := newTestApp(t)

	form := url.Values{}
	form.Set("name", "valid-name")
	form.Set("address", "notacidr")

	req := httptest.NewRequest(http.MethodPost, "/peers", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	app.CreatePeer(w, req)

	loc := w.Result().Header.Get("Location")
	if !strings.Contains(loc, "err=") {
		t.Errorf("expected error for invalid address, got %q", loc)
	}
}

// Ensure wireguard.Runner satisfies RunnerIface at compile time.
var _ RunnerIface = wireguard.Runner{}

// Clean up the temp dir automatically via testing.T.TempDir()
func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
