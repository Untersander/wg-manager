package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"wg-manager/internal/config"
	"wg-manager/internal/views"
	"wg-manager/internal/wireguard"

	"github.com/skip2/go-qrcode"
)

type App struct {
	Settings config.Settings
	Runner   wireguard.Runner
}

func NewApp(settings config.Settings) *App {
	return &App{
		Settings: settings,
		Runner: wireguard.Runner{
			InterfaceName: settings.InterfaceName,
			ConfigPath:    settings.ConfigPath,
		},
	}
}

func (a *App) Dashboard(w http.ResponseWriter, r *http.Request) {
	cfg, err := wireguard.LoadConfig(a.Settings.ConfigPath)
	if err != nil {
		http.Error(w, "failed loading config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	runtimeByKey, _ := a.Runner.ShowRuntime()

	peers := make([]views.PeerView, 0, len(cfg.Peers))
	for _, p := range cfg.Peers {
		rt := runtimeByKey[p.PublicKey]
		handshake := "never"
		if rt.LatestHandshakeEpoch > 0 {
			handshake = time.Unix(rt.LatestHandshakeEpoch, 0).Format(time.RFC3339)
		}
		peers = append(peers, views.PeerView{
			Name:       p.Name,
			AllowedIPs: strings.Join(p.AllowedIPs, ", "),
			Handshake:  handshake,
			Rx:         formatBytes(rt.TransferRx),
			Tx:         formatBytes(rt.TransferTx),
		})
	}

	data := views.PeersData{
		Peers:             peers,
		DefaultKeepalive:  a.Settings.DefaultKeepalive,
		DefaultDNS:        strings.Join(a.Settings.DefaultDNS, ", "),
		DefaultAllowedIPs: strings.Join(a.Settings.DefaultAllowedIPs, ", "),
		Error:             r.URL.Query().Get("err"),
	}

	nextAddr, err := wireguard.NextAvailableAddresses(
		a.Settings.SubnetV4,
		a.Settings.SubnetV6,
		cfg.Peers,
	)
	if err == nil {
		data.NextAddress = nextAddr
	}

	if err := views.PeersPage(data).Render(r.Context(), w); err != nil {
		slog.Error("failed rendering peers page", "error", err)
	}
}

func (a *App) Stats(w http.ResponseWriter, r *http.Request) {
	cfg, err := wireguard.LoadConfig(a.Settings.ConfigPath)
	if err != nil {
		http.Error(w, "failed loading config", http.StatusInternalServerError)
		return
	}

	runtimeByKey, _ := a.Runner.ShowRuntime()

	type PeerStat struct {
		Name      string `json:"name"`
		Rx        string `json:"rx"`
		Tx        string `json:"tx"`
		Handshake string `json:"handshake"`
	}

	stats := make([]PeerStat, 0, len(cfg.Peers))
	for _, p := range cfg.Peers {
		rt := runtimeByKey[p.PublicKey]
		handshake := "never"
		if rt.LatestHandshakeEpoch > 0 {
			handshake = time.Unix(rt.LatestHandshakeEpoch, 0).Format(time.RFC3339)
		}
		stats = append(stats, PeerStat{
			Name:      p.Name,
			Rx:        formatBytes(rt.TransferRx),
			Tx:        formatBytes(rt.TransferTx),
			Handshake: handshake,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		slog.Error("failed encoding stats", "error", err)
	}
}

func (a *App) SettingsPage(w http.ResponseWriter, r *http.Request) {
	cfg, err := wireguard.LoadConfig(a.Settings.ConfigPath)
	if err != nil {
		http.Error(w, "failed loading config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	data := views.SettingsData{
		ListenPort:        cfg.Interface.ListenPort,
		MTU:               cfg.Interface.MTU,
		EgressInterface:   a.Settings.EgressInterface,
		DefaultDNS:        strings.Join(a.Settings.DefaultDNS, ", "),
		DefaultAllowedIPs: strings.Join(a.Settings.DefaultAllowedIPs, ", "),
		Error:             r.URL.Query().Get("err"),
	}
	if err := views.SettingsPage(data).Render(r.Context(), w); err != nil {
		slog.Error("failed rendering settings page", "error", err)
	}
}

func (a *App) CreatePeer(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/?err=invalid+form", http.StatusSeeOther)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	address := strings.TrimSpace(r.FormValue("address"))
	if name == "" {
		http.Redirect(w, r, "/?err=name+required", http.StatusSeeOther)
		return
	}
	if err := validatePeerName(name); err != nil {
		http.Redirect(w, r, "/?err=invalid+peer+name", http.StatusSeeOther)
		return
	}
	if address != "" {
		if err := validateCIDRList(address); err != nil {
			http.Redirect(w, r, "/?err=invalid+address", http.StatusSeeOther)
			return
		}
	}

	keepalive, err := strconv.Atoi(r.FormValue("keepalive"))
	if err != nil {
		keepalive = 0
	}
	if keepalive < 0 {
		keepalive = 0
	}

	dns := strings.TrimSpace(r.FormValue("dns"))
	clientAllowedIPs := strings.TrimSpace(r.FormValue("client_allowed_ips"))
	if dns != "" {
		if err := validateDNSList(dns); err != nil {
			http.Redirect(w, r, "/?err=invalid+dns", http.StatusSeeOther)
			return
		}
	}
	if clientAllowedIPs != "" {
		if err := validateCIDRList(clientAllowedIPs); err != nil {
			http.Redirect(w, r, "/?err=invalid+allowed+ips", http.StatusSeeOther)
			return
		}
	}

	cfg, err := wireguard.LoadConfig(a.Settings.ConfigPath)
	if err != nil {
		http.Redirect(w, r, "/?err=failed+loading+config", http.StatusSeeOther)
		return
	}
	for _, p := range cfg.Peers {
		if p.Name == name {
			http.Redirect(w, r, "/?err=peer+name+exists", http.StatusSeeOther)
			return
		}
	}

	if address == "" {
		autoAddr, err := wireguard.NextAvailableAddresses(
			a.Settings.SubnetV4,
			a.Settings.SubnetV6,
			cfg.Peers,
		)
		if err != nil {
			http.Redirect(w, r, "/?err=no+available+addresses", http.StatusSeeOther)
			return
		}
		address = autoAddr
	}

	priv, pub, err := a.Runner.GenerateKeyPair()
	if err != nil {
		http.Redirect(w, r, "/?err=failed+key+generation", http.StatusSeeOther)
		return
	}

	cfg.Peers = append(cfg.Peers, wireguard.Peer{
		Name:                name,
		PublicKey:           pub,
		PrivateKey:          priv,
		AllowedIPs:          splitCSV(address),
		PersistentKeepalive: keepalive,
		DNS:                 splitCSV(dns),
		ClientAllowedIPs:    splitCSV(clientAllowedIPs),
	})

	if err := wireguard.SaveConfig(a.Settings.ConfigPath, cfg); err != nil {
		http.Redirect(w, r, "/?err=failed+saving+config", http.StatusSeeOther)
		return
	}
	if err := a.Runner.SyncConfig(); err != nil {
		http.Redirect(w, r, "/?err=failed+reloading+wireguard", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) DeletePeer(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	cfg, err := wireguard.LoadConfig(a.Settings.ConfigPath)
	if err != nil {
		http.Redirect(w, r, "/?err=failed+loading+config", http.StatusSeeOther)
		return
	}

	before := len(cfg.Peers)
	cfg.Peers = slices.DeleteFunc(cfg.Peers, func(p wireguard.Peer) bool {
		return p.Name == name
	})
	if len(cfg.Peers) == before {
		http.Redirect(w, r, "/?err=peer+not+found", http.StatusSeeOther)
		return
	}

	if err := wireguard.SaveConfig(a.Settings.ConfigPath, cfg); err != nil {
		http.Redirect(w, r, "/?err=failed+saving+config", http.StatusSeeOther)
		return
	}
	if err := a.Runner.SyncConfig(); err != nil {
		http.Redirect(w, r, "/?err=failed+reloading+wireguard", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) EditPeer(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	cfg, err := wireguard.LoadConfig(a.Settings.ConfigPath)
	if err != nil {
		http.Error(w, "failed loading config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var peer wireguard.Peer
	found := false
	for _, p := range cfg.Peers {
		if p.Name == name {
			peer = p
			found = true
			break
		}
	}
	if !found {
		http.NotFound(w, r)
		return
	}

	if err := views.EditPeerPage(views.EditPeerData{
		Name:              peer.Name,
		AllowedIPs:        strings.Join(peer.AllowedIPs, ", "),
		Keepalive:         peer.PersistentKeepalive,
		DNS:               strings.Join(peer.DNS, ", "),
		ClientAllowedIPs:  strings.Join(peer.ClientAllowedIPs, ", "),
		DefaultDNS:        strings.Join(a.Settings.DefaultDNS, ", "),
		DefaultAllowedIPs: strings.Join(a.Settings.DefaultAllowedIPs, ", "),
		Error:             r.URL.Query().Get("err"),
	}).Render(r.Context(), w); err != nil {
		slog.Error("failed rendering edit peer page", "error", err)
	}
}

func (a *App) UpdatePeer(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/peers/"+name+"?err=invalid+form", http.StatusSeeOther)
		return
	}

	address := strings.TrimSpace(r.FormValue("address"))
	keepalive, err := strconv.Atoi(r.FormValue("keepalive"))
	if err != nil {
		keepalive = 0
	}
	if keepalive < 0 {
		keepalive = 0
	}
	dns := strings.TrimSpace(r.FormValue("dns"))
	clientAllowedIPs := strings.TrimSpace(r.FormValue("client_allowed_ips"))

	if address != "" {
		if err := validateCIDRList(address); err != nil {
			http.Redirect(w, r, "/peers/"+name+"?err=invalid+address", http.StatusSeeOther)
			return
		}
	}
	if dns != "" {
		if err := validateDNSList(dns); err != nil {
			http.Redirect(w, r, "/peers/"+name+"?err=invalid+dns", http.StatusSeeOther)
			return
		}
	}
	if clientAllowedIPs != "" {
		if err := validateCIDRList(clientAllowedIPs); err != nil {
			http.Redirect(w, r, "/peers/"+name+"?err=invalid+allowed+ips", http.StatusSeeOther)
			return
		}
	}

	cfg, err := wireguard.LoadConfig(a.Settings.ConfigPath)
	if err != nil {
		http.Redirect(w, r, "/peers/"+name+"?err=failed+loading+config", http.StatusSeeOther)
		return
	}

	found := false
	for i, p := range cfg.Peers {
		if p.Name == name {
			if address != "" {
				cfg.Peers[i].AllowedIPs = splitCSV(address)
			}
			cfg.Peers[i].PersistentKeepalive = keepalive
			cfg.Peers[i].DNS = splitCSV(dns)
			cfg.Peers[i].ClientAllowedIPs = splitCSV(clientAllowedIPs)
			found = true
			break
		}
	}
	if !found {
		http.Redirect(w, r, "/?err=peer+not+found", http.StatusSeeOther)
		return
	}

	if err := wireguard.SaveConfig(a.Settings.ConfigPath, cfg); err != nil {
		http.Redirect(w, r, "/peers/"+name+"?err=failed+saving+config", http.StatusSeeOther)
		return
	}
	if err := a.Runner.SyncConfig(); err != nil {
		http.Redirect(w, r, "/peers/"+name+"?err=failed+reloading+wireguard", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/peers/"+name, http.StatusSeeOther)
}

func (a *App) DownloadPeerConfig(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	_, clientCfg, err := a.renderablePeer(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name+".conf"))
	if _, err := w.Write([]byte(clientCfg)); err != nil {
		slog.Error("failed writing peer config response", "peer", name, "error", err)
	}
}

func (a *App) PeerQR(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	_, clientCfg, err := a.renderablePeer(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	png, err := qrcode.Encode(clientCfg, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, "failed qr", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	if _, err := w.Write(png); err != nil {
		slog.Error("failed writing QR response", "peer", name, "error", err)
	}
}

func (a *App) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/settings?err=invalid+form", http.StatusSeeOther)
		return
	}

	port, err := strconv.Atoi(strings.TrimSpace(r.FormValue("listen_port")))
	if err != nil || port < 1 || port > 65535 {
		http.Redirect(w, r, "/settings?err=invalid+port", http.StatusSeeOther)
		return
	}
	mtu, err := strconv.Atoi(strings.TrimSpace(r.FormValue("mtu")))
	if err != nil || mtu < 1280 {
		http.Redirect(w, r, "/settings?err=invalid+mtu", http.StatusSeeOther)
		return
	}
	egress := strings.TrimSpace(r.FormValue("egress_interface"))
	if egress == "" {
		http.Redirect(w, r, "/settings?err=egress+required", http.StatusSeeOther)
		return
	}
	if err := validateInterface(egress); err != nil {
		http.Redirect(w, r, "/settings?err=invalid+egress+interface", http.StatusSeeOther)
		return
	}
	defaultDNS := strings.TrimSpace(r.FormValue("default_dns"))
	defaultAllowedIPs := strings.TrimSpace(r.FormValue("default_allowed_ips"))

	if defaultDNS != "" {
		if err := validateDNSList(defaultDNS); err != nil {
			http.Redirect(w, r, "/settings?err=invalid+dns", http.StatusSeeOther)
			return
		}
	}
	if defaultAllowedIPs != "" {
		if err := validateCIDRList(defaultAllowedIPs); err != nil {
			http.Redirect(w, r, "/settings?err=invalid+allowed+ips", http.StatusSeeOther)
			return
		}
	}

	cfg, err := wireguard.LoadConfig(a.Settings.ConfigPath)
	if err != nil {
		http.Redirect(w, r, "/settings?err=failed+loading+config", http.StatusSeeOther)
		return
	}
	cfg.Interface.ListenPort = port
	cfg.Interface.MTU = mtu

	if err := wireguard.SaveConfig(a.Settings.ConfigPath, cfg); err != nil {
		http.Redirect(w, r, "/settings?err=failed+saving+config", http.StatusSeeOther)
		return
	}
	if err := a.Runner.SyncConfig(); err != nil {
		http.Redirect(w, r, "/settings?err=failed+reloading+wireguard", http.StatusSeeOther)
		return
	}
	if err := wireguard.ApplyMasquerade(egress, a.Settings.SubnetV4, a.Settings.SubnetV6); err != nil {
		http.Redirect(w, r, "/settings?err=failed+applying+nft+rules", http.StatusSeeOther)
		return
	}
	a.Settings.EgressInterface = egress
	if defaultDNS != "" {
		a.Settings.DefaultDNS = splitCSV(defaultDNS)
	}
	if defaultAllowedIPs != "" {
		a.Settings.DefaultAllowedIPs = splitCSV(defaultAllowedIPs)
	}

	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (a *App) renderablePeer(name string) (wireguard.Peer, string, error) {
	cfg, err := wireguard.LoadConfig(a.Settings.ConfigPath)
	if err != nil {
		return wireguard.Peer{}, "", err
	}

	var peer wireguard.Peer
	found := false
	for _, p := range cfg.Peers {
		if p.Name == name {
			peer = p
			found = true
			break
		}
	}
	if !found {
		return wireguard.Peer{}, "", fmt.Errorf("peer not found")
	}

	serverPriv := cfg.Interface.PrivateKey
	if serverPriv == "" {
		return wireguard.Peer{}, "", fmt.Errorf("server private key missing")
	}
	_, serverPub, err := a.Runner.GenerateKeyPairFromPrivate(serverPriv)
	if err != nil {
		return wireguard.Peer{}, "", err
	}

	dns := a.Settings.DefaultDNS
	if len(peer.DNS) > 0 {
		dns = peer.DNS
	}
	allowedIPs := a.Settings.DefaultAllowedIPs
	if len(peer.ClientAllowedIPs) > 0 {
		allowedIPs = peer.ClientAllowedIPs
	}

	clientCfg := wireguard.BuildClientConfig(wireguard.ClientConfigInput{
		PrivateKey:          peer.PrivateKey,
		Address:             strings.Join(peer.AllowedIPs, ", "),
		DNS:                 dns,
		ServerPublicKey:     serverPub,
		Endpoint:            fmt.Sprintf("%s:%d", a.Settings.Host, cfg.Interface.ListenPort),
		AllowedIPs:          allowedIPs,
		PersistentKeepalive: peer.PersistentKeepalive,
	})

	return peer, clientCfg, nil
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

func formatBytes(b uint64) string {
	if b == 0 {
		return "0 B"
	}
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
