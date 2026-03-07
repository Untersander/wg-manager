package handlers

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"wg-manager/internal/config"
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

	type peerView struct {
		Name       string
		AllowedIPs string
		Handshake  string
		Rx         string
		Tx         string
	}

	peers := make([]peerView, 0, len(cfg.Peers))
	for _, p := range cfg.Peers {
		rt := runtimeByKey[p.PublicKey]
		handshake := "never"
		if rt.LatestHandshakeEpoch > 0 {
			handshake = time.Unix(rt.LatestHandshakeEpoch, 0).Format(time.RFC3339)
		}
		peers = append(peers, peerView{
			Name:       p.Name,
			AllowedIPs: strings.Join(p.AllowedIPs, ", "),
			Handshake:  handshake,
			Rx:         fmt.Sprintf("%d", rt.TransferRx),
			Tx:         fmt.Sprintf("%d", rt.TransferTx),
		})
	}

	data := map[string]any{
		"ListenPort":       cfg.Interface.ListenPort,
		"MTU":              cfg.Interface.MTU,
		"EgressInterface":  a.Settings.EgressInterface,
		"DefaultKeepalive": a.Settings.DefaultKeepalive,
		"Peers":            peers,
		"Error":            r.URL.Query().Get("err"),
	}
	_ = dashboardTemplate.Execute(w, data)
}

func (a *App) CreatePeer(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/?err=invalid+form", http.StatusSeeOther)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	address := strings.TrimSpace(r.FormValue("address"))
	if name == "" || address == "" {
		http.Redirect(w, r, "/?err=name+and+address+required", http.StatusSeeOther)
		return
	}

	keepalive, _ := strconv.Atoi(r.FormValue("keepalive"))
	if keepalive < 0 {
		keepalive = 0
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
	})

	if err := wireguard.SaveConfig(a.Settings.ConfigPath, cfg); err != nil {
		http.Redirect(w, r, "/?err=failed+saving+config", http.StatusSeeOther)
		return
	}
	if err := a.Runner.SyncConfig(); err != nil {
		http.Redirect(w, r, "/?err=failed+reloading+wireguard", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/peers/"+name, http.StatusSeeOther)
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

func (a *App) PeerDetails(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	peer, clientCfg, err := a.renderablePeer(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	png, err := qrcode.Encode(clientCfg, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, "failed qr", http.StatusInternalServerError)
		return
	}

	_ = peerTemplate.Execute(w, map[string]any{
		"Name":   peer.Name,
		"Config": clientCfg,
		"QRCode": base64.StdEncoding.EncodeToString(png),
	})
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
	_, _ = w.Write([]byte(clientCfg))
}

func (a *App) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/?err=invalid+form", http.StatusSeeOther)
		return
	}

	port, err := strconv.Atoi(strings.TrimSpace(r.FormValue("listen_port")))
	if err != nil || port < 1 || port > 65535 {
		http.Redirect(w, r, "/?err=invalid+port", http.StatusSeeOther)
		return
	}
	mtu, err := strconv.Atoi(strings.TrimSpace(r.FormValue("mtu")))
	if err != nil || mtu < 1280 {
		http.Redirect(w, r, "/?err=invalid+mtu", http.StatusSeeOther)
		return
	}
	egress := strings.TrimSpace(r.FormValue("egress_interface"))
	if egress == "" {
		http.Redirect(w, r, "/?err=egress+required", http.StatusSeeOther)
		return
	}

	cfg, err := wireguard.LoadConfig(a.Settings.ConfigPath)
	if err != nil {
		http.Redirect(w, r, "/?err=failed+loading+config", http.StatusSeeOther)
		return
	}
	cfg.Interface.ListenPort = port
	cfg.Interface.MTU = mtu

	if err := wireguard.SaveConfig(a.Settings.ConfigPath, cfg); err != nil {
		http.Redirect(w, r, "/?err=failed+saving+config", http.StatusSeeOther)
		return
	}
	if err := a.Runner.SyncConfig(); err != nil {
		http.Redirect(w, r, "/?err=failed+reloading+wireguard", http.StatusSeeOther)
		return
	}
	if err := wireguard.ApplyMasquerade(egress); err != nil {
		http.Redirect(w, r, "/?err=failed+applying+nft+rules", http.StatusSeeOther)
		return
	}
	a.Settings.EgressInterface = egress

	http.Redirect(w, r, "/", http.StatusSeeOther)
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

	clientCfg := wireguard.BuildClientConfig(wireguard.ClientConfigInput{
		PrivateKey:          peer.PrivateKey,
		Address:             strings.Join(peer.AllowedIPs, ", "),
		DNS:                 a.Settings.DefaultDNS,
		ServerPublicKey:     serverPub,
		Endpoint:            fmt.Sprintf("%s:%d", a.Settings.Host, cfg.Interface.ListenPort),
		AllowedIPs:          a.Settings.DefaultAllowedIPs,
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
