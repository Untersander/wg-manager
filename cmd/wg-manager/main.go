package main

import (
	"log"
	"net/http"
	"strings"

	"wg-manager/internal/config"
	"wg-manager/internal/handlers"
	"wg-manager/internal/wireguard"
)

func main() {
	settings, err := config.Load()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	if err := wireguard.EnableIPForwarding(); err != nil {
		log.Printf("warning: ip forwarding: %v", err)
	}

	if err := wireguard.EnsureConfig(
		settings.ConfigPath,
		settings.ListenPort,
		settings.MTU,
		settings.ServerAddressV4,
		settings.ServerAddressV6,
	); err != nil {
		log.Fatalf("failed to ensure wireguard config: %v", err)
	}

	runner := wireguard.Runner{InterfaceName: settings.InterfaceName, ConfigPath: settings.ConfigPath}
	if err := runner.EnsureInterfaceUp(); err != nil {
		log.Printf("warning: failed to ensure interface up: %v", err)
	}
	if err := wireguard.ApplyMasquerade(settings.EgressInterface); err != nil {
		log.Printf("warning: failed to apply nftables masquerade: %v", err)
	}

	auth := handlers.NewAuth(settings.Password, settings.SessionCookieName)
	app := handlers.NewApp(settings)

	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))))

	mux.HandleFunc("GET /login", auth.LoginGet)
	mux.HandleFunc("POST /login", auth.LoginPost)
	mux.HandleFunc("POST /logout", auth.Logout)

	mux.Handle("GET /{$}", auth.Require(http.HandlerFunc(app.Dashboard)))
	mux.Handle("GET /settings", auth.Require(http.HandlerFunc(app.SettingsPage)))
	mux.Handle("POST /settings", auth.Require(http.HandlerFunc(app.UpdateSettings)))
	mux.Handle("POST /peers", auth.Require(http.HandlerFunc(app.CreatePeer)))
	mux.Handle("GET /peers/{name}", auth.Require(http.HandlerFunc(app.EditPeer)))
	mux.Handle("POST /peers/{name}", auth.Require(http.HandlerFunc(app.UpdatePeer)))
	mux.Handle("GET /peers/{name}/config", auth.Require(http.HandlerFunc(app.DownloadPeerConfig)))
	mux.Handle("GET /peers/{name}/qr", auth.Require(http.HandlerFunc(app.PeerQR)))
	mux.Handle("POST /peers/{name}/delete", auth.Require(http.HandlerFunc(app.DeletePeer)))

	addr := settings.HTTPAddr
	host := addr
	if strings.HasPrefix(addr, ":") {
		host = "localhost" + addr
	}
	log.Printf("wg-manager listening on http://%s", host)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server stopped: %v", err)
	}
}
