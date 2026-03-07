package main

import (
	"log"
	"net/http"
	"os"
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

	if _, err := os.Stat(settings.ConfigPath); err != nil {
		log.Fatalf("wireguard config missing at %s", settings.ConfigPath)
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
	mux.Handle("POST /settings", auth.Require(http.HandlerFunc(app.UpdateSettings)))
	mux.Handle("POST /peers", auth.Require(http.HandlerFunc(app.CreatePeer)))
	mux.Handle("GET /peers/{name}", auth.Require(http.HandlerFunc(app.PeerDetails)))
	mux.Handle("GET /peers/{name}/config", auth.Require(http.HandlerFunc(app.DownloadPeerConfig)))
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
