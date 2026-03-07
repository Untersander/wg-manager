package main

import (
	"log/slog"
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
		slog.Error("config error", "error", err)
		os.Exit(1)
	}

	if err := wireguard.EnableIPForwarding(); err != nil {
		slog.Warn("ip forwarding failed", "error", err)
	}

	if err := wireguard.EnsureConfig(
		settings.ConfigPath,
		settings.ListenPort,
		settings.MTU,
		settings.SubnetV4,
		settings.SubnetV6,
	); err != nil {
		slog.Error("failed to ensure wireguard config", "error", err)
		os.Exit(1)
	}

	runner := wireguard.Runner{InterfaceName: settings.InterfaceName, ConfigPath: settings.ConfigPath}
	if err := runner.EnsureInterfaceUp(); err != nil {
		slog.Warn("failed to ensure interface up", "error", err)
	}
	if err := wireguard.ApplyMasquerade(settings.EgressInterface, settings.SubnetV4, settings.SubnetV6); err != nil {
		slog.Warn("failed to apply nftables masquerade", "error", err)
	}

	auth := handlers.NewAuth(settings.Password, settings.SessionCookieName)
	app := handlers.NewApp(settings)

	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))))

	mux.HandleFunc("GET /login", auth.LoginGet)
	mux.HandleFunc("POST /login", auth.LoginPost)
	mux.Handle("POST /logout", auth.Require(http.HandlerFunc(auth.Logout)))

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
	slog.Info("wg-manager listening", "url", "http://"+host)
	if err := http.ListenAndServe(addr, securityHeaders(mux)); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'self' 'unsafe-inline'")
		next.ServeHTTP(w, r)
	})
}
