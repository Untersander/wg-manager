module wg-manager

go 1.27.1

require (
	github.com/a-h/templ v0.3.1118
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e
	golang.org/x/time v0.15.0
)

require (
	github.com/a-h/parse v0.0.42 // indirect
	github.com/andybalholm/brotli v1.3.0 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/cli/browser v1.3.0 // indirect
	github.com/fatih/color v1.19.0 // indirect
	github.com/fsnotify/fsnotify v1.10.1 // indirect
	github.com/mattn/go-colorable v0.1.16 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/natefinch/atomic v1.0.1 // indirect
	golang.org/x/mod v0.43.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/tools v0.52.0 // indirect
)

tool (
	github.com/a-h/templ/cmd/templ
	wg-manager/cmd/wg-manager
	wg-manager/internal/config
	wg-manager/internal/handlers
	wg-manager/internal/views
	wg-manager/internal/wireguard
)
