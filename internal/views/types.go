package views

import "context"

type csrfKeyType struct{}

var CSRFKey = csrfKeyType{}

func CSRFToken(ctx context.Context) string {
	if v, ok := ctx.Value(CSRFKey).(string); ok {
		return v
	}
	return ""
}

type PeerView struct {
	Name       string
	AllowedIPs string
	Handshake  string
	Rx         string
	Tx         string
}

type PeersData struct {
	Peers            []PeerView
	DefaultKeepalive int
	NextAddress      string
	Error            string
}

type SettingsData struct {
	ListenPort        int
	MTU               int
	EgressInterface   string
	DefaultDNS        string
	DefaultAllowedIPs string
	Error             string
}

type EditPeerData struct {
	Name              string
	AllowedIPs        string
	Keepalive         int
	DNS               string
	ClientAllowedIPs  string
	DefaultDNS        string
	DefaultAllowedIPs string
	Error             string
}
