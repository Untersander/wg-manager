package wireguard

import (
	"fmt"
	"strings"
)

type ClientConfigInput struct {
	PrivateKey          string
	Address             string
	DNS                 []string
	ServerPublicKey     string
	Endpoint            string
	AllowedIPs          []string
	PersistentKeepalive int
}

func BuildClientConfig(in ClientConfigInput) string {
	b := &strings.Builder{}
	_, _ = fmt.Fprintln(b, "[Interface]")
	_, _ = fmt.Fprintf(b, "PrivateKey = %s\n", in.PrivateKey)
	_, _ = fmt.Fprintf(b, "Address = %s\n", in.Address)
	if len(in.DNS) > 0 {
		_, _ = fmt.Fprintf(b, "DNS = %s\n", strings.Join(in.DNS, ", "))
	}

	_, _ = fmt.Fprintln(b, "")
	_, _ = fmt.Fprintln(b, "[Peer]")
	_, _ = fmt.Fprintf(b, "PublicKey = %s\n", in.ServerPublicKey)
	_, _ = fmt.Fprintf(b, "AllowedIPs = %s\n", strings.Join(in.AllowedIPs, ", "))
	_, _ = fmt.Fprintf(b, "Endpoint = %s\n", in.Endpoint)
	if in.PersistentKeepalive > 0 {
		_, _ = fmt.Fprintf(b, "PersistentKeepalive = %d\n", in.PersistentKeepalive)
	}

	return b.String()
}
