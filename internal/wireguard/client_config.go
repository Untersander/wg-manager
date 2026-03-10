package wireguard

import (
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
	mustWrite(b, "[Interface]\n")
	mustWrite(b, "PrivateKey = %s\n", in.PrivateKey)
	mustWrite(b, "Address = %s\n", in.Address)
	if len(in.DNS) > 0 {
		mustWrite(b, "DNS = %s\n", strings.Join(in.DNS, ", "))
	}

	mustWrite(b, "\n")
	mustWrite(b, "[Peer]\n")
	mustWrite(b, "PublicKey = %s\n", in.ServerPublicKey)
	mustWrite(b, "AllowedIPs = %s\n", strings.Join(in.AllowedIPs, ", "))
	mustWrite(b, "Endpoint = %s\n", in.Endpoint)
	if in.PersistentKeepalive > 0 {
		mustWrite(b, "PersistentKeepalive = %d\n", in.PersistentKeepalive)
	}

	return b.String()
}
