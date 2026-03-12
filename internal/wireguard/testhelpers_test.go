package wireguard

import (
	"net/netip"
	"testing"
)

func mustParsePrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("mustParsePrefix(%q): %v", s, err)
	}
	return p
}
