package wireguard

import (
	"testing"
)

func TestNextAvailableIP(t *testing.T) {
	tests := []struct {
		name       string
		serverCIDR string
		usedCIDRs  []string
		want       string
		wantErr    bool
	}{
		{
			name:       "first available in empty subnet",
			serverCIDR: "10.8.0.0/24",
			usedCIDRs:  nil,
			// 10.8.0.1 is reserved as server address (first usable from network)
			want: "10.8.0.2/32",
		},
		{
			name:       "skips used addresses",
			serverCIDR: "10.8.0.0/24",
			usedCIDRs:  []string{"10.8.0.2/32"},
			want:       "10.8.0.3/32",
		},
		{
			name:       "invalid server CIDR",
			serverCIDR: "notacidr",
			wantErr:    true,
		},
		{
			name:       "subnet exhausted",
			serverCIDR: "10.8.0.0/30",
			// /30 has .0 (network), .1 (server), .2 (used), .3 (broadcast)
			usedCIDRs: []string{"10.8.0.2/32"},
			wantErr:   true,
		},
		{
			name:       "server is specific host address",
			serverCIDR: "10.8.0.1/24",
			usedCIDRs:  nil,
			// network=10.8.0.0, server=10.8.0.1 → first candidate is 10.8.0.2
			want: "10.8.0.2/32",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NextAvailableIP(tt.serverCIDR, tt.usedCIDRs)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNextAvailableAddresses(t *testing.T) {
	t.Run("empty peers returns first available dual-stack", func(t *testing.T) {
		got, err := NextAvailableAddresses("10.8.0.0/24", "fd42::/64", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "10.8.0.2/32, fd42::2/128"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("skips allocated peers", func(t *testing.T) {
		peers := []Peer{
			{AllowedIPs: []string{"10.8.0.2/32", "fd42::2/128"}},
		}
		got, err := NextAvailableAddresses("10.8.0.0/24", "fd42::/64", peers)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "10.8.0.3/32, fd42::3/128"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}

func TestNetworkAddress(t *testing.T) {
	tests := []struct {
		cidr string
		want string
	}{
		{"10.8.0.5/24", "10.8.0.0"},
		{"192.168.1.100/16", "192.168.0.0"},
		{"fd42::5/64", "fd42::"},
	}
	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			prefix := mustParsePrefix(t, tt.cidr)
			got := networkAddress(prefix)
			if got.String() != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBroadcastAddress(t *testing.T) {
	tests := []struct {
		cidr string
		want string
	}{
		{"10.8.0.0/24", "10.8.0.255"},
		{"10.8.0.0/30", "10.8.0.3"},
	}
	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			prefix := mustParsePrefix(t, tt.cidr)
			got := broadcastAddress(prefix)
			if got.String() != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
