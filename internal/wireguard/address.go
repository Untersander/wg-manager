package wireguard

import (
	"fmt"
	"net"
	"net/netip"
)

// NextAvailableIP finds the next unused IP in the server's subnet,
// skipping the network address, broadcast (for v4), and any IPs already
// assigned to peers.
func NextAvailableIP(serverCIDR string, usedCIDRs []string) (string, error) {
	prefix, err := netip.ParsePrefix(serverCIDR)
	if err != nil {
		return "", fmt.Errorf("parsing server CIDR %q: %w", serverCIDR, err)
	}

	used := make(map[netip.Addr]struct{}, len(usedCIDRs)+1)
	reserveServerAddress(prefix, used)
	for _, cidr := range usedCIDRs {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			a, err2 := netip.ParseAddr(cidr)
			if err2 != nil {
				continue
			}
			used[a] = struct{}{}
			continue
		}
		used[p.Addr()] = struct{}{}
	}

	networkAddr := networkAddress(prefix)
	broadcastAddr := broadcastAddress(prefix)

	// start from network + 1 (skip network address itself)
	candidate := networkAddr.Next()
	last := broadcastAddr
	for candidate.IsValid() && candidate.Less(last) {
		if _, exists := used[candidate]; !exists {
			return fmt.Sprintf("%s/%d", candidate.String(), prefix.Addr().BitLen()), nil
		}
		candidate = candidate.Next()
	}

	return "", fmt.Errorf("no available IPs in %s", serverCIDR)
}

func networkAddress(prefix netip.Prefix) netip.Addr {
	addr := prefix.Addr()
	if addr.Is4() {
		b := addr.As4()
		mask := net.CIDRMask(prefix.Bits(), 32)
		for i := range b {
			b[i] &= mask[i]
		}
		return netip.AddrFrom4(b)
	}
	b := addr.As16()
	mask := net.CIDRMask(prefix.Bits(), 128)
	for i := range b {
		b[i] &= mask[i]
	}
	return netip.AddrFrom16(b)
}

func broadcastAddress(prefix netip.Prefix) netip.Addr {
	addr := prefix.Addr()
	if addr.Is4() {
		b := addr.As4()
		mask := net.CIDRMask(prefix.Bits(), 32)
		for i := range b {
			b[i] |= ^mask[i]
		}
		return netip.AddrFrom4(b)
	}
	// For IPv6, compute the last address in the prefix
	b := addr.As16()
	mask := net.CIDRMask(prefix.Bits(), 128)
	for i := range b {
		b[i] |= ^mask[i]
	}
	return netip.AddrFrom16(b)
}

// NextAvailableAddresses returns "v4/32, v6/128" for a new peer,
// picking the next free host in each server subnet.
func NextAvailableAddresses(serverV4, serverV6 string, peers []Peer) (string, error) {
	usedV4 := make([]string, 0, len(peers)*2)
	usedV6 := make([]string, 0, len(peers)*2)
	for _, p := range peers {
		for _, a := range p.AllowedIPs {
			pref, err := netip.ParsePrefix(a)
			if err != nil {
				continue
			}
			if pref.Addr().Is4() {
				usedV4 = append(usedV4, a)
			} else {
				usedV6 = append(usedV6, a)
			}
		}
	}

	nextV4, err := nextHost(serverV4, usedV4)
	if err != nil {
		return "", fmt.Errorf("v4: %w", err)
	}

	nextV6, err := nextHost(serverV6, usedV6)
	if err != nil {
		return "", fmt.Errorf("v6: %w", err)
	}

	return fmt.Sprintf("%s/32, %s/128", nextV4, nextV6), nil
}

func nextHost(serverCIDR string, usedCIDRs []string) (string, error) {
	prefix, err := netip.ParsePrefix(serverCIDR)
	if err != nil {
		return "", fmt.Errorf("parsing %q: %w", serverCIDR, err)
	}

	used := make(map[netip.Addr]struct{}, len(usedCIDRs)+1)
	reserveServerAddress(prefix, used)
	for _, cidr := range usedCIDRs {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		used[p.Addr()] = struct{}{}
	}

	net := networkAddress(prefix)
	bcast := broadcastAddress(prefix)

	candidate := net.Next()
	for candidate.IsValid() && candidate.Less(bcast) {
		if _, exists := used[candidate]; !exists {
			return candidate.String(), nil
		}
		candidate = candidate.Next()
	}
	// for v6, also check the broadcast address itself (v6 doesn't have broadcast)
	if prefix.Addr().Is6() {
		if _, exists := used[bcast]; !exists {
			return bcast.String(), nil
		}
	}

	return "", fmt.Errorf("no available IPs in %s", serverCIDR)
}

func reserveServerAddress(prefix netip.Prefix, used map[netip.Addr]struct{}) {
	netAddr := networkAddress(prefix)
	serverAddr := prefix.Addr()

	// When settings provide a subnet (e.g. 10.8.0.0/24), reserve first usable
	// because EnsureConfig assigns that to the server interface.
	if serverAddr == netAddr {
		serverAddr = netAddr.Next()
	}

	if serverAddr.IsValid() {
		used[serverAddr] = struct{}{}
	}
}
