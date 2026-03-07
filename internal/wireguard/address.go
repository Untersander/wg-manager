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

	used := map[netip.Addr]bool{}
	// mark the server's own address
	used[prefix.Addr()] = true
	for _, cidr := range usedCIDRs {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			a, err2 := netip.ParseAddr(cidr)
			if err2 != nil {
				continue
			}
			used[a] = true
			continue
		}
		used[p.Addr()] = true
	}

	networkAddr := networkAddress(prefix)
	broadcastAddr := broadcastAddress(prefix)

	// start from network + 1 (skip network address itself)
	candidate := networkAddr.Next()
	last := broadcastAddr
	for candidate.IsValid() && candidate.Less(last) {
		if !used[candidate] {
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
	var usedV4, usedV6 []string
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

	used := map[netip.Addr]bool{}
	used[prefix.Addr()] = true
	for _, cidr := range usedCIDRs {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		used[p.Addr()] = true
	}

	net := networkAddress(prefix)
	bcast := broadcastAddress(prefix)

	candidate := net.Next()
	for candidate.IsValid() && candidate.Less(bcast) {
		if !used[candidate] {
			return candidate.String(), nil
		}
		candidate = candidate.Next()
	}
	// for v6, also check the broadcast address itself (v6 doesn't have broadcast)
	if prefix.Addr().Is6() && !used[bcast] {
		return bcast.String(), nil
	}

	return "", fmt.Errorf("no available IPs in %s", serverCIDR)
}
