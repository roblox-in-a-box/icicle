package broker

import (
	"errors"
	"fmt"
	"net"
	"net/http"
)

// ParseTrustedProxies accepts CIDR ranges or single addresses for reverse proxies on other hosts
func ParseTrustedProxies(values []string) ([]*net.IPNet, error) {
	if len(values) > 256 {
		return nil, errors.New("too many trusted proxies")
	}
	networks := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			ip := net.ParseIP(value)
			if ip == nil {
				return nil, fmt.Errorf("invalid trusted proxy %q", value)
			}
			bits := 8 * net.IPv6len
			if v4 := ip.To4(); v4 != nil {
				ip, bits = v4, 8*net.IPv4len
			}
			network = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
		}
		if ones, _ := network.Mask.Size(); ones == 0 {
			return nil, fmt.Errorf("trusted proxy %q would trust every address", value)
		}
		networks = append(networks, network)
	}
	return networks, nil
}

func trustedProxy(ip net.IP, trustLoopback bool, proxies []*net.IPNet) bool {
	if trustLoopback && ip.IsLoopback() {
		return true
	}
	for _, network := range proxies {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func clientIP(r *http.Request, trustLoopback bool, proxies []*net.IPNet) (string, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", errors.New("invalid client address")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "", errors.New("invalid client address")
	}
	if trustedProxy(ip, trustLoopback, proxies) {
		header := r.Header.Get("X-Icicle-Client-IP")
		if header != "" {
			ip = net.ParseIP(header)
			if ip == nil {
				return "", errors.New("invalid proxy client address")
			}
		}
	}
	return ip.String(), nil
}

func (b *Broker) relayCapacityAvailable(s *session, c *peer) bool {
	hostPairs, hostIP, clientIP := 0, 0, 0
	for _, lobby := range b.sessions {
		for _, other := range lobby.clients {
			if other.relayRevoke == nil {
				continue
			}
			if lobby.host == s.host {
				hostPairs++
			}
			if lobby.host.sourceIP == s.host.sourceIP || other.sourceIP == s.host.sourceIP {
				hostIP++
			}
			if lobby.host.sourceIP == c.sourceIP || other.sourceIP == c.sourceIP {
				clientIP++
			}
		}
	}
	return hostPairs < 16 && hostIP < 32 && clientIP < 32
}
