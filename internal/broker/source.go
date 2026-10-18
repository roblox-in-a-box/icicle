package broker

import (
	"errors"
	"net"
	"net/http"
)

func clientIP(r *http.Request, trustLoopback bool) (string, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", errors.New("invalid client address")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "", errors.New("invalid client address")
	}
	if trustLoopback && ip.IsLoopback() {
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
