package relay

import (
	"encoding/binary"
	"net"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

func (b *bucket) take(now time.Time, rate, cost float64) bool {
	if b.last.IsZero() {
		b.tokens = rate
	}
	b.tokens += now.Sub(b.last).Seconds() * rate
	if b.tokens > rate {
		b.tokens = rate
	}
	b.last = now
	if cost > b.tokens {
		return false
	}
	b.tokens -= cost
	return true
}

type ingress struct {
	net.PacketConn
	global  bucket
	packets bucket
	peers   map[string]*bucket
}

func (p *ingress) ReadFrom(data []byte) (int, net.Addr, error) {
	for {
		n, addr, err := p.PacketConn.ReadFrom(data)
		if err != nil {
			return n, addr, err
		}
		if n < 4 {
			continue
		}
		if !p.packets.take(time.Now(), 20000, 1) {
			continue
		}
		// This endpoint is not a public STUN discovery service
		if binary.BigEndian.Uint16(data[:2]) == 1 {
			continue
		}
		if data[0]&0xc0 == 0x40 {
			return n, addr, nil
		}
		now := time.Now()
		if !p.global.take(now, 200, 1) {
			continue
		}
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			continue
		}
		b := p.peers[host]
		if b == nil {
			if len(p.peers) >= 4096 {
				for key, entry := range p.peers {
					if now.Sub(entry.last) > time.Minute {
						delete(p.peers, key)
					}
				}
				if len(p.peers) >= 4096 {
					continue
				}
			}
			b = &bucket{}
			p.peers[host] = b
		}
		if b.take(now, 40, 1) {
			return n, addr, nil
		}
	}
}
