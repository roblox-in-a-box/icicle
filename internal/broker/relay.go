package broker

import (
	"errors"
	"time"

	"icicle/internal/wire"
)

func (b *Broker) relayClient(p *peer, m *wire.Envelope) (*peer, error) {
	s := p.session
	if b.closed || s == nil || b.sessions[s.id] != s || m.SessionId != s.id {
		return nil, errors.New("relay session unavailable")
	}
	c := p
	if p == s.host {
		c = s.clients[m.PeerId]
	}
	if c == nil || c == s.host || s.clients[c.id] != c || !c.admitted || c.relayRevoke == nil || m.RequestId != c.request.RequestId {
		return nil, errors.New("relay requires an approved host and client pair")
	}
	if p != s.host && m.PeerId != "host" {
		return nil, errors.New("clients can relay only to their host")
	}
	return c, nil
}

func (b *Broker) startWebSocketRelay(p *peer, m *wire.Envelope) error {
	c, err := b.relayClient(p, m)
	if err != nil {
		return err
	}
	if c.websocketRelay {
		return nil
	}
	c.websocketRelay = true
	s := c.session
	s.preferRelay, s.preferWebSocket = true, true
	ready := &wire.Envelope{Kind: wire.Envelope_RELAY_READY, SessionId: s.id, PeerId: c.id, RequestId: c.request.RequestId}
	s.host.send(ready, false)
	c.send(ready, false)
	return nil
}

func (b *Broker) forwardDatagram(p *peer, m *wire.Envelope) error {
	now := time.Now()
	packets, bytes := float64(2000), float64(1024*1024)
	if p.session != nil && p == p.session.host {
		packets, bytes = 20000, 16*1024*1024
	}
	if p.lastDatagram.IsZero() {
		p.inputPackets, p.inputBytes = packets, bytes
	}
	elapsed := now.Sub(p.lastDatagram).Seconds()
	p.lastDatagram = now
	p.inputPackets = min(packets, p.inputPackets+elapsed*packets)
	p.inputBytes = min(bytes, p.inputBytes+elapsed*bytes)
	if p.inputPackets < 1 || p.inputBytes < float64(len(m.Payload)) {
		return errors.New("relay input rate exceeded")
	}
	p.inputPackets--
	p.inputBytes -= float64(len(m.Payload))
	if p.session != nil && p == p.session.host && m.SessionId == p.session.id && p.session.clients[m.PeerId] == nil {
		return nil
	}
	c, err := b.relayClient(p, m)
	if err != nil {
		return err
	}
	if !c.websocketRelay || len(m.Payload) == 0 || len(m.Payload) > 1464 {
		return errors.New("invalid relay datagram")
	}
	user, target, peerID := c.relayClientUser, c.session.host, c.id
	if p == c.session.host {
		user, target, peerID = c.relayHostUser, c, "host"
	}
	if !b.config.Relay.Allow(user, len(m.Payload)) {
		return nil
	}
	target.sendDatagram(&wire.Envelope{Kind: wire.Envelope_RELAY_DATA, SessionId: c.session.id, PeerId: peerID, RequestId: c.request.RequestId, Payload: m.Payload})
	return nil
}
