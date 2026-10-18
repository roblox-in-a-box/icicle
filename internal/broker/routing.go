package broker

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"time"

	"google.golang.org/protobuf/proto"

	"icicle/internal/wire"
)

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9_]{1,32}$`)

var lobbyPattern = regexp.MustCompile(`^[A-Z0-9]{8}$`)
var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func (b *Broker) handle(p *peer, m *wire.Envelope) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if m.Kind == wire.Envelope_RELAY_DATA {
		return b.forwardDatagram(p, m)
	}
	now := time.Now()
	p.tokens += now.Sub(p.lastMessage).Seconds() * 20
	if p.tokens > 60 {
		p.tokens = 60
	}
	p.lastMessage = now
	if p.tokens < 1 {
		return errors.New("signalling rate exceeded")
	}
	p.tokens--
	if b.closed {
		return errors.New("server shutting down")
	}
	if !lobbyPattern.MatchString(m.SessionId) {
		return errors.New("invalid lobby code")
	}
	if p.session == nil {
		if now.After(p.deadline) {
			return errors.New("registration expired")
		}
		switch m.Kind {
		case wire.Envelope_REGISTER_HOST:
			return b.registerHost(p, m)
		case wire.Envelope_REGISTER_CLIENT, wire.Envelope_PREPARE_CLIENT:
			return b.registerClient(p, m)
		default:
			return errors.New("registration required")
		}
	}
	s := p.session
	if m.SessionId != s.id {
		return errors.New("wrong session")
	}
	if m.Kind == wire.Envelope_ROUTE_STATUS {
		if p != s.host {
			return errors.New("only the host can set relay preference")
		}
		s.preferRelay = s.preferRelay || m.PreferRelay
		s.preferWebSocket = s.preferWebSocket || m.PreferWebsocket
		return nil
	}
	if m.Kind == wire.Envelope_RELAY_REQUEST {
		return b.startWebSocketRelay(p, m)
	}
	if m.Kind == wire.Envelope_REVOKE_PEER {
		if p != s.host {
			return errors.New("only the host can revoke a peer")
		}
		c := s.clients[m.PeerId]
		if c == nil || c.request.RequestId != m.RequestId {
			return nil
		}
		if c.relayRevoke != nil {
			c.relayRevoke()
			c.relayRevoke = nil
		}
		delete(s.clients, c.id)
		c.send(&wire.Envelope{Kind: wire.Envelope_ERROR, SessionId: s.id, Error: "Host closed the game connection"}, true)
		return nil
	}
	if p != s.host && m.Kind == wire.Envelope_OFFER_READY {
		if !p.prepared || p.admitted || p.request.Offer != "" {
			return errors.New("unexpected game offer")
		}
		request, err := validateJoinRequest(p, m)
		if err != nil {
			return err
		}
		if request.RequestId != p.request.RequestId || request.Username != p.request.Username || !bytes.Equal(m.PublicKey, p.key) || !proto.Equal(request.Build, p.request.Build) {
			return errors.New("prepared identity changed")
		}
		p.request = request
		s.host.send(&wire.Envelope{Kind: wire.Envelope_JOIN_REQUEST, SessionId: s.id, PeerId: p.id, RequestId: request.RequestId, PublicKey: p.key, Payload: m.Payload, Signature: m.Signature}, false)
		return nil
	}
	if p != s.host {
		if !p.admitted || (m.Kind != wire.Envelope_DESCRIPTION && m.Kind != wire.Envelope_CANDIDATE) || (m.PeerId != "" && m.PeerId != "host") {
			return errors.New("unauthorized client message")
		}
		m.PeerId = p.id
		m.RequestId = p.request.RequestId
		if !validRelay(m) {
			return errors.New("invalid signalling message")
		}
		s.host.send(m, false)
		return nil
	}
	c := s.clients[m.PeerId]
	if c == nil || m.RequestId != c.request.RequestId {
		if (m.Kind == wire.Envelope_ADMITTED || m.Kind == wire.Envelope_REJECTED) && tokenPattern.MatchString(m.PeerId) && tokenPattern.MatchString(m.RequestId) {
			p.logf("stale_admission", "lobby=%q peer=%q request=%q reason=%q", s.id, m.PeerId, m.RequestId, "peer or request no longer active")
			p.send(&wire.Envelope{Kind: wire.Envelope_REJECTED, SessionId: s.id, PeerId: m.PeerId, RequestId: m.RequestId, Error: "Join request is no longer active"}, false)
			return nil
		}
		return errors.New("unknown peer or request")
	}
	switch m.Kind {
	case wire.Envelope_PREPARE_ACCEPT:
		if c.prepared || c.request.Offer != "" {
			return errors.New("unexpected preparation approval")
		}
		if now.After(c.deadline) {
			b.rejectAdmission(s, c, "preparation expired")
			return nil
		}
		if !b.relayCapacityAvailable(s, c) {
			b.rejectAdmission(s, c, "relay source capacity reached")
			return nil
		}
		host := &wire.Envelope{Kind: wire.Envelope_PREPARED, SessionId: s.id, PeerId: c.id, RequestId: c.request.RequestId, PreferRelay: s.preferRelay, PreferWebsocket: s.preferWebSocket}
		client := &wire.Envelope{Kind: wire.Envelope_PREPARED, SessionId: s.id, PeerId: c.id, RequestId: c.request.RequestId, PreferRelay: s.preferRelay, PreferWebsocket: s.preferWebSocket}
		if b.config.Relay != nil {
			h, j, renew, revoke, err := b.config.Relay.IssuePair()
			if err != nil {
				b.rejectAdmission(s, c, "relay capacity unavailable")
				return nil
			}
			c.relayRenew, c.relayRevoke = renew, revoke
			c.relayHostUser, c.relayClientUser = h.Username, j.Username
			host.Relay = &wire.RelayCredentials{Urls: h.URLs, Username: h.Username, Password: h.Password}
			client.Relay = &wire.RelayCredentials{Urls: j.URLs, Username: j.Username, Password: j.Password}
		}
		c.prepared = true
		s.host.send(host, false)
		c.send(client, false)
	case wire.Envelope_ADMITTED:
		if c.admitted {
			return errors.New("admission repeated")
		}
		if now.After(c.deadline) {
			b.rejectAdmission(s, c, fmt.Sprintf("admission expired by %dms", now.Sub(c.deadline).Milliseconds()))
			return nil
		}
		if err := validateAnswer(s, c, m, now); err != nil {
			b.rejectAdmission(s, c, err.Error())
			return nil
		}
		issued, err := b.issueAdmission(s, c, m, now)
		if err != nil {
			b.rejectAdmission(s, c, "could not issue ticket: "+err.Error())
			return nil
		}
		c.admitted = true
		s.host.send(issued, false)
		c.send(issued, false)
	case wire.Envelope_REJECTED:
		if c.admitted {
			return errors.New("peer already admitted")
		}
		p.logf("host_refused_client", "lobby=%q peer=%q request=%q client_connection=%d reason=%q", s.id, c.id, c.request.RequestId, c.connectionID, logValue(m.Error))
		delete(s.clients, c.id)
		if c.relayRevoke != nil {
			c.relayRevoke()
			c.relayRevoke = nil
		}
		c.send(&wire.Envelope{Kind: wire.Envelope_REJECTED, SessionId: s.id, PeerId: c.id, RequestId: c.request.RequestId, Error: "Admission failed"}, true)
	case wire.Envelope_DESCRIPTION, wire.Envelope_CANDIDATE:
		if !c.admitted || !validRelay(m) {
			return errors.New("invalid signalling message")
		}
		c.send(m, false)
	default:
		return errors.New("unauthorized host message")
	}
	return nil
}

func (b *Broker) rejectAdmission(s *session, c *peer, reason string) {
	s.host.logf("admission_refused", "lobby=%q peer=%q request=%q client_connection=%d reason=%q", s.id, c.id, c.request.RequestId, c.connectionID, reason)
	delete(s.clients, c.id)
	if c.relayRevoke != nil {
		c.relayRevoke()
		c.relayRevoke = nil
	}
	refusal := &wire.Envelope{Kind: wire.Envelope_REJECTED, SessionId: s.id, PeerId: c.id, RequestId: c.request.RequestId, Error: reason}
	s.host.send(refusal, false)
	c.send(refusal, true)
}

func validRelay(m *wire.Envelope) bool {
	if m.Kind == wire.Envelope_CANDIDATE {
		return len(m.Candidate) > 0 && len(m.Candidate) <= 4096 && len(m.Mid) <= 256
	}
	return (m.DescriptionType == "offer" || m.DescriptionType == "answer") && len(m.Description) > 0 && len(m.Description) <= 48*1024
}
