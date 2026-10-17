package broker

import (
	"errors"
	"regexp"
	"time"

	"icicle/internal/wire"
)

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9_]{1,32}$`)

var lobbyPattern = regexp.MustCompile(`^[A-Z0-9]{8}$`)
var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func (b *Broker) handle(p *peer, m *wire.Envelope) error {
	b.mu.Lock()
	defer b.mu.Unlock()
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
		case wire.Envelope_REGISTER_CLIENT:
			return b.registerClient(p, m)
		default:
			return errors.New("registration required")
		}
	}
	s := p.session
	if m.SessionId != s.id {
		return errors.New("wrong session")
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
		return errors.New("unknown peer or request")
	}
	switch m.Kind {
	case wire.Envelope_ADMITTED:
		if c.admitted || now.After(c.deadline) {
			return errors.New("admission expired or repeated")
		}
		if err := validateAnswer(s, c, m, now); err != nil {
			return err
		}
		issued, err := b.issueAdmission(s, c, m, now)
		if err != nil {
			return err
		}
		c.admitted = true
		s.host.send(issued, false)
		c.send(issued, false)
	case wire.Envelope_REJECTED:
		if c.admitted {
			return errors.New("peer already admitted")
		}
		delete(s.clients, c.id)
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

func validRelay(m *wire.Envelope) bool {
	if m.Kind == wire.Envelope_CANDIDATE {
		return len(m.Candidate) > 0 && len(m.Candidate) <= 4096 && len(m.Mid) <= 256
	}
	return (m.DescriptionType == "offer" || m.DescriptionType == "answer") && len(m.Description) > 0 && len(m.Description) <= 48*1024
}
