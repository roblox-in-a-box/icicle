package broker

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"google.golang.org/protobuf/proto"

	"icicle/internal/wire"
)

// registration runs under b.mu, held by handle
func (b *Broker) registerHost(p *peer, m *wire.Envelope) error {
	proof := append([]byte(m.SessionId+"\n"), p.challenge...)
	if !verify(m.PublicKey, "icicle/register/host/v1\n", proof, m.Signature) {
		return errors.New("invalid host signature")
	}
	if b.sessions[m.SessionId] != nil {
		return errors.New("lobby already exists")
	}
	s := &session{id: m.SessionId, host: p, clients: make(map[string]*peer)}
	p.session, p.key, p.id = s, m.PublicKey, "host"
	b.sessions[s.id] = s
	p.send(&wire.Envelope{Kind: wire.Envelope_REGISTERED, SessionId: s.id, PeerId: "host", PublicKey: p.key}, false)
	return nil
}

func (b *Broker) registerClient(p *peer, m *wire.Envelope) error {
	s := b.sessions[m.SessionId]
	if s == nil {
		return errors.New("lobby not found")
	}
	request, err := validateJoinRequest(p, m)
	if err != nil {
		return err
	}
	for _, c := range s.clients {
		if c.request.RequestId == request.RequestId {
			return errors.New("duplicate request")
		}
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return errors.New("random generation failed")
	}
	id := hex.EncodeToString(idBytes)
	if s.clients[id] != nil {
		return errors.New("peer identity collision")
	}
	p.session, p.key, p.id, p.request = s, m.PublicKey, id, request
	p.deadline = time.Now().Add(b.config.AdmissionTimeout)
	s.clients[id] = p
	p.send(&wire.Envelope{Kind: wire.Envelope_REGISTERED, SessionId: s.id, PeerId: id, RequestId: request.RequestId, PublicKey: s.host.key}, false)
	s.host.send(&wire.Envelope{Kind: wire.Envelope_JOIN_REQUEST, SessionId: s.id, PeerId: id, RequestId: request.RequestId, PublicKey: p.key, Payload: m.Payload, Signature: m.Signature}, false)
	return nil
}

func validateJoinRequest(p *peer, m *wire.Envelope) (*wire.JoinRequest, error) {
	invalid := errors.New("invalid join request")
	request := new(wire.JoinRequest)
	if len(m.Payload) > 64*1024 || (proto.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(m.Payload, request) != nil {
		return nil, invalid
	}
	if request.Version != 1 || request.SessionId != m.SessionId || request.RequestId != m.RequestId {
		return nil, invalid
	}
	if !tokenPattern.MatchString(m.RequestId) || len(request.Offer) == 0 || len(request.Offer) > 48*1024 {
		return nil, invalid
	}
	if !bytes.Equal(request.Challenge, p.challenge) || !bytes.Equal(request.ClientPublicKey, m.PublicKey) {
		return nil, invalid
	}
	// verify the received bytes
	// !!!re encoding a signed message can change its signature
	if !verify(m.PublicKey, "icicle/join/v1\n", m.Payload, m.Signature) {
		return nil, invalid
	}
	return request, nil
}
