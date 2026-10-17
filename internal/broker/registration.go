package broker

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"icicle/internal/wire"
)

// registration runs under b.mu, held by handle
func (b *Broker) registerHost(p *peer, m *wire.Envelope) error {
	registration := new(wire.HostRegistration)
	if len(m.Payload) > 4096 || (proto.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(m.Payload, registration) != nil {
		return errors.New("malformed host registration")
	}
	if registration.Version != 2 {
		return fmt.Errorf("unsupported host registration version: %d", registration.Version)
	}
	if registration.SessionId != m.SessionId {
		return errors.New("host registration lobby mismatch")
	}
	if !bytes.Equal(registration.Challenge, p.challenge) {
		return errors.New("host registration challenge mismatch")
	}
	if !validBuild(registration.Build) {
		return errors.New("invalid host build metadata")
	}
	if !verify(m.PublicKey, "icicle/register/host/v2\n", m.Payload, m.Signature) {
		return errors.New("invalid host signature")
	}
	if b.sessions[m.SessionId] != nil {
		return errors.New("lobby already exists")
	}
	s := &session{id: m.SessionId, host: p, clients: make(map[string]*peer)}
	p.session, p.key, p.id, p.build = s, m.PublicKey, "host", registration.Build
	b.sessions[s.id] = s
	p.logf("host_registered", "lobby=%q protocol=%d version=%q revision=%q", s.id, p.build.ProtocolVersion, p.build.BuildVersion, p.build.Revision)
	p.send(&wire.Envelope{Kind: wire.Envelope_REGISTERED, SessionId: s.id, PeerId: "host", PublicKey: p.key, Build: p.build}, false)
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
	p.logf("client_registration", "lobby=%q request=%q username=%q host_protocol=%d client_protocol=%d version=%q revision=%q", s.id, request.RequestId, request.Username, s.host.build.ProtocolVersion, request.Build.ProtocolVersion, request.Build.BuildVersion, request.Build.Revision)
	if !compatibleBuilds(s.host.build, request.Build) {
		return fmt.Errorf("incompatible replication protocol: host %d (%s), client %d (%s)", s.host.build.ProtocolVersion, s.host.build.BuildVersion, request.Build.ProtocolVersion, request.Build.BuildVersion)
	}
	for _, c := range s.clients {
		if strings.EqualFold(c.request.Username, request.Username) {
			return errors.New("username already in use in this lobby")
		}
		if bytes.Equal(c.key, m.PublicKey) {
			return errors.New("identity already in this lobby")
		}
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
	p.logf("admission_requested", "lobby=%q peer=%q request=%q host_connection=%d timeout_ms=%d", s.id, id, request.RequestId, s.host.connectionID, b.config.AdmissionTimeout.Milliseconds())
	p.send(&wire.Envelope{Kind: wire.Envelope_REGISTERED, SessionId: s.id, PeerId: id, RequestId: request.RequestId, PublicKey: s.host.key, Build: s.host.build}, false)
	s.host.send(&wire.Envelope{Kind: wire.Envelope_JOIN_REQUEST, SessionId: s.id, PeerId: id, RequestId: request.RequestId, PublicKey: p.key, Payload: m.Payload, Signature: m.Signature}, false)
	return nil
}

func validateJoinRequest(p *peer, m *wire.Envelope) (*wire.JoinRequest, error) {
	request := new(wire.JoinRequest)
	if len(m.Payload) > 64*1024 || (proto.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(m.Payload, request) != nil {
		return nil, errors.New("malformed join request")
	}
	checks := []struct {
		valid  bool
		reason string
	}{
		{request.Version == 2, "unsupported join request version"},
		{request.SessionId == m.SessionId, "join request lobby mismatch"},
		{request.RequestId == m.RequestId && tokenPattern.MatchString(m.RequestId), "invalid join request ID"},
		{validBuild(request.Build), "invalid client build metadata"},
		{usernamePattern.MatchString(request.Username), "invalid username"},
		{len(request.Offer) > 0 && len(request.Offer) <= 48*1024, "invalid offer size"},
		{bytes.Equal(request.Challenge, p.challenge), "join request challenge mismatch"},
		{bytes.Equal(request.ClientPublicKey, m.PublicKey), "join request public key mismatch"},
	}
	for _, check := range checks {
		if !check.valid {
			return nil, errors.New(check.reason)
		}
	}
	if !verify(m.PublicKey, "icicle/join/v1\n", m.Payload, m.Signature) {
		return nil, errors.New("invalid client signature")
	}
	return request, nil
}

func validBuild(build *wire.BuildCompatibility) bool {
	return build != nil && build.ProtocolVersion > 0 && len(build.BuildVersion) > 0 && len(build.BuildVersion) <= 128 && len(build.Revision) <= 128
}

func compatibleBuilds(host, client *wire.BuildCompatibility) bool {
	return validBuild(host) && validBuild(client) && host.ProtocolVersion == client.ProtocolVersion
}
