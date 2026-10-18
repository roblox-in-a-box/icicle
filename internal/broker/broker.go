package broker

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"time"

	"icicle/internal/relay"
	"icicle/internal/wire"
)

type session struct {
	id              string
	host            *peer
	clients         map[string]*peer
	preferRelay     bool
	preferWebSocket bool
}

type Broker struct {
	// mu protects lobby membership, admission state, connection registry
	mu               sync.Mutex
	config           Config
	sessions         map[string]*session
	connections      map[*peer]struct{}
	nextConnectionID uint64
	closed           bool
	done             chan struct{}
	wg               sync.WaitGroup
}

func New(config Config) (*Broker, error) {
	if config.Relay == nil {
		var err error
		config.Relay, err = relay.New(relay.Config{})
		if err != nil {
			return nil, err
		}
	}
	if len(config.SigningKey) == 0 {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		config.SigningKey = key
	}
	if len(config.SigningKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid authority key")
	}
	config.SigningKey = append(ed25519.PrivateKey(nil), config.SigningKey...)
	if len(config.AdminKeys) > 256 {
		return nil, errors.New("too many admin keys")
	}
	admins := make([]ed25519.PublicKey, 0, len(config.AdminKeys))
	for _, key := range config.AdminKeys {
		if len(key) != ed25519.PublicKeySize {
			return nil, errors.New("invalid admin key")
		}
		admins = append(admins, append(ed25519.PublicKey(nil), key...))
	}
	config.AdminKeys = admins

	if config.RegistrationTimeout <= 0 {
		config.RegistrationTimeout = 35 * time.Second
	}
	if config.AdmissionTimeout <= 0 {
		config.AdmissionTimeout = 90 * time.Second
	}
	b := &Broker{
		config:      config,
		sessions:    make(map[string]*session),
		connections: make(map[*peer]struct{}),
		done:        make(chan struct{}),
	}
	b.wg.Add(1)
	go b.expire()
	return b, nil
}

func (b *Broker) remove(p *peer) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.connections, p)
	s := p.session
	if p.relayRevoke != nil {
		p.relayRevoke()
		p.relayRevoke = nil
	}
	if s == nil {
		return
	}
	if p == s.host {
		if b.sessions[s.id] != s {
			return
		}
		p.logf("lobby_closed", "lobby=%q clients=%d reason=%q", s.id, len(s.clients), "host disconnected")
		delete(b.sessions, s.id)
		for _, c := range s.clients {
			if c.relayRevoke != nil {
				c.relayRevoke()
				c.relayRevoke = nil
			}
			c.send(&wire.Envelope{Kind: wire.Envelope_ERROR, SessionId: s.id, Error: "Host disconnected"}, true)
		}
	} else if s.clients[p.id] == p {
		p.logf("client_removed", "lobby=%q peer=%q request=%q admitted=%t", s.id, p.id, p.request.RequestId, p.admitted)
		delete(s.clients, p.id)
		s.host.send(&wire.Envelope{Kind: wire.Envelope_PEER_LEFT, SessionId: s.id, PeerId: p.id, RequestId: p.request.RequestId}, false)
	}
}

func (b *Broker) expire() {
	defer b.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-b.done:
			return
		case now := <-ticker.C:
			b.mu.Lock()
			for p := range b.connections {
				if p.relayRenew != nil && p.session != nil && b.sessions[p.session.id] == p.session && p.session.clients[p.id] == p {
					p.relayRenew()
				}
				if p.conn != nil && (p.session == nil || (p != p.session.host && !p.admitted)) && now.After(p.deadline) {
					phase := "registration"
					lobby, request := "", ""
					if p.session != nil {
						phase = "admission"
						lobby = p.session.id
						request = p.request.RequestId
					}
					select {
					case <-p.done:
						continue
					default:
					}
					p.logf("connection_expired", "phase=%s lobby=%q request=%q overdue_ms=%d", phase, lobby, request, now.Sub(p.deadline).Milliseconds())
					p.close()
				}
			}
			b.mu.Unlock()
		}
	}
}

func (b *Broker) Close() {
	b.mu.Lock()
	if !b.closed {
		b.closed = true
		close(b.done)
		for p := range b.connections {
			if p.conn != nil {
				p.close()
			}
		}
	}
	b.mu.Unlock()
	b.wg.Wait()
}
