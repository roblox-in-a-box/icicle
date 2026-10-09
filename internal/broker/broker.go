package broker

import (
	"sync"
	"time"

	"icicle/internal/wire"
)

type session struct {
	id      string
	host    *peer
	clients map[string]*peer
}

type Broker struct {
	// mu protects lobby membership, admission state, connection registry
	mu          sync.Mutex
	config      Config
	sessions    map[string]*session
	connections map[*peer]struct{}
	closed      bool
	done        chan struct{}
	wg          sync.WaitGroup
}

func New(config Config) *Broker {
	if config.RegistrationTimeout <= 0 {
		config.RegistrationTimeout = 35 * time.Second
	}
	if config.AdmissionTimeout <= 0 {
		config.AdmissionTimeout = 30 * time.Second
	}
	b := &Broker{
		config:      config,
		sessions:    make(map[string]*session),
		connections: make(map[*peer]struct{}),
		done:        make(chan struct{}),
	}
	b.wg.Add(1)
	go b.expire()
	return b
}

func (b *Broker) remove(p *peer) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.connections, p)
	s := p.session
	if s == nil {
		return
	}
	if p == s.host {
		if b.sessions[s.id] != s {
			return
		}
		delete(b.sessions, s.id)
		for _, c := range s.clients {
			c.send(&wire.Envelope{Kind: wire.Envelope_ERROR, SessionId: s.id, Error: "Host disconnected"}, true)
		}
	} else if s.clients[p.id] == p {
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
				if p.conn != nil && (p.session == nil || (p != p.session.host && !p.admitted)) && now.After(p.deadline) {
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
