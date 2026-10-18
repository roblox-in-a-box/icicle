package broker

import (
	"crypto/rand"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"

	"icicle/internal/wire"
)

func (b *Broker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, OPTIONS")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path == "/healthz" {
		b.mu.Lock()
		closed := b.closed
		b.mu.Unlock()
		if closed {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("ok\n"))
		return
	}
	if r.URL.Path != "/ws" {
		http.NotFound(w, r)
		return
	}
	source, err := clientIP(r, b.config.TrustLoopbackProxy)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		http.Error(w, "server shutting down", http.StatusServiceUnavailable)
		return
	}
	count := 0
	for p := range b.connections {
		if p.sourceIP == source {
			count++
		}
	}
	ip := net.ParseIP(source)
	if len(b.connections) >= 1024 || (count >= 64 && (ip == nil || !ip.IsLoopback())) {
		b.mu.Unlock()
		http.Error(w, "connection capacity reached", http.StatusTooManyRequests)
		return
	}
	b.nextConnectionID++
	p := &peer{
		connectionID: b.nextConnectionID,
		remote:       r.RemoteAddr,
		sourceIP:     source,
		out:          make(chan outbound, 8),
		datagrams:    make(chan []byte, 128),
		done:         make(chan struct{}),
		writerDone:   make(chan struct{}),
		deadline:     time.Now().Add(b.config.RegistrationTimeout),
		tokens:       60,
		lastMessage:  time.Now(),
	}
	b.connections[p] = struct{}{}
	b.wg.Add(1)
	b.mu.Unlock()
	defer b.wg.Done()
	defer b.remove(p)
	upgrader := websocket.Upgrader{
		HandshakeTimeout: 10 * time.Second,
		ReadBufferSize:   4096,
		WriteBufferSize:  4096,
		CheckOrigin:      func(*http.Request) bool { return true },
	}
	p.logf("connection_opening", "origin=%q", logValue(r.Header.Get("Origin")))
	conn, err := upgrader.Upgrade(w, r, w.Header())
	if err != nil {
		p.logf("upgrade_failed", "reason=%q", err)
		return
	}
	b.mu.Lock()
	p.conn = conn
	if b.closed {
		b.mu.Unlock()
		p.close()
		return
	}
	b.mu.Unlock()
	defer p.close()
	p.challenge = make([]byte, 32)
	if _, err = rand.Read(p.challenge); err != nil {
		p.logf("challenge_failed", "reason=%q", err)
		return
	}
	conn.SetReadLimit(128 * 1024)
	conn.SetReadDeadline(time.Now().Add(45 * time.Second))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(45 * time.Second))
	})
	go p.writeLoop()
	defer func() { p.close(); <-p.writerDone }()
	serverTime := time.Now().Unix()
	p.logf("challenge_sent", "server_unix=%d registration_timeout_ms=%d", serverTime, b.config.RegistrationTimeout.Milliseconds())
	p.send(&wire.Envelope{Kind: wire.Envelope_SERVER_CHALLENGE, Challenge: p.challenge, Authority: b.authorityPolicy(), ServerTimeUnix: serverTime}, false)
	for {
		kind, data, err := conn.ReadMessage()
		if err != nil {
			p.logf("connection_read_ended", "reason=%q", err)
			return
		}
		message := &wire.Envelope{}
		if kind != websocket.BinaryMessage || (proto.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(data, message) != nil {
			err = errors.New("invalid binary protobuf frame")
		} else {
			if message.Kind == wire.Envelope_RELAY_DATA && len(data) > 2048 {
				p.send(&wire.Envelope{Kind: wire.Envelope_ERROR, Error: "relay frame too large"}, true)
				return
			}
			if message.Kind != wire.Envelope_RELAY_DATA {
				p.logf("message_received", "kind=%s lobby=%q peer=%q request=%q bytes=%d", message.Kind, logValue(message.SessionId), logValue(message.PeerId), logValue(message.RequestId), len(data))
			}
			err = b.handle(p, message)
		}
		if err != nil {
			p.logf("refused", "kind=%s lobby=%q peer=%q request=%q reason=%q", message.Kind, logValue(message.SessionId), logValue(message.PeerId), logValue(message.RequestId), err)
			p.send(&wire.Envelope{Kind: wire.Envelope_ERROR, Error: err.Error()}, true)
			select {
			case <-p.writerDone:
			case <-time.After(6 * time.Second):
			}
			return
		}
	}
}
