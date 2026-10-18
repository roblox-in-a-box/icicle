package broker

import (
	"testing"

	"icicle/internal/wire"
)

func prepareAndAdmit(t *testing.T, url string, h *testPeer, id string) (*testPeer, *wire.Envelope) {
	t.Helper()
	c, request := prepareClient(t, url, h, id)
	h.send(t, &wire.Envelope{Kind: wire.Envelope_PREPARE_ACCEPT, SessionId: request.SessionId, PeerId: request.PeerId, RequestId: id})
	h.read(t, wire.Envelope_PREPARED)
	c.read(t, wire.Envelope_PREPARED)
	offer := c.joinMessage("ABCD1234", id)
	offer.Kind = wire.Envelope_OFFER_READY
	c.send(t, offer)
	request = h.read(t, wire.Envelope_JOIN_REQUEST)
	h.send(t, answer(h, request))
	h.read(t, wire.Envelope_ADMITTED)
	c.read(t, wire.Envelope_ADMITTED)
	return c, request
}

func activateRelay(t *testing.T, h, c *testPeer, request *wire.Envelope) {
	t.Helper()
	c.send(t, &wire.Envelope{Kind: wire.Envelope_RELAY_REQUEST, SessionId: request.SessionId, PeerId: "host", RequestId: request.RequestId})
	h.read(t, wire.Envelope_RELAY_READY)
	c.read(t, wire.Envelope_RELAY_READY)
}

func TestWebSocketRelayPairIsolation(t *testing.T) {
	_, url := setup(t, Config{})
	h := host(t, url, "ABCD1234")
	a, requestA := prepareAndAdmit(t, url, h, "first")
	activateRelay(t, h, a, requestA)
	b, requestB := prepareAndAdmit(t, url, h, "second")
	activateRelay(t, h, b, requestB)
	a.send(t, &wire.Envelope{Kind: wire.Envelope_RELAY_DATA, SessionId: "ABCD1234", PeerId: "host", RequestId: "first", Payload: []byte("gameplay")})
	packet := h.read(t, wire.Envelope_RELAY_DATA)
	if packet.PeerId != requestA.PeerId || string(packet.Payload) != "gameplay" {
		t.Fatal("client relay route changed")
	}
	h.send(t, &wire.Envelope{Kind: wire.Envelope_RELAY_DATA, SessionId: "ABCD1234", PeerId: requestA.PeerId, RequestId: "first", Payload: []byte("reply")})
	packet = a.read(t, wire.Envelope_RELAY_DATA)
	if packet.PeerId != "host" || string(packet.Payload) != "reply" {
		t.Fatal("host relay route changed")
	}
	a.send(t, &wire.Envelope{Kind: wire.Envelope_RELAY_DATA, SessionId: "ABCD1234", PeerId: requestB.PeerId, RequestId: "first", Payload: []byte("forbidden")})
	a.read(t, wire.Envelope_ERROR)
	h.read(t, wire.Envelope_PEER_LEFT)
	b.send(t, &wire.Envelope{Kind: wire.Envelope_RELAY_DATA, SessionId: "ABCD1234", PeerId: "host", RequestId: "second", Payload: []byte("still connected")})
	if string(h.read(t, wire.Envelope_RELAY_DATA).Payload) != "still connected" {
		t.Fatal("another pair was disrupted")
	}
}

func TestWebSocketRelayRequiresAdmission(t *testing.T) {
	_, url := setup(t, Config{})
	h := host(t, url, "ABCD1234")
	c, _ := prepareClient(t, url, h, "unapproved")
	c.send(t, &wire.Envelope{Kind: wire.Envelope_RELAY_REQUEST, SessionId: "ABCD1234", PeerId: "host", RequestId: "unapproved"})
	c.read(t, wire.Envelope_ERROR)
}

func TestWebSocketRelayHostRevocation(t *testing.T) {
	broker, url := setup(t, Config{})
	h := host(t, url, "ABCD1234")
	c, request := prepareAndAdmit(t, url, h, "revoked")
	activateRelay(t, h, c, request)
	h.send(t, &wire.Envelope{Kind: wire.Envelope_REVOKE_PEER, SessionId: "ABCD1234", PeerId: request.PeerId, RequestId: "revoked"})
	c.read(t, wire.Envelope_ERROR)
	broker.mu.Lock()
	remaining := len(broker.sessions["ABCD1234"].clients)
	broker.mu.Unlock()
	if remaining != 0 {
		t.Fatal("revoked peer remained in lobby")
	}
}

func TestRelayCongestionDoesNotConsumeControlQueue(t *testing.T) {
	p := &peer{done: make(chan struct{}), out: make(chan outbound, 1), datagrams: make(chan []byte, 128)}
	for i := 0; i < 512; i++ {
		p.sendDatagram(&wire.Envelope{Kind: wire.Envelope_RELAY_DATA, Payload: make([]byte, 1464)})
	}
	if p.datagramBytes.Load() > 128*1024 {
		t.Fatal("relay byte queue exceeded limit")
	}
	if !p.send(&wire.Envelope{Kind: wire.Envelope_PEER_LEFT}, false) {
		t.Fatal("relay traffic filled the control queue")
	}
	select {
	case <-p.done:
		t.Fatal("congested relay closed its recipient")
	default:
	}
}

func TestWebSocketRelayRejectsInvalidTraffic(t *testing.T) {
	for _, attack := range []string{"wrong-session", "wrong-request", "oversized", "not-activated"} {
		t.Run(attack, func(t *testing.T) {
			_, url := setup(t, Config{})
			h := host(t, url, "ABCD1234")
			c, request := prepareAndAdmit(t, url, h, "traffic")
			if attack != "not-activated" {
				activateRelay(t, h, c, request)
			}
			packet := &wire.Envelope{Kind: wire.Envelope_RELAY_DATA, SessionId: "ABCD1234", PeerId: "host", RequestId: "traffic", Payload: []byte("packet")}
			switch attack {
			case "wrong-session":
				packet.SessionId = "WXYZ5678"
			case "wrong-request":
				packet.RequestId = "another"
			case "oversized":
				packet.Payload = make([]byte, 1465)
			}
			c.send(t, packet)
			c.read(t, wire.Envelope_ERROR)
		})
	}
}

func TestWebSocketRelayInputFloodIsRejected(t *testing.T) {
	b, url := setup(t, Config{})
	h := host(t, url, "ABCD1234")
	c, request := prepareAndAdmit(t, url, h, "flood")
	activateRelay(t, h, c, request)
	b.mu.Lock()
	sender := b.sessions["ABCD1234"].clients[request.PeerId]
	b.mu.Unlock()
	packet := &wire.Envelope{Kind: wire.Envelope_RELAY_DATA, SessionId: "ABCD1234", PeerId: "host", RequestId: "flood", Payload: make([]byte, 1464)}
	for i := 0; i < 10000; i++ {
		if err := b.handle(sender, packet); err != nil {
			return
		}
	}
	t.Fatal("sustained relay input bypassed the sender limit")
}
