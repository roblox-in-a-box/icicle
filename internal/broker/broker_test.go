package broker

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"

	"icicle/internal/wire"
)

func TestSignedPayloadBytesArePreserved(t *testing.T) {
	_, url := setup(t, Config{})
	h := host(t, url, "ABCD1234")
	c := connect(t, url)
	unknown, err := hex.DecodeString("a00601")
	if err != nil {
		t.Fatal(err)
	}
	m := c.joinMessage("ABCD1234", "signed-bytes")
	m.Payload = append(m.Payload, unknown...)
	m.Signature = c.sign("icicle/join/v1\n", m.Payload)
	c.send(t, m)
	c.read(t, wire.Envelope_REGISTERED)
	r := h.read(t, wire.Envelope_JOIN_REQUEST)
	if !bytes.Equal(r.Payload, m.Payload) || !bytes.Equal(r.Signature, m.Signature) {
		t.Fatal("signed join request was changed")
	}
	a := answer(h, r)
	a.Payload = append(a.Payload, unknown...)
	a.Signature = h.sign("icicle/answer/v1\n", a.Payload)
	h.send(t, a)
	admitted := c.read(t, wire.Envelope_ADMITTED)
	if !bytes.Equal(admitted.Payload, a.Payload) || !bytes.Equal(admitted.Signature, a.Signature) {
		t.Fatal("signed host answer was changed")
	}
}

func TestHealthAndRoutes(t *testing.T) {
	_, url := setup(t, Config{})
	for _, tc := range []struct {
		method, path string
		status       int
		body         string
	}{{"GET", "/healthz", 200, "ok\n"}, {"POST", "/healthz", 405, ""}, {"GET", "/missing", 404, ""}, {"GET", "/ws", 400, ""}} {
		req, _ := http.NewRequest(tc.method, url+tc.path, nil)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != tc.status || (tc.body != "" && string(data) != tc.body) {
			t.Fatalf("%s %s: %d %q", tc.method, tc.path, res.StatusCode, data)
		}
	}
}

func TestTLSWebSocket(t *testing.T) {
	b := New(Config{})
	s := httptest.NewTLSServer(b)
	t.Cleanup(func() { b.Close(); s.Close() })
	transport := s.Client().Transport.(*http.Transport)
	dialer := websocket.Dialer{TLSClientConfig: transport.TLSClientConfig}
	c, _, err := dialer.Dial("wss"+strings.TrimPrefix(s.URL, "https")+"/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(time.Second))
	_, data, err := c.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	message := new(wire.Envelope)
	if proto.Unmarshal(data, message) != nil || message.Kind != wire.Envelope_SERVER_CHALLENGE || len(message.Challenge) != 32 {
		t.Fatal("invalid TLS handshake")
	}
}

func TestThreeClientsAdmissionAndRouting(t *testing.T) {
	_, url := setup(t, Config{})
	h := host(t, url, "ABCD1234")
	clients := make([]*testPeer, 3)
	requests := make([]*wire.Envelope, 3)
	for i := range clients {
		c, r := join(t, url, "ABCD1234", fmt.Sprintf("request%d", i), h)
		clients[i], requests[i] = c, r
		m := answer(h, r)
		h.send(t, m)
		got := c.read(t, wire.Envelope_ADMITTED)
		if !bytes.Equal(got.Payload, m.Payload) || !bytes.Equal(got.Signature, m.Signature) || got.PeerId != r.PeerId {
			t.Fatal("admission changed")
		}
	}
	for i, c := range clients {
		c.send(t, &wire.Envelope{Kind: wire.Envelope_CANDIDATE, SessionId: "ABCD1234", PeerId: "host", Candidate: fmt.Sprintf("candidate%d", i), Mid: "0"})
		m := h.read(t, wire.Envelope_CANDIDATE)
		if m.PeerId != requests[i].PeerId || m.RequestId != requests[i].RequestId {
			t.Fatal("wrong host route")
		}
		h.send(t, m)
		got := c.read(t, wire.Envelope_CANDIDATE)
		if got.Candidate != m.Candidate {
			t.Fatal("wrong client route")
		}
	}
	clients[0].conn.Close()
	left := h.read(t, wire.Envelope_PEER_LEFT)
	if left.PeerId != requests[0].PeerId {
		t.Fatal("wrong disconnect route")
	}
	h.conn.Close()
	for _, c := range clients[1:] {
		c.read(t, wire.Envelope_ERROR)
	}
}

func TestHostRegistrationFailures(t *testing.T) {
	_, url := setup(t, Config{})
	host(t, url, "ABCD1234")
	for _, name := range []string{"duplicate", "signature", "challenge", "code", "unregistered", "text", "malformed"} {
		t.Run(name, func(t *testing.T) {
			p := connect(t, url)
			m := p.hostMessage("EFGH5678")
			switch name {
			case "duplicate":
				m = p.hostMessage("ABCD1234")
			case "signature":
				m.Signature[0] ^= 1
			case "challenge":
				p.challenge[0] ^= 1
				m = p.hostMessage("EFGH5678")
			case "code":
				m = p.hostMessage("abcd1234")
			case "unregistered":
				m.Kind = wire.Envelope_CANDIDATE
			case "text":
				p.conn.WriteMessage(websocket.TextMessage, []byte("hello"))
				p.read(t, wire.Envelope_ERROR)
				return
			case "malformed":
				p.conn.WriteMessage(websocket.BinaryMessage, []byte{0xff})
				p.read(t, wire.Envelope_ERROR)
				return
			}
			p.send(t, m)
			p.read(t, wire.Envelope_ERROR)
		})
	}
}

func TestJoinFailuresDoNotDisruptHost(t *testing.T) {
	_, url := setup(t, Config{})
	h := host(t, url, "ABCD1234")
	for _, name := range []string{"missing", "signature", "challenge", "key", "request", "version", "oversized"} {
		t.Run(name, func(t *testing.T) {
			c := connect(t, url)
			m := c.joinMessage("ABCD1234", "request")
			r := new(wire.JoinRequest)
			proto.Unmarshal(m.Payload, r)
			switch name {
			case "missing":
				m = c.joinMessage("EFGH5678", "request")
			case "signature":
				m.Signature[0] ^= 1
			case "key":
				m.PublicKey = bytes.Repeat([]byte{1}, 32)
			case "request":
				m.RequestId = "wrong"
			case "challenge":
				r.Challenge[0] ^= 1
			case "version":
				r.Version = 2
			case "oversized":
				r.Offer = strings.Repeat("x", 48*1024+1)
			}
			if name == "challenge" || name == "version" || name == "oversized" {
				m.Payload = marshalMessage(r)
				m.Signature = c.sign("icicle/join/v1\n", m.Payload)
			}
			c.send(t, m)
			c.read(t, wire.Envelope_ERROR)
		})
	}
	c, r := join(t, url, "ABCD1234", "valid", h)
	h.send(t, answer(h, r))
	c.read(t, wire.Envelope_ADMITTED)
}

func TestRejection(t *testing.T) {
	_, url := setup(t, Config{})
	h := host(t, url, "ABCD1234")
	c, r := join(t, url, "ABCD1234", "first", h)
	h.send(t, &wire.Envelope{Kind: wire.Envelope_REJECTED, SessionId: r.SessionId, PeerId: r.PeerId, RequestId: r.RequestId})
	c.read(t, wire.Envelope_REJECTED)
	next, request := join(t, url, "ABCD1234", "third", h)
	h.send(t, answer(h, request))
	next.read(t, wire.Envelope_ADMITTED)
}

func TestMoreThanSixteenClients(t *testing.T) {
	_, url := setup(t, Config{})
	h := host(t, url, "ABCD1234")
	for i := 0; i < 17; i++ {
		c, r := join(t, url, "ABCD1234", fmt.Sprintf("request%d", i), h)
		h.send(t, answer(h, r))
		c.read(t, wire.Envelope_ADMITTED)
	}
}

func TestAdmissionValidation(t *testing.T) {
	for _, name := range []string{"signature", "ticket-signature", "session", "peer", "request", "client-key", "host-key", "hash", "expired", "future", "ticket-id"} {
		t.Run(name, func(t *testing.T) {
			_, url := setup(t, Config{})
			h := host(t, url, "ABCD1234")
			_, r := join(t, url, "ABCD1234", "request", h)
			m := answer(h, r)
			a := new(wire.HostAnswer)
			proto.Unmarshal(m.Payload, a)
			ticket := new(wire.ClientTicket)
			proto.Unmarshal(a.TicketPayload, ticket)
			switch name {
			case "signature":
				m.Signature[0] ^= 1
			case "ticket-signature":
				a.TicketSignature[0] ^= 1
			case "session":
				ticket.SessionId = "EFGH5678"
			case "peer":
				ticket.PeerId = "another"
			case "request":
				ticket.RequestId = "another"
			case "client-key":
				ticket.ClientPublicKey[0] ^= 1
			case "host-key":
				ticket.HostPublicKey[0] ^= 1
			case "hash":
				ticket.OfferSha256[0] ^= 1
			case "expired":
				ticket.ExpiresUnix = time.Now().Unix() - 1
			case "future":
				ticket.ExpiresUnix = time.Now().Unix() + 120
			case "ticket-id":
				ticket.TicketId = []byte{1}
			}
			if name != "signature" {
				if name != "ticket-signature" {
					a.TicketPayload = marshalMessage(ticket)
					a.TicketSignature = h.sign("icicle/ticket/v1\n", a.TicketPayload)
				}
				m.Payload = marshalMessage(a)
				m.Signature = h.sign("icicle/answer/v1\n", m.Payload)
			}
			h.send(t, m)
			h.read(t, wire.Envelope_ERROR)
		})
	}
}

func TestSessionIsolation(t *testing.T) {
	_, url := setup(t, Config{})
	h := host(t, url, "ABCD1234")
	other := host(t, url, "EFGH5678")
	c, r := join(t, url, "ABCD1234", "request", h)
	forged := answer(other, r)
	forged.SessionId = "EFGH5678"
	other.send(t, forged)
	other.read(t, wire.Envelope_ERROR)
	h.send(t, answer(h, r))
	c.read(t, wire.Envelope_ADMITTED)
	c.send(t, &wire.Envelope{Kind: wire.Envelope_CANDIDATE, SessionId: "EFGH5678", Candidate: "test"})
	c.read(t, wire.Envelope_ERROR)
	h.read(t, wire.Envelope_PEER_LEFT)
}

func TestTimeoutsAndShutdown(t *testing.T) {
	b, url := setup(t, Config{RegistrationTimeout: 20 * time.Millisecond, AdmissionTimeout: 20 * time.Millisecond})
	unused := connect(t, url)
	unused.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := unused.conn.ReadMessage(); err == nil {
		t.Fatal("unregistered peer did not expire")
	}
	h := host(t, url, "ABCD1234")
	c, r := join(t, url, "ABCD1234", "request", h)
	if left := h.read(t, wire.Envelope_PEER_LEFT); left.PeerId != r.PeerId {
		t.Fatal("pending client did not expire")
	}
	c.conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := c.conn.ReadMessage(); err == nil {
		t.Fatal("pending client stayed open")
	}
	b.Close()
	h.conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := h.conn.ReadMessage(); err == nil {
		t.Fatal("shutdown left host open")
	}
}
