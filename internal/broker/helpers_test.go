package broker

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"

	"icicle/internal/wire"
)

type testPeer struct {
	conn      *websocket.Conn
	key       ed25519.PrivateKey
	challenge []byte
}

func marshalMessage(m proto.Message) []byte {
	data, err := proto.Marshal(m)
	if err != nil {
		panic(err)
	}
	return data
}

func setup(t *testing.T, config Config) (*Broker, string) {
	t.Helper()
	b := New(config)
	s := httptest.NewServer(b)
	t.Cleanup(func() { b.Close(); s.Close() })
	return b, s.URL
}

func connect(t *testing.T, url string) *testPeer {
	t.Helper()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(url, "http")+"/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &testPeer{conn: c, key: key}
	m := p.read(t, wire.Envelope_SERVER_CHALLENGE)
	if len(m.Challenge) != 32 {
		t.Fatal("challenge must be 32 bytes")
	}
	p.challenge = m.Challenge
	return p
}

func (p *testPeer) read(t *testing.T, kind wire.Envelope_Kind) *wire.Envelope {
	t.Helper()
	p.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	typ, data, err := p.conn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	m := new(wire.Envelope)
	if typ != websocket.BinaryMessage || proto.Unmarshal(data, m) != nil || m.Kind != kind {
		t.Fatalf("wanted kind %d, got %+v", kind, m)
	}
	return m
}

func (p *testPeer) send(t *testing.T, m *wire.Envelope) {
	t.Helper()
	if err := p.conn.WriteMessage(websocket.BinaryMessage, marshalMessage(m)); err != nil {
		t.Fatal(err)
	}
}

func (p *testPeer) sign(prefix string, data []byte) []byte {
	return ed25519.Sign(p.key, append([]byte(prefix), data...))
}

func (p *testPeer) hostMessage(code string) *wire.Envelope {
	data := append([]byte(code+"\n"), p.challenge...)
	return &wire.Envelope{Kind: wire.Envelope_REGISTER_HOST, SessionId: code, PublicKey: p.key.Public().(ed25519.PublicKey), Signature: p.sign("icicle/register/host/v1\n", data)}
}

func host(t *testing.T, url, code string) *testPeer {
	t.Helper()
	p := connect(t, url)
	p.send(t, p.hostMessage(code))
	m := p.read(t, wire.Envelope_REGISTERED)
	if m.SessionId != code || !bytes.Equal(m.PublicKey, p.key.Public().(ed25519.PublicKey)) {
		t.Fatal("host identity mismatch")
	}
	return p
}

func (p *testPeer) joinMessage(code, requestID string) *wire.Envelope {
	r := &wire.JoinRequest{Version: 1, SessionId: code, RequestId: requestID, ClientPublicKey: p.key.Public().(ed25519.PublicKey), Offer: "v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n", Challenge: p.challenge}
	payload := marshalMessage(r)
	return &wire.Envelope{Kind: wire.Envelope_REGISTER_CLIENT, SessionId: code, RequestId: requestID, PublicKey: r.ClientPublicKey, Payload: payload, Signature: p.sign("icicle/join/v1\n", payload)}
}

func join(t *testing.T, url, code, requestID string, h *testPeer) (*testPeer, *wire.Envelope) {
	t.Helper()
	c := connect(t, url)
	m := c.joinMessage(code, requestID)
	c.send(t, m)
	registered := c.read(t, wire.Envelope_REGISTERED)
	if registered.SessionId != code || registered.RequestId != requestID || !tokenPattern.MatchString(registered.PeerId) || !bytes.Equal(registered.PublicKey, h.key.Public().(ed25519.PublicKey)) {
		t.Fatal("client registration mismatch")
	}
	r := h.read(t, wire.Envelope_JOIN_REQUEST)
	if r.PeerId != registered.PeerId || !bytes.Equal(r.Payload, m.Payload) || !bytes.Equal(r.Signature, m.Signature) {
		t.Fatal("join proof changed")
	}
	return c, r
}

func answer(h *testPeer, r *wire.Envelope) *wire.Envelope {
	request := new(wire.JoinRequest)
	proto.Unmarshal(r.Payload, request)
	digest := sha256.Sum256([]byte(request.Offer))
	ticket := &wire.ClientTicket{Version: 1, SessionId: r.SessionId, PeerId: r.PeerId, RequestId: r.RequestId, ClientPublicKey: request.ClientPublicKey, HostPublicKey: h.key.Public().(ed25519.PublicKey), OfferSha256: digest[:], ExpiresUnix: time.Now().Unix() + 30, TicketId: bytes.Repeat([]byte{7}, 32)}
	ticketBytes := marshalMessage(ticket)
	a := &wire.HostAnswer{TicketPayload: ticketBytes, TicketSignature: h.sign("icicle/ticket/v1\n", ticketBytes), Answer: "v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"}
	payload := marshalMessage(a)
	return &wire.Envelope{Kind: wire.Envelope_ADMITTED, SessionId: r.SessionId, PeerId: r.PeerId, RequestId: r.RequestId, Payload: payload, Signature: h.sign("icicle/answer/v1\n", payload)}
}
