package broker

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/websocket"

	"icicle/internal/wire"
)

func TestTLSReverseProxy(t *testing.T) {
	_, backend := setup(t, Config{})
	target, _ := url.Parse(backend)
	edge := httptest.NewTLSServer(httputil.NewSingleHostReverseProxy(target))
	t.Cleanup(edge.Close)
	dialer := websocket.Dialer{TLSClientConfig: edge.Client().Transport.(*http.Transport).TLSClientConfig}
	res, err := edge.Client().Get(edge.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || string(body) != "ok\n" {
		t.Fatal("proxied health probe failed")
	}
	makePeer := func(header http.Header) *testPeer {
		conn, _, err := dialer.Dial("wss"+strings.TrimPrefix(edge.URL, "https"), header)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		p := &testPeer{conn: conn, key: key, build: &wire.BuildCompatibility{ProtocolVersion: 36, BuildVersion: "test", Revision: "test-revision"}}
		challenge := p.read(t, wire.Envelope_SERVER_CHALLENGE)
		p.challenge = challenge.Challenge
		p.authority = challenge.Authority.TicketPublicKeys[0]
		return p
	}
	h := makePeer(nil)
	h.hosting = true
	h.send(t, h.hostMessage("ABCD1234"))
	h.read(t, wire.Envelope_REGISTERED)
	c := makePeer(http.Header{"Origin": {edge.URL}})
	c.send(t, c.joinMessage("ABCD1234", "proxied-client"))
	c.read(t, wire.Envelope_REGISTERED)
	r := h.read(t, wire.Envelope_JOIN_REQUEST)
	h.send(t, answer(h, r))
	c.read(t, wire.Envelope_ADMITTED)
	c.send(t, &wire.Envelope{Kind: wire.Envelope_CANDIDATE, SessionId: "ABCD1234", Candidate: "proxied-candidate"})
	if got := h.read(t, wire.Envelope_CANDIDATE); got.PeerId != r.PeerId || got.Candidate != "proxied-candidate" {
		t.Fatal("proxied route failed")
	}
}
