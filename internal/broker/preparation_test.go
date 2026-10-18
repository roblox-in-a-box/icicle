package broker

import (
	"crypto/ed25519"
	"testing"

	"google.golang.org/protobuf/proto"

	"icicle/internal/relay"
	"icicle/internal/wire"
)

func prepareClient(t *testing.T, url string, h *testPeer, requestID string) (*testPeer, *wire.Envelope) {
	t.Helper()
	c := connect(t, url)
	m := c.joinMessage("ABCD1234", requestID)
	r := new(wire.JoinRequest)
	if err := proto.Unmarshal(m.Payload, r); err != nil {
		t.Fatal(err)
	}
	r.Offer = ""
	m.Kind = wire.Envelope_PREPARE_CLIENT
	m.Payload = marshalMessage(r)
	m.Signature = c.sign("icicle/join/v1\n", m.Payload)
	c.send(t, m)
	c.read(t, wire.Envelope_REGISTERED)
	return c, h.read(t, wire.Envelope_PREPARE_JOIN)
}

func TestRelayPreparationRequiresHostApproval(t *testing.T) {
	s, err := relay.New(relay.Config{PublicIP: "127.0.0.1", UDPListen: "127.0.0.1:0", URLs: []string{"turn:127.0.0.1:3478"}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, url := setup(t, Config{Relay: s})
	h := host(t, url, "ABCD1234")
	h.send(t, &wire.Envelope{Kind: wire.Envelope_ROUTE_STATUS, SessionId: "ABCD1234", PreferRelay: true})
	c, request := prepareClient(t, url, h, "prepared")
	h.send(t, &wire.Envelope{Kind: wire.Envelope_PREPARE_ACCEPT, SessionId: request.SessionId, PeerId: request.PeerId, RequestId: request.RequestId})
	hostGrant := h.read(t, wire.Envelope_PREPARED)
	clientGrant := c.read(t, wire.Envelope_PREPARED)
	if hostGrant.Relay == nil || clientGrant.Relay == nil || hostGrant.Relay.Username == clientGrant.Relay.Username || !hostGrant.PreferRelay || !clientGrant.PreferRelay {
		t.Fatal("approved pair did not receive separate credentials and host relay policy")
	}
	offer := c.joinMessage("ABCD1234", "prepared")
	offer.Kind = wire.Envelope_OFFER_READY
	c.send(t, offer)
	join := h.read(t, wire.Envelope_JOIN_REQUEST)
	if string(join.Payload) != string(offer.Payload) {
		t.Fatal("prepared offer proof changed")
	}
	h.send(t, answer(h, join))
	c.read(t, wire.Envelope_ADMITTED)
}

func TestPreparedIdentityCannotChange(t *testing.T) {
	for _, change := range []string{"unapproved", "username", "build", "key"} {
		t.Run(change, func(t *testing.T) {
			_, url := setup(t, Config{})
			h := host(t, url, "ABCD1234")
			c, request := prepareClient(t, url, h, "prepared")
			if change != "unapproved" {
				h.send(t, &wire.Envelope{Kind: wire.Envelope_PREPARE_ACCEPT, SessionId: request.SessionId, PeerId: request.PeerId, RequestId: request.RequestId})
				h.read(t, wire.Envelope_PREPARED)
				c.read(t, wire.Envelope_PREPARED)
			}
			m := c.joinMessage("ABCD1234", "prepared")
			m.Kind = wire.Envelope_OFFER_READY
			r := new(wire.JoinRequest)
			if err := proto.Unmarshal(m.Payload, r); err != nil {
				t.Fatal(err)
			}
			signer := c
			switch change {
			case "username":
				r.Username = "Substituted"
			case "build":
				r.Build.Revision = "changed"
			case "key":
				signer = connect(t, url)
				m.PublicKey = signer.key.Public().(ed25519.PublicKey)
				r.ClientPublicKey = m.PublicKey
			}
			m.Payload = marshalMessage(r)
			m.Signature = signer.sign("icicle/join/v1\n", m.Payload)
			c.send(t, m)
			c.read(t, wire.Envelope_ERROR)
		})
	}
}
