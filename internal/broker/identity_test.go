package broker

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"icicle/internal/wire"
)

func TestAuthorityPersistsAndRejectsCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authority.key")
	first, err := LoadAuthority(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadAuthority(path)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("authority changed after restart", err)
	}
	if err := os.WriteFile(path, []byte("damaged"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAuthority(path); err == nil {
		t.Fatal("corrupt authority was silently regenerated")
	}
	contents, _ := os.ReadFile(path)
	if string(contents) != "damaged" {
		t.Fatal("corrupt authority was overwritten")
	}
}

func TestAuthorityConcurrentStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authority.key")
	results := make(chan ed25519.PrivateKey, 8)
	for range 8 {
		go func() {
			key, err := LoadAuthority(path)
			if err != nil {
				t.Error(err)
			}
			results <- key
		}()
	}
	first := <-results
	for range 7 {
		if key := <-results; len(key) != ed25519.PrivateKeySize || !bytes.Equal(first, key) {
			t.Fatal("concurrent authority startup produced different keys")
		}
	}
}

func TestPublishedAdminPolicy(t *testing.T) {
	public := bytes.Repeat([]byte{7}, 32)
	id := "ed25519:" + base64.RawURLEncoding.EncodeToString(public)
	keys, err := ParseAdminKeys("# Trusted administrators\n" + id + "\n")
	if err != nil {
		t.Fatal(err)
	}
	_, url := setup(t, Config{AdminKeys: keys})
	p := connect(t, url)
	if len(p.authority) != 32 {
		t.Fatal("missing authority verification key")
	}
	for _, invalid := range []string{"123", "ed25519:AA", "ed25519:" + base64.StdEncoding.EncodeToString(public)} {
		if _, err := ParseAdminKeys(invalid); err == nil {
			t.Fatalf("accepted invalid admin identity %q", invalid)
		}
	}
}

func TestBuildDriftAndProtocolMismatch(t *testing.T) {
	_, url := setup(t, Config{})
	h := connect(t, url)
	h.hosting = true
	h.build.BuildVersion = "v1.0.0"
	h.send(t, h.hostMessage("ABCD1234"))
	h.read(t, wire.Envelope_REGISTERED)
	c := connect(t, url)
	c.build.BuildVersion = "v1.1.0"
	c.build.Revision = "client-only-changes"
	c.send(t, c.joinMessage("ABCD1234", "compatible"))
	c.read(t, wire.Envelope_REGISTERED)
	request := h.read(t, wire.Envelope_JOIN_REQUEST)
	h.send(t, answer(h, request))
	issued := verifyIssued(t, c, c.read(t, wire.Envelope_ADMITTED))
	if issued.HostBuild.BuildVersion != "v1.0.0" || issued.ClientBuild.BuildVersion != "v1.1.0" {
		t.Fatal("ticket lost build diagnostics")
	}
	different := connect(t, url)
	different.build.ProtocolVersion++
	different.send(t, different.joinMessage("ABCD1234", "incompatible"))
	rejection := different.read(t, wire.Envelope_ERROR)
	if !strings.Contains(rejection.Error, "incompatible replication protocol") {
		t.Fatal("missing compatibility diagnostic", rejection.Error)
	}
}

func TestDuplicateUsernameAndIdentityReservations(t *testing.T) {
	_, url := setup(t, Config{})
	h := host(t, url, "ABCD1234")
	first := connect(t, url)
	original := first.joinMessage("ABCD1234", "first")
	request := new(wire.JoinRequest)
	proto.Unmarshal(original.Payload, request)
	request.Username = "PlayerOne"
	original.Payload = marshalMessage(request)
	original.Signature = first.sign("icicle/join/v1\n", original.Payload)
	first.send(t, original)
	first.read(t, wire.Envelope_REGISTERED)
	h.read(t, wire.Envelope_JOIN_REQUEST)
	for _, sameKey := range []bool{false, true} {
		c := connect(t, url)
		if sameKey {
			c.key = first.key
		}
		message := c.joinMessage("ABCD1234", "duplicate")
		r := new(wire.JoinRequest)
		proto.Unmarshal(message.Payload, r)
		if sameKey {
			r.Username = "AnotherName"
		} else {
			r.Username = "pLaYeRoNe"
		}
		message.Payload = marshalMessage(r)
		message.Signature = c.sign("icicle/join/v1\n", message.Payload)
		c.send(t, message)
		c.read(t, wire.Envelope_ERROR)
	}
	first.conn.Close()
	h.read(t, wire.Envelope_PEER_LEFT)
	next := connect(t, url)
	message := next.joinMessage("ABCD1234", "reclaimed")
	proto.Unmarshal(message.Payload, request)
	request.Username = "PlayerOne"
	message.Payload = marshalMessage(request)
	message.Signature = next.sign("icicle/join/v1\n", message.Payload)
	next.send(t, message)
	next.read(t, wire.Envelope_REGISTERED)
	h.read(t, wire.Envelope_JOIN_REQUEST)
}

func TestHostCannotChangeSignedClientIdentity(t *testing.T) {
	for _, field := range []string{"username", "UserId", "client-build", "host-build"} {
		t.Run(field, func(t *testing.T) {
			_, url := setup(t, Config{})
			h := host(t, url, "ABCD1234")
			_, request := join(t, url, "ABCD1234", "request", h)
			message := answer(h, request)
			admission := new(wire.HostAnswer)
			proto.Unmarshal(message.Payload, admission)
			ticket := new(wire.ClientTicket)
			proto.Unmarshal(admission.TicketPayload, ticket)
			switch field {
			case "username":
				ticket.Username = "Substituted"
			case "UserId":
				ticket.UserId = -1
			case "client-build":
				ticket.ClientBuild.ProtocolVersion++
			case "host-build":
				ticket.HostBuild.Revision = "substituted"
			}
			admission.TicketPayload = marshalMessage(ticket)
			admission.TicketSignature = h.sign("icicle/ticket/v1\n", admission.TicketPayload)
			message.Payload = marshalMessage(admission)
			message.Signature = h.sign("icicle/answer/v1\n", message.Payload)
			h.send(t, message)
			h.read(t, wire.Envelope_ERROR)
		})
	}
}
