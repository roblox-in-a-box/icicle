package broker

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"icicle/internal/wire"
)

func TestJoinUsernameValidation(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	challenge := bytes.Repeat([]byte{1}, 32)
	for _, name := range []string{"A", "Player_42", "Two Words", "Two  Words", strings.Repeat("A", 32),
		"", " ", " Leading", "Trailing ", "User\tName", "User\nName", "User/Name", "User\x00Name", "Jósé", strings.Repeat("A", 33)} {
		t.Run(name, func(t *testing.T) {
			valid := name == "A" || name == "Player_42" || name == "Two Words" || name == "Two  Words" || name == strings.Repeat("A", 32)
			for _, kind := range []wire.Envelope_Kind{wire.Envelope_REGISTER_CLIENT, wire.Envelope_PREPARE_CLIENT} {
				request := &wire.JoinRequest{Version: 2, SessionId: "ABCD1234", RequestId: "request", Username: name,
					ClientPublicKey: public, Challenge: challenge, Build: &wire.BuildCompatibility{ProtocolVersion: 36, BuildVersion: "test"}}
				if kind == wire.Envelope_REGISTER_CLIENT {
					request.Offer = "offer"
				}
				payload := marshalMessage(request)
				message := &wire.Envelope{Kind: kind, SessionId: request.SessionId, RequestId: request.RequestId,
					PublicKey: public, Payload: payload, Signature: ed25519.Sign(private, append([]byte("icicle/join/v1\n"), payload...))}
				_, err := validateJoinRequest(&peer{challenge: challenge}, message)
				if valid && err != nil {
					t.Fatalf("valid username rejected: %v", err)
				}
				if !valid && (err == nil || err.Error() != "invalid username") {
					t.Fatalf("invalid username was not rejected: %v", err)
				}
			}
		})
	}
}
