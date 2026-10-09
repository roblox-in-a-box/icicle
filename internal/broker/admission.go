// TODO: per-lobby admission policy e.g whitelisting users by UniqueUserId.
// ? ^^ operate this & icicle level or rak level?

// TODO: use existing rbx client ticket flow except it verifies the final join ticket is signed by icicle
// for anyone reading this, yes we have many ideas. many ambitious ones. please ignore my shit code. -b
package broker

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"icicle/internal/wire"
)

func verify(key []byte, prefix string, payload, signature []byte) bool {
	return len(key) == ed25519.PublicKeySize && len(signature) == ed25519.SignatureSize && ed25519.Verify(key, append([]byte(prefix), payload...), signature)
}

func validateAnswer(s *session, c *peer, m *wire.Envelope, now time.Time) error {
	invalid := func(reason string) error {
		return fmt.Errorf("invalid host admission: %s", reason)
	}
	if len(m.Payload) > 64*1024 {
		return invalid("answer payload too large")
	}
	if !verify(s.host.key, "icicle/answer/v1\n", m.Payload, m.Signature) {
		return invalid("invalid answer signature")
	}
	answer := new(wire.HostAnswer)
	decoder := proto.UnmarshalOptions{DiscardUnknown: true}
	if decoder.Unmarshal(m.Payload, answer) != nil {
		return invalid("malformed host answer")
	}
	if len(answer.Answer) == 0 || len(answer.Answer) > 48*1024 {
		return invalid("invalid answer description size")
	}
	if len(answer.TicketPayload) > 4096 {
		return invalid("ticket payload too large")
	}
	ticket := new(wire.ClientTicket)
	if decoder.Unmarshal(answer.TicketPayload, ticket) != nil {
		return invalid("malformed ticket")
	}
	if !verify(s.host.key, "icicle/ticket/v1\n", answer.TicketPayload, answer.TicketSignature) {
		return invalid("invalid ticket signature")
	}
	digest := sha256.Sum256([]byte(c.request.Offer))
	checks := []struct {
		valid  bool
		reason string
	}{
		{ticket.Version == 1, "unsupported ticket version"},
		{ticket.SessionId == s.id, "ticket lobby mismatch"},
		{ticket.PeerId == c.id, "ticket peer mismatch"},
		{ticket.RequestId == c.request.RequestId, "ticket request mismatch"},
		{bytes.Equal(ticket.ClientPublicKey, c.key), "ticket client key mismatch"},
		{bytes.Equal(ticket.HostPublicKey, s.host.key), "ticket host key mismatch"},
		{bytes.Equal(ticket.OfferSha256, digest[:]), "ticket offer digest mismatch"},
		{len(ticket.TicketId) == 32, "invalid ticket ID size"},
	}
	for _, check := range checks {
		if !check.valid {
			return invalid(check.reason)
		}
	}
	if ticket.ExpiresUnix <= now.Unix() || ticket.ExpiresUnix > now.Unix()+60 {
		return fmt.Errorf("invalid host admission: ticket expiry outside broker window expiry_unix=%d broker_unix=%d delta_seconds=%d allowed_delta_seconds=1..60", ticket.ExpiresUnix, now.Unix(), ticket.ExpiresUnix-now.Unix())
	}

	return nil
}
