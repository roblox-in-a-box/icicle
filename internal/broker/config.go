package broker

import (
	"crypto/ed25519"
	"time"

	"icicle/internal/relay"
)

type Config struct {
	SigningKey          ed25519.PrivateKey
	AdminKeys           []ed25519.PublicKey
	RegistrationTimeout time.Duration
	AdmissionTimeout    time.Duration
	Relay               *relay.Server
	TrustLoopbackProxy  bool
}
