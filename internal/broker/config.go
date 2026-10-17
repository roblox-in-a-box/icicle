package broker

import (
	"crypto/ed25519"
	"time"
)

type Config struct {
	SigningKey          ed25519.PrivateKey
	AdminKeys           []ed25519.PublicKey
	RegistrationTimeout time.Duration
	AdmissionTimeout    time.Duration
}
