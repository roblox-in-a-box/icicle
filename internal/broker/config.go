package broker

import (
	"time"
)

type Config struct {
	RegistrationTimeout time.Duration
	AdmissionTimeout    time.Duration
}
