package broker

import (
	"fmt"
	"net/http/httptest"
	"testing"
)

func TestProxySourceCannotBeSpoofedDirectly(t *testing.T) {
	for _, test := range []struct {
		remote, header, want string
		trusted              bool
	}{
		{"198.51.100.1:1000", "203.0.113.1", "198.51.100.1", false},
		{"198.51.100.1:1000", "203.0.113.1", "198.51.100.1", true},
		{"127.0.0.1:1000", "203.0.113.1", "127.0.0.1", false},
		{"127.0.0.1:1000", "203.0.113.1", "203.0.113.1", true},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = test.remote
		r.Header.Set("X-Icicle-Client-IP", test.header)
		got, err := clientIP(r, test.trusted, nil)
		if err != nil || got != test.want {
			t.Fatalf("client source = %q %v, wanted %q", got, err, test.want)
		}
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:1000"
	r.Header.Set("X-Icicle-Client-IP", "198.51.100.1, 203.0.113.1")
	if _, err := clientIP(r, true, nil); err == nil {
		t.Fatal("ambiguous proxy source was accepted")
	}
}

func TestRelayCapacityIsBoundedPerHostAndSource(t *testing.T) {
	h := &peer{sourceIP: "198.51.100.1"}
	c := &peer{sourceIP: "203.0.113.1"}
	s := &session{host: h, clients: make(map[string]*peer)}
	b := &Broker{sessions: map[string]*session{"first": s}}
	for i := 0; i < 16; i++ {
		s.clients[fmt.Sprint(i)] = &peer{sourceIP: "192.0.2.1", relayRevoke: func() {}}
	}
	if b.relayCapacityAvailable(s, c) {
		t.Fatal("per-host relay limit was bypassed")
	}
	s.clients = make(map[string]*peer)
	for i := 0; i < 32; i++ {
		b.sessions[fmt.Sprint(i)] = &session{host: &peer{sourceIP: h.sourceIP}, clients: map[string]*peer{"client": {sourceIP: "192.0.2.1", relayRevoke: func() {}}}}
	}
	if b.relayCapacityAvailable(s, c) {
		t.Fatal("per-source relay limit was bypassed across hosts")
	}
	h.sourceIP = "198.51.100.2"
	if !b.relayCapacityAvailable(s, c) {
		t.Fatal("one source exhausted another source's relay allowance")
	}
}
