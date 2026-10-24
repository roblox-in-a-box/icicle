package broker

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestParseTrustedProxies(t *testing.T) {
	proxies, err := ParseTrustedProxies([]string{"10.0.0.5", "192.168.1.0/24", "2001:db8::1", "fd00::/64"})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		ip   string
		want bool
	}{
		{"10.0.0.5", true},
		{"10.0.0.6", false},
		{"192.168.1.200", true},
		{"192.168.2.1", false},
		{"2001:db8::1", true},
		{"2001:db8::2", false},
		{"fd00::abcd", true},
		{"::ffff:10.0.0.5", true},
	} {
		if got := trustedProxy(net.ParseIP(test.ip), false, proxies); got != test.want {
			t.Fatalf("trusted %s = %t, wanted %t", test.ip, got, test.want)
		}
	}
	for _, invalid := range []string{"", "nginx.lan", "10.0.0.0/33", "0.0.0.0/0", "::/0", " 10.0.0.5"} {
		if _, err := ParseTrustedProxies([]string{invalid}); err == nil {
			t.Fatalf("trusted proxy %q was accepted", invalid)
		}
	}
	if _, err := ParseTrustedProxies(make([]string, 257)); err == nil {
		t.Fatal("unbounded trusted proxy list was accepted")
	}
}

func TestTrustedProxySource(t *testing.T) {
	proxies, err := ParseTrustedProxies([]string{"10.0.0.5"})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		remote, header, want string
		loopback             bool
	}{
		{"10.0.0.5:1000", "203.0.113.1", "203.0.113.1", false},
		{"10.0.0.5:1000", "", "10.0.0.5", false},
		{"10.0.0.6:1000", "203.0.113.1", "10.0.0.6", false},
		{"198.51.100.1:1000", "203.0.113.1", "198.51.100.1", false},
		{"127.0.0.1:1000", "203.0.113.1", "127.0.0.1", false},
		{"127.0.0.1:1000", "203.0.113.1", "203.0.113.1", true},
		{"10.0.0.5:1000", "2001:db8::7", "2001:db8::7", false},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = test.remote
		if test.header != "" {
			r.Header.Set("X-Icicle-Client-IP", test.header)
		}
		got, err := clientIP(r, test.loopback, proxies)
		if err != nil || got != test.want {
			t.Fatalf("client source via %s = %q %v, wanted %q", test.remote, got, err, test.want)
		}
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.5:1000"
	r.Header.Set("X-Icicle-Client-IP", "198.51.100.1, 203.0.113.1")
	if _, err := clientIP(r, false, proxies); err == nil {
		t.Fatal("ambiguous trusted proxy source was accepted")
	}
}

func TestBrokerUsesTrustedProxySource(t *testing.T) {
	for _, test := range []struct {
		name    string
		proxies []string
		want    string
	}{
		{"trusted", []string{"127.0.0.1/32"}, "203.0.113.9"},
		{"untrusted", []string{"10.0.0.5"}, "127.0.0.1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			proxies, err := ParseTrustedProxies(test.proxies)
			if err != nil {
				t.Fatal(err)
			}
			b, url := setup(t, Config{TrustedProxies: proxies})
			conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(url, "http"), http.Header{"X-Icicle-Client-IP": {"203.0.113.9"}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { conn.Close() })
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, _, err := conn.ReadMessage(); err != nil {
				t.Fatal(err)
			}
			b.mu.Lock()
			defer b.mu.Unlock()
			if len(b.connections) != 1 {
				t.Fatalf("connections = %d, wanted 1", len(b.connections))
			}
			for p := range b.connections {
				if p.sourceIP != test.want {
					t.Fatalf("source = %q, wanted %q", p.sourceIP, test.want)
				}
			}
		})
	}
}
