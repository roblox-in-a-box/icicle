package relay

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/pion/stun/v4"
	"github.com/pion/turn/v5"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	s, err := New(Config{PublicIP: "203.0.113.10", UDPListen: "127.0.0.1:0", URLs: []string{"turn:127.0.0.1:3478"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func allocate(t *testing.T, s *Server, credentials Credentials) (*turn.Client, net.PacketConn) {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := s.udpAddress.String()
	t.Cleanup(func() { conn.Close() })
	client, err := turn.NewClient(&turn.ClientConfig{TURNServerAddr: address, Username: credentials.Username, Password: credentials.Password, Conn: conn, RTO: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	if err := client.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	allocation, err := client.AllocateWithContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { allocation.Close() })
	return client, allocation
}

func TestApprovedPairTransports(t *testing.T) {
	t.Run("UDP", func(t *testing.T) {
		s := testServer(t)
		h, c, _, revoke, err := s.IssuePair()
		if err != nil {
			t.Fatal(err)
		}
		defer revoke()
		host, hostConn := allocate(t, s, h)
		client, clientConn := allocate(t, s, c)
		if err := host.CreatePermission(clientConn.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		if err := client.CreatePermission(hostConn.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		if _, err := hostConn.WriteTo([]byte("approved"), clientConn.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		clientConn.SetReadDeadline(time.Now().Add(time.Second))
		buffer := make([]byte, 256)
		n, _, err := clientConn.ReadFrom(buffer)
		if err != nil || string(buffer[:n]) != "approved" {
			t.Fatalf("approved relay failed: %q %v", buffer[:n], err)
		}
		if _, err := clientConn.WriteTo([]byte("reply"), hostConn.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		hostConn.SetReadDeadline(time.Now().Add(time.Second))
		n, _, err = hostConn.ReadFrom(buffer)
		if err != nil || string(buffer[:n]) != "reply" {
			t.Fatalf("relay reply failed: %q %v", buffer[:n], err)
		}
	})
}

func TestRelayDestinationIsolationAndRevocation(t *testing.T) {
	s := testServer(t)
	h, c, _, revoke, err := s.IssuePair()
	if err != nil {
		t.Fatal(err)
	}
	defer revoke()
	h2, _, _, revoke2, err := s.IssuePair()
	if err != nil {
		t.Fatal(err)
	}
	defer revoke2()
	allocateRaw := func(user string) (net.PacketConn, net.Addr) {
		conn, addr, err := s.AllocatePacketConn(turn.AllocateListenerConfig{Network: "udp4", UserID: user})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return conn, addr
	}
	host, hostAddr := allocateRaw(h.Username)
	_, clientAddr := allocateRaw(c.Username)
	_, unrelated := allocateRaw(h2.Username)
	external, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer external.Close()
	p := host.(*packetConn)
	if !p.allowed(clientAddr, 10) {
		t.Fatal("approved peer was denied")
	}
	for _, addr := range []net.Addr{unrelated, external.LocalAddr(), hostAddr, &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 53}, &net.UDPAddr{IP: net.IPv6loopback, Port: 53}} {
		if p.allowed(addr, 10) {
			t.Fatalf("unapproved destination accepted: %s", addr)
		}
	}
	if _, err := host.WriteTo([]byte("must not escape"), external.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	external.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err := external.ReadFrom(make([]byte, 256)); err == nil {
		t.Fatal("relay sent data outside its approved pair")
	}
	if p.allowed(clientAddr, s.config.BytesPerSecond+1) {
		t.Fatal("bandwidth limit bypassed")
	}
	s.mu.Lock()
	p.grant.pair.expires = time.Now().Add(-time.Second)
	s.mu.Unlock()
	if p.allowed(clientAddr, 1) {
		t.Fatal("expired grant forwarded traffic")
	}
	revoke()
	if p.allowed(clientAddr, 1) {
		t.Fatal("revoked grant forwarded traffic")
	}
	if _, _, ok := s.authenticate(&turn.RequestAttributes{Username: h.Username, Realm: realm}); ok {
		t.Fatal("revoked credentials authenticated")
	}
}

func TestAllocationAndPairLimits(t *testing.T) {
	s := testServer(t)
	s.config.MaxPairs = 1
	h, _, _, revoke, err := s.IssuePair()
	if err != nil {
		t.Fatal(err)
	}
	defer revoke()
	if _, _, _, _, err := s.IssuePair(); err == nil {
		t.Fatal("pair capacity bypassed")
	}
	for i := 0; i < 5; i++ {
		conn, _, err := s.AllocatePacketConn(turn.AllocateListenerConfig{Network: "udp4", UserID: h.Username})
		if i == 4 {
			if err == nil {
				conn.Close()
				t.Fatal("allocation limit bypassed")
			}
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
	}
	if _, _, err := s.AllocatePacketConn(turn.AllocateListenerConfig{Network: "udp4", UserID: "unknown"}); err == nil {
		t.Fatal("unknown user allocated relay")
	}
	if _, _, err := s.AllocateListener(turn.AllocateListenerConfig{}); err == nil {
		t.Fatal("TCP peer listener enabled")
	}
	if _, err := s.AllocateConn(turn.AllocateConnConfig{}); err == nil {
		t.Fatal("TCP peer dialing enabled")
	}
}

func TestNoPublicBindingReflection(t *testing.T) {
	s := testServer(t)
	conn, err := net.Dial("udp4", s.udpAddress.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	if _, err := conn.Write(message.Raw); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err := conn.Read(make([]byte, 2048)); err == nil {
		t.Fatal("public STUN reflection is enabled")
	}
}

func TestBucketHasBoundedBurst(t *testing.T) {
	var b bucket
	now := time.Now()
	if !b.take(now, 40, 40) || b.take(now, 40, 1) {
		t.Fatal("burst limit failed")
	}
	if !b.take(now.Add(time.Second), 40, 40) || b.take(now.Add(time.Second), 40, 1) {
		t.Fatal("refill limit failed")
	}
}
