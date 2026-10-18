package relay

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

const realm = "icicle"

type Config struct {
	PublicIP            string
	UDPListen           string
	URLs                []string
	BytesPerSecond      int
	MaxPairs            int
	TotalBytesPerSecond int
}

type Credentials struct {
	URLs     []string
	Username string
	Password string
}

type grant struct {
	credentials Credentials
	pair        *pair
	host        bool
	allocations int
	bytes       bucket
	packets     bucket
}

type pair struct {
	active  bool
	expires time.Time
	users   [2]string
}

type Server struct {
	mu             sync.Mutex
	config         Config
	ip             net.IP
	grants         map[string]*grant
	addresses      map[string]*packetConn
	localAddresses map[string]*packetConn
	server         *turn.Server
	bytes          bucket
	udpAddress     net.Addr
}

func New(config Config) (*Server, error) {
	ip := net.ParseIP(config.PublicIP)
	if config.UDPListen != "" && (ip == nil || ip.To4() == nil || len(config.URLs) == 0) {
		return nil, errors.New("TURN requires an IPv4 relay address, listener and advertised URLs")
	}
	if config.BytesPerSecond <= 0 {
		config.BytesPerSecond = 512 * 1024
	}
	if config.MaxPairs <= 0 {
		config.MaxPairs = 128
	}
	if config.TotalBytesPerSecond <= 0 {
		config.TotalBytesPerSecond = 8 * 1024 * 1024
	}
	s := &Server{config: config, ip: ip, grants: make(map[string]*grant), addresses: make(map[string]*packetConn), localAddresses: make(map[string]*packetConn)}
	if config.UDPListen == "" {
		return s, nil
	}
	c := turn.ServerConfig{Realm: realm, AuthHandler: s.authenticate, AllocationLifetime: time.Minute}
	logger := logging.NewDefaultLoggerFactory()
	logger.Writer = io.Discard
	c.LoggerFactory = logger
	var conn net.PacketConn
	if config.UDPListen != "" {
		var err error
		conn, err = net.ListenPacket("udp4", config.UDPListen)
		if err != nil {
			return nil, err
		}
		s.udpAddress = conn.LocalAddr()
		c.PacketConnConfigs = append(c.PacketConnConfigs, turn.PacketConnConfig{PacketConn: &ingress{PacketConn: conn, peers: make(map[string]*bucket)}, RelayAddressGenerator: s, PermissionHandler: s.permission})
	}
	var err error
	s.server, err = turn.NewServer(c)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return s, nil
}

func randomToken() (string, error) {
	var bytes [32]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes[:]), nil
}

func (s *Server) IssuePair() (Credentials, Credentials, func(), func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.grants) >= s.config.MaxPairs*2 {
		return Credentials{}, Credentials{}, nil, nil, errors.New("TURN capacity reached")
	}
	p := &pair{active: true, expires: time.Now().Add(2 * time.Minute)}
	var credentials [2]Credentials
	for i := range credentials {
		username, err := randomToken()
		if err != nil {
			return Credentials{}, Credentials{}, nil, nil, err
		}
		password, err := randomToken()
		if err != nil {
			return Credentials{}, Credentials{}, nil, nil, err
		}
		credentials[i] = Credentials{URLs: append([]string(nil), s.config.URLs...), Username: username, Password: password}
		p.users[i] = username
	}
	for i, c := range credentials {
		s.grants[c.Username] = &grant{credentials: c, pair: p, host: i == 0}
	}
	renew := func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if p.active {
			p.expires = time.Now().Add(2 * time.Minute)
		}
	}
	revoke := func() {
		s.mu.Lock()
		p.active = false
		for _, user := range p.users {
			delete(s.grants, user)
		}
		var conns []*packetConn
		for _, conn := range s.addresses {
			if conn.grant.pair == p {
				conns = append(conns, conn)
			}
		}
		s.mu.Unlock()
		for _, conn := range conns {
			conn.Close()
		}
	}
	return credentials[0], credentials[1], renew, revoke, nil
}

func (s *Server) authenticate(a *turn.RequestAttributes) (string, []byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.grants[a.Username]
	if a.Realm != realm || g == nil || !g.pair.active || time.Now().After(g.pair.expires) {
		return "", nil, false
	}
	return a.Username, turn.GenerateAuthKey(a.Username, realm, g.credentials.Password), true
}

func (s *Server) permission(_ net.Addr, ip net.IP) bool { return s.ip.Equal(ip) }
func (s *Server) Allow(username string, size int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.grants[username]
	return g != nil && g.pair.active && time.Now().Before(g.pair.expires) && s.allow(g, size)
}

func (s *Server) allow(g *grant, size int) bool {
	now := time.Now()
	return size > 0 && size <= 1464 && g.packets.take(now, 2000, 1) && g.bytes.take(now, float64(s.config.BytesPerSecond), float64(size)) && s.bytes.take(now, float64(s.config.TotalBytesPerSecond), float64(size))
}
func (s *Server) Validate() error { return nil }

func (s *Server) AllocatePacketConn(c turn.AllocateListenerConfig) (net.PacketConn, net.Addr, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.grants[c.UserID]
	if c.Network != "udp4" || c.RequestedPort != 0 || g == nil || !g.pair.active || time.Now().After(g.pair.expires) || g.allocations >= 4 {
		return nil, nil, errors.New("unauthorized TURN allocation")
	}
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	address := &net.UDPAddr{IP: s.ip, Port: conn.LocalAddr().(*net.UDPAddr).Port}
	p := &packetConn{PacketConn: conn, server: s, grant: g, address: address.String()}
	s.addresses[p.address] = p
	s.localAddresses[conn.LocalAddr().String()] = p
	g.allocations++
	return p, address, nil
}

func (s *Server) AllocateListener(turn.AllocateListenerConfig) (net.Listener, net.Addr, error) {
	return nil, nil, errors.New("TCP relay allocations are disabled")
}

func (s *Server) AllocateConn(turn.AllocateConnConfig) (net.Conn, error) {
	return nil, errors.New("TCP relay connections are disabled")
}

func (s *Server) Close() error {
	if s.server == nil {
		return nil
	}
	return s.server.Close()
}

type packetConn struct {
	net.PacketConn
	server  *Server
	grant   *grant
	address string
	once    sync.Once
}

func (p *packetConn) allowed(address net.Addr, size int) bool {
	s := p.server
	s.mu.Lock()
	defer s.mu.Unlock()
	other := s.addresses[address.String()]
	now := time.Now()
	if !p.grant.pair.active || now.After(p.grant.pair.expires) || other == nil || other.grant.pair != p.grant.pair || other.grant.host == p.grant.host {
		return false
	}
	return s.allow(p.grant, size)
}

func (p *packetConn) WriteTo(data []byte, address net.Addr) (int, error) {
	if !p.allowed(address, len(data)) {
		return len(data), nil
	}
	p.server.mu.Lock()
	other := p.server.addresses[address.String()]
	if other == nil {
		p.server.mu.Unlock()
		return len(data), nil
	}
	local := other.PacketConn.LocalAddr()
	p.server.mu.Unlock()
	return p.PacketConn.WriteTo(data, local)
}

func (p *packetConn) ReadFrom(data []byte) (int, net.Addr, error) {
	for {
		n, address, err := p.PacketConn.ReadFrom(data)
		if err != nil {
			return n, address, err
		}
		p.server.mu.Lock()
		other := p.server.localAddresses[address.String()]
		var published net.Addr
		if other != nil {
			published = &net.UDPAddr{IP: p.server.ip, Port: other.PacketConn.LocalAddr().(*net.UDPAddr).Port}
		}
		p.server.mu.Unlock()
		if published != nil && p.allowed(published, n) {
			return n, published, nil
		}
	}
}

func (p *packetConn) Close() error {
	var err error
	p.once.Do(func() {
		p.server.mu.Lock()
		delete(p.server.addresses, p.address)
		delete(p.server.localAddresses, p.PacketConn.LocalAddr().String())
		p.grant.allocations--
		p.server.mu.Unlock()
		err = p.PacketConn.Close()
	})
	return err
}
