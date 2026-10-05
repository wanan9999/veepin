package l2tp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/wanan9999/veepin/dataplane"
	"github.com/wanan9999/veepin/internal/ikev1"
	"github.com/wanan9999/veepin/internal/ikev2/esp"
	"github.com/wanan9999/veepin/internal/mschap"
	"github.com/wanan9999/veepin/internal/ppp"
	"github.com/wanan9999/veepin/internal/vlog"
)

// ServerConfig configures the L2TP/IPsec server engine.
type ServerConfig struct {
	PacketDeviceFactory func(string, net.IP, uint16) (io.ReadWriteCloser, error)

	PSK   []byte
	Users map[string]string // username -> password for MS-CHAPv2
	// PublicIP is the server's outer address as clients reach it. It becomes the
	// IKE identity and the phase-2 traffic selector, so a server listening on the
	// wildcard — where the socket cannot name it — must be told.
	PublicIP net.IP
	Pool     *dataplane.AddrPool // inner address pool
	Gateway  net.IP              // server's inner address (pool's first host)
	DNS      []net.IP
	// Shape is the per-flow downstream shaping budget in bytes; 0 disables it.
	// See dataplane/shape.go. MTU is the inner size shaping pads towards, and
	// defaults to the PPP MRU this package negotiates.
	Shape  int
	MTU    int
	Logger *vlog.Logger
}

// defaultShapeMTU is the inner size shaping pads towards when ServerConfig.MTU
// is unset. RFC 1661 5.1 caps PPP padding at the MRU, and the MRU this package
// negotiates is ppp.DefaultMRU, so that is both the correct ceiling and the size
// a genuine full packet would have been.
const defaultShapeMTU = ppp.DefaultMRU

// Server is a running L2TP/IPsec responder. It binds two sockets — the IKE port
// for Main Mode and the NAT-T port for everything after the float — and gives
// each client a per-peer IKEv1 responder, ESP transport SA, L2TP LNS tunnel and
// PPP session. A single TUN is shared, with inbound IP routed to the owning peer
// by inner destination address.
//
// Peers are keyed by initiator cookie for IKE and by inbound SPI for ESP, not by
// remote address: NAT-T moves a session to a different port mid-exchange, and a
// NAT rebinding can move it again afterwards, so the address is tracked as
// mutable state rather than used as identity.
type Server struct {
	cfg      ServerConfig
	ikeConn  *dataplane.PacketConn // port 500: Main Mode
	nattConn *dataplane.PacketConn // port 4500: floated IKE + UDP-encapsulated ESP
	tun      tunIO
	pool     *dataplane.AddrPool
	gateway  net.IP
	logger   *vlog.Logger
	gate     *dataplane.Gate
	// shaper pads outbound PPP frames so the ESP packet carrying them says less
	// about the inner packet (dataplane/shape.go); nil disables shaping.
	//
	// One Shaper is safe to share across peers because tunLoop is the single
	// goroutine that consults it — the same single-owner rule the pump relies on.
	shaper *dataplane.Shaper

	mu       sync.Mutex
	byCookie map[[8]byte]*serverPeer // initiator cookie -> peer, for IKE
	bySPI    map[uint32]*serverPeer  // our inbound ESP SPI -> peer
	byIP     map[uint32]*serverPeer  // inner IP -> peer, for TUN egress

	serveErr  chan error
	done      chan struct{}
	closeOnce sync.Once
}

// NewServer builds a server over the two bound UDP sockets and a TUN.
func NewServer(rawIKE, rawNATT *net.UDPConn, tun tunIO, cfg ServerConfig) *Server {
	ikeConn := dataplane.NewPacketConn(rawIKE)
	nattConn := dataplane.NewPacketConn(rawNATT)
	logger := cfg.Logger
	var shaper *dataplane.Shaper
	if cfg.Shape > 0 {
		shaper = dataplane.NewShaper(dataplane.ShapeConfig{Bytes: cfg.Shape})
		logger.Printf("l2tp: downstream shaping on, %d bytes per flow", cfg.Shape)
	}
	return &Server{
		cfg:      cfg,
		shaper:   shaper,
		ikeConn:  ikeConn,
		nattConn: nattConn,
		tun:      tun,
		pool:     cfg.Pool,
		gateway:  cfg.Gateway,
		logger:   logger,
		gate:     dataplane.NewGate(dataplane.AdmissionConfig{}),
		byCookie: map[[8]byte]*serverPeer{},
		bySPI:    map[uint32]*serverPeer{},
		byIP:     map[uint32]*serverPeer{},
		done:     make(chan struct{}),
		serveErr: make(chan error, 3),
	}
}

// mtu is the inner size shaping pads towards.
func (s *Server) mtu() int {
	if s.cfg.MTU <= 0 {
		return defaultShapeMTU
	}
	return s.cfg.MTU
}

// Serve runs the data path until Close. It blocks.
func (s *Server) Serve() error {
	if s.cfg.PacketDeviceFactory == nil {
		go s.tunLoop()
	}
	go s.recvIKE()
	go s.recvNATT()
	select {
	case <-s.done:
		return nil
	case err := <-s.serveErr:
		_ = s.Close()
		return err
	}
}

// Close stops the server.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		s.ikeConn.Close()
		s.nattConn.Close()
		s.mu.Lock()
		peers := make([]*serverPeer, 0, len(s.byCookie))
		for _, p := range s.byCookie {
			peers = append(peers, p)
		}
		s.mu.Unlock()
		for _, p := range peers {
			s.removePeer(p, net.ErrClosed)
		}
	})
	return nil
}

// recvIKE reads the plain IKE port. Every datagram here is a bare Main Mode
// message. Some clients (TunnelForge v0.7.4) finish Main Mode here and only
// move to NAT-T for Quick Mode; others float before MM5.
func (s *Server) recvIKE() {
	buf := make([]byte, 65535)
	for {
		n, addr, err := s.ikeConn.ReadFromUDP(buf)
		if err != nil {
			s.readFailed("recvIKE", err)
			return
		}
		s.dispatchIKE(append([]byte(nil), buf[:n]...), addr, false)
	}
}

// recvNATT reads the NAT-T port, where IKE and ESP share a socket and the
// non-ESP marker tells them apart. Reads are batched
// (dataplane.PacketConn.ReadBatch): one recvmmsg drains up to readBatch
// datagrams under load and blocks like a plain read when idle. Unlike the flat
// ESP protocols, every datagram is still copied out: the L2TP engine behind
// handleESP parses control AVPs whose handling may alias the packet beyond
// this loop, so only the syscalls are batched, not the buffer ownership.
func (s *Server) recvNATT() {
	const readBatch = 16
	bufs := make([][]byte, readBatch)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	sizes := make([]int, readBatch)
	froms := make([]*net.UDPAddr, readBatch)
	for {
		n, err := s.nattConn.ReadBatch(bufs, sizes, froms)
		for i := range n {
			pkt, addr := append([]byte(nil), bufs[i][:sizes[i]]...), froms[i]
			if msg, ok := isIKE(pkt); ok {
				s.dispatchIKE(msg, addr, true)
				continue
			}
			if p := s.peerBySPI(pkt); p != nil {
				p.handleESP(pkt, addr)
			}
		}
		if err != nil {
			s.readFailed("recvNATT", err)
			return
		}
	}
}

// dispatchIKE routes an IKE message to the peer owning its initiator cookie,
// creating a responder for a cookie not seen before.
func (s *Server) dispatchIKE(msg []byte, addr *net.UDPAddr, natt bool) {
	cookie, ok := ikev1.InitiatorCookie(msg)
	if !ok {
		return
	}
	if !ikev1.IsInitialMainMode(msg) {
		s.mu.Lock()
		known := s.byCookie[cookie] != nil
		s.mu.Unlock()
		if !known {
			return
		}
	}
	p := s.peerFor(cookie, addr, natt)
	if p == nil {
		// Refused by admission control; already logged.
		return
	}
	p.mu.Lock()
	oldTransport := p.ikeNATT && !natt
	p.mu.Unlock()
	if oldTransport {
		return // RFC 3947 section 4: do not revive the pre-float exchange.
	}
	p.ike.HandleInboundAuthenticated(msg, func() { p.noteIKEAddr(addr, natt) })
}

// peerFor returns the peer owning an initiator cookie, creating an IKE responder
// for a newly seen one. It returns nil when admission control refuses.
//
// This is where an unauthenticated peer makes the server allocate: the cookie is
// chosen by the initiator, so without a bound, traffic with a varying cookie
// creates one IKE responder -- with its Diffie-Hellman state -- per message.
func (s *Server) peerFor(cookie [8]byte, addr *net.UDPAddr, natt bool) *serverPeer {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.done:
		return nil
	default:
	}
	if p, ok := s.byCookie[cookie]; ok {
		return p
	}

	if r := s.gate.Admit(addr); r != dataplane.Admitted {
		s.logger.Warnf("l2tp: refusing new peer %s: %v", addr, r)
		return nil
	}

	// A fresh IKE SA from the same authenticated transport may renew the
	// control channel without tearing down PPP. The IKE layer verifies identity.
	for _, existing := range s.byCookie {
		existing.mu.Lock()
		same := natt && existing.ready && !existing.closed && existing.nattAddr.Port == addr.Port && existing.nattAddr.IP.Equal(addr.IP)
		existing.mu.Unlock()
		if same {
			s.gate.Done()
			count := 0
			for _, owner := range s.byCookie {
				if owner == existing {
					count++
				}
			}
			if count >= 10 {
				return nil
			}
			return existing
		}
	}
	p := &serverPeer{
		srv:    s,
		cookie: cookie,
		done:   make(chan struct{}),
		addr:   addr,
		// Pin unauthenticated replies to this initial endpoint. No guessed
		// destination port is used while waiting for an authenticated float.
		nattAddr: addr,
		ikeNATT:  natt,
	}
	p.ike = ikev1.NewSession(ikev1.Config{
		Role:           ikev1.Responder,
		ManageLifetime: true,
		PSK:            s.cfg.PSK,
		LocalIP:        s.publicIP(),
		PeerIP:         addr.IP,
		LocalPort:      defaultIKEPort,
		PeerPort:       uint16(addr.Port),
		Send:           p.sendIKE,
		Handler:        p,
		Logger:         s.logger,
	})
	s.byCookie[cookie] = p
	go p.monitor()
	s.logger.Printf("l2tp: new peer %s (cookie %x)", addr, cookie)
	return p
}

// publicIP is the address the server presents as its IKE identity and phase-2
// traffic selector: the configured one, else the IKE socket's bound address when
// it is concrete. Listening on the wildcard without configuring one leaves it
// nil, which yields an empty ID — workable only with a peer matching on %any.
func (s *Server) publicIP() net.IP {
	if s.cfg.PublicIP != nil {
		return s.cfg.PublicIP
	}
	if la, ok := s.ikeConn.LocalAddr().(*net.UDPAddr); ok && !la.IP.IsUnspecified() {
		return la.IP
	}
	return nil
}

// peerBySPI finds the peer an inbound ESP packet belongs to by its SPI.
func (s *Server) peerBySPI(pkt []byte) *serverPeer {
	if len(pkt) < 4 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bySPI[binary.BigEndian.Uint32(pkt[:4])]
}

func (s *Server) mapSPI(spi uint32, p *serverPeer) {
	s.mu.Lock()
	if s.byCookie[p.cookie] == p {
		s.bySPI[spi] = p
	}
	s.mu.Unlock()
}

func (s *Server) peerByIP(ip net.IP) *serverPeer {
	v4 := ip.To4()
	if v4 == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byIP[binary.BigEndian.Uint32(v4)]
}

func (s *Server) mapIP(ip net.IP, p *serverPeer) {
	if v4 := ip.To4(); v4 != nil {
		s.mu.Lock()
		if s.byCookie[p.cookie] == p {
			s.byIP[binary.BigEndian.Uint32(v4)] = p
		}
		s.mu.Unlock()
	}
}

// removePeer drops a peer from every index and releases its resources. It is
// idempotent: the tunnel's Closed callback re-enters it during teardown, and the
// map-presence check makes the second call a no-op.
func (s *Server) removePeer(p *serverPeer, err error) {
	s.mu.Lock()
	if s.byCookie[p.cookie] != p {
		s.mu.Unlock()
		return
	}
	for cookie, owner := range s.byCookie {
		if owner == p {
			delete(s.byCookie, cookie)
		}
	}
	p.releaseAdmission()
	for spi, owner := range s.bySPI {
		if owner == p {
			delete(s.bySPI, spi)
		}
	}
	p.mu.Lock()
	address, addr := p.innerIP, p.addr
	t, ps, device := p.tunnel, p.ppp, p.device
	p.closed, p.ready, p.device = true, false, nil
	if p.drainTimer != nil {
		p.drainTimer.Stop()
		p.drainTimer = nil
	}
	if p.done != nil {
		close(p.done)
	}
	if v4 := address.To4(); v4 != nil {
		delete(s.byIP, binary.BigEndian.Uint32(v4))
	}
	p.mu.Unlock()
	s.mu.Unlock()
	if address != nil {
		s.pool.Release(address)
	}
	if ps != nil {
		go ps.Close()
	} // A PPP callback may already hold its lock.
	if p.ike != nil {
		go p.ike.Close()
	} // IKE callbacks may own the session lock.
	if device != nil {
		_ = device.Close()
	}
	if t != nil {
		t.Abort()
	}
	s.logger.Printf("l2tp: peer %s gone: %v", addr, err)
}

func (s *Server) auth(username string) (string, bool) {
	pw, ok := s.cfg.Users[username]
	return pw, ok
}

// tunLoop routes TUN egress to the peer owning the inner destination address.
func (s *Server) tunLoop() {
	buf := make([]byte, 65535)
	for {
		n, err := s.tun.Read(buf)
		if err != nil {
			s.readFailed("tunLoop", err)
			return
		}
		dst := ipv4Dst(buf[:n])
		if dst == nil {
			continue
		}
		p := s.peerByIP(dst)
		if p == nil {
			continue
		}
		p.mu.Lock()
		t := p.tunnel
		mtu := int(p.mtu)
		ready := p.ready && !p.closed && !p.draining
		p.mu.Unlock()
		if t != nil && ready {
			// A non-zero target pads the PPP Information field out to it, so the
			// ESP packet this becomes is the same size whatever the inner packet
			// was. RFC 1661 5.1 sanctions the padding; ppp.IsIP trims it back.
			pkt := append([]byte(nil), buf[:n]...)
			if err := sendIPv4(t, pkt, mtu, s.shaper.Target(pkt, min(mtu, s.mtu())), func(reply []byte) { _, _ = s.tun.Write(reply) }); err != nil {
				s.removePeer(p, err)
			}
		}
	}
}

// serverPeer is one client's state on the server.
type serverPeer struct {
	mtu        uint16
	draining   bool
	drainTimer *time.Timer
	transport  ikev1.TransportPolicy
	peerUDP    uint16
	srv        *Server
	cookie     [8]byte
	ike        *ikev1.Session

	mu            sync.Mutex
	addr          *net.UDPAddr // where Main Mode came from
	nattAddr      *net.UDPAddr // where floated IKE and ESP go
	ikeNATT       bool         // peer has actually sent IKE on the NAT-T socket
	sa            *esp.SA
	sas           map[uint32]timedSA
	inSPI         uint32
	tunnel        *Tunnel
	ppp           *ppp.ServerSession
	innerIP       net.IP
	username      string
	ready         bool
	closed        bool
	device        io.ReadWriteCloser
	done          chan struct{}
	admissionOnce sync.Once
}

// noteIKEAddr commits a cryptographically verified IKE packet's endpoint.
// Initial unauthenticated replies use the endpoint fixed at peer creation.
func (p *serverPeer) noteIKEAddr(addr *net.UDPAddr, natt bool) {
	p.mu.Lock()
	if p.ikeNATT && !natt {
		p.mu.Unlock()
		return
	}
	previous := p.addr
	if p.ikeNATT {
		previous = p.nattAddr
	}
	changed := previous.Port != addr.Port || !previous.IP.Equal(addr.IP) || natt != p.ikeNATT
	if natt {
		p.nattAddr = addr
		p.ikeNATT = true
	} else {
		p.addr = addr
	}
	p.mu.Unlock()
	if changed {
		p.srv.logger.Printf("l2tp: authenticated IKE endpoint %s -> %s (NAT-T=%v)", previous, addr, natt)
	}
}

// noteAddr commits the source of ESP only after integrity and replay checks.
func (p *serverPeer) noteAddr(addr *net.UDPAddr) {
	p.mu.Lock()
	previous := p.nattAddr
	changed := previous.Port != addr.Port || !previous.IP.Equal(addr.IP)
	if changed {
		p.nattAddr = addr
	}
	p.mu.Unlock()
	if changed {
		p.srv.logger.Printf("l2tp: authenticated ESP endpoint %s -> %s", previous, addr)
	}
}

func (p *serverPeer) sendIKE(msg []byte, _ bool) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return net.ErrClosed
	}
	ike, nat := p.addr, p.nattAddr
	natt := p.ikeNATT
	p.mu.Unlock()
	// Negotiating NAT-T does not reveal the client's translated UDP/4500
	// endpoint. Reply on the transport it actually used until it floats.
	// TunnelForge finishes MM5/MM6 on UDP/500; guessing port 4500 loses MM6
	// behind NAT. A peer starting on 4500 also needs its MM2 sent there.
	if natt {
		_, err := p.srv.nattConn.WriteToUDP(markIKE(msg), nat)
		return err
	}
	_, err := p.srv.ikeConn.WriteToUDP(msg, ike)
	return err
}

func (p *serverPeer) handleESP(pkt []byte, addr *net.UDPAddr) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	sa, tun := p.sa, p.tunnel
	policy := p.transport
	if p.sas != nil {
		if len(pkt) < 4 {
			p.mu.Unlock()
			return
		}
		entry, ok := p.sas[binary.BigEndian.Uint32(pkt)]
		if !ok || !time.Now().Before(entry.expires) {
			p.mu.Unlock()
			return
		}
		sa = entry.sa
		policy = entry.transport
	}
	active := sa == p.sa
	p.mu.Unlock()
	if sa == nil || tun == nil {
		return
	}
	inner, nh, err := sa.Decapsulate(pkt)
	if err != nil || nh != ipProtoUDP {
		return
	}
	if active && sa.NeedsRekey() {
		p.ike.RequestRekey()
	}
	if l2, ok := unwrapUDP(inner, policy); ok {
		p.mu.Lock()
		source := binary.BigEndian.Uint16(inner)
		if p.peerUDP != 0 && p.peerUDP != source {
			p.mu.Unlock()
			return
		}
		p.peerUDP = source
		p.mu.Unlock()
		p.noteAddr(addr)
		tun.HandleInbound(l2)
	}
}

// --- ikev1.Handler ---

func (p *serverPeer) Established(r ikev1.Result) {
	p.releaseAdmission()
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.sa = newESPSA(r)
	p.transport = r.Transport
	p.inSPI = r.InSPI
	if p.sas == nil {
		p.sas = make(map[uint32]timedSA)
	}
	now := time.Now()
	p.sas[r.InSPI] = timedSA{sa: p.sa, expires: now.Add(r.Lifetime), transport: r.Transport}
	if p.tunnel == nil {
		p.tunnel = NewTunnel(RoleLNS, p.espSend, p)
	}
	p.mu.Unlock()
	p.srv.mapSPI(r.InSPI, p)
	p.srv.logger.Printf("l2tp: IPsec SA established with %s (spi in=%#x out=%#x rekey=%v)", p.addr, r.InSPI, r.OutSPI, r.Rekey)
}

func (p *serverPeer) Failed(err error) { p.srv.removePeer(p, err) }

func (p *serverPeer) espSend(l2tp []byte) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return net.ErrClosed
	}
	sa, to := p.sa, p.nattAddr
	port := p.peerUDP
	if port == 0 {
		port = p.transport.PeerPort
	}
	if port == 0 {
		port = l2tpUDPPort
	}
	p.mu.Unlock()
	if sa == nil {
		return errors.New("l2tp: ESP SA not ready")
	}
	if sa.NeedsRekey() {
		p.ike.RequestRekey()
	}
	pkt, err := sa.Encapsulate(wrapUDP(l2tp, l2tpUDPPort, port), ipProtoUDP)
	if err != nil {
		return err
	}
	_, err = p.srv.nattConn.WriteToUDP(pkt, to)
	return err
}

// --- l2tp.Handler ---

func (p *serverPeer) SessionUp() {
	ip, err := p.srv.pool.Allocate()
	if err != nil {
		p.srv.removePeer(p, err)
		return
	}
	p.mu.Lock()
	if p.closed || p.ppp != nil {
		p.mu.Unlock()
		p.srv.pool.Release(ip)
		return
	}
	p.innerIP = ip
	p.ppp = ppp.NewServer(ppp.ServerConfig{
		ClientIP: ip,
		ServerIP: p.srv.gateway,
		DNS:      p.srv.cfg.DNS,
		Auth:     p.srv.auth,
	}, p.tunnel, serverPPP{p})
	ps := p.ppp
	p.mu.Unlock()
	p.srv.mapIP(ip, p)
	p.srv.logger.Printf("l2tp: L2TP session up for %s, assigning %s", p.addr, ip)
	ps.Start()
}

func (p *serverPeer) DataFrame(frame []byte) {
	if ip, ok := ppp.IsIP(frame); ok {
		p.mu.Lock()
		ready, device := p.ready && !p.closed && !p.draining, p.device
		address := append(net.IP(nil), p.innerIP...)
		p.mu.Unlock()
		// The authenticated peer may only send from its assigned IPv4 address.
		// No data is admitted before both PPP authentication and IPCP complete.
		if !ready || len(ip) < 20 || ip[0]>>4 != 4 || !net.IP(ip[12:16]).Equal(address) {
			return
		}
		if device != nil {
			_, _ = device.Write(ip)
		} else if p.srv.tun != nil {
			_, _ = p.srv.tun.Write(ip)
		}
		return
	}
	p.mu.Lock()
	ps := p.ppp
	p.mu.Unlock()
	if ps != nil {
		ps.Receive(frame)
	}
}

func (p *serverPeer) Closed(err error) { p.beginDrain(err) }

// serverPPP adapts serverPeer to ppp.ServerHandler.
type serverPPP struct{ p *serverPeer }

func (h serverPPP) Authenticated(u, pw string, nt [mschap.NTResponseLen]byte) {
	h.p.mu.Lock()
	h.p.username = u
	h.p.mu.Unlock()
}
func (h serverPPP) NetworkUp(mtu uint16) {
	p := h.p
	p.mu.Lock()
	user, address := p.username, append(net.IP(nil), p.innerIP...)
	if p.closed || p.draining || p.ready || user == "" {
		p.mu.Unlock()
		return
	}
	p.mu.Unlock()
	var device io.ReadWriteCloser
	if factory := p.srv.cfg.PacketDeviceFactory; factory != nil {
		var err error
		device, err = factory(user, address, mtu)
		if err != nil || device == nil {
			p.srv.removePeer(p, errors.New("l2tp: session device unavailable"))
			return
		}
	}
	p.mu.Lock()
	if p.closed || p.draining {
		p.mu.Unlock()
		if device != nil {
			device.Close()
		}
		return
	}
	p.device, p.ready, p.mtu = device, true, mtu
	p.mu.Unlock()
	if device != nil {
		go p.deviceLoop(device)
	}
	h.p.srv.logger.Printf("l2tp: PPP up for %s", h.p.addr)
}
func (h serverPPP) Closed(err error) { h.p.beginDrain(err) }

// ipv4Dst extracts the destination address from an IPv4 packet.
func ipv4Dst(pkt []byte) net.IP {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return nil
	}
	return net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19])
}

// deviceLoop belongs to one PPP session; an address reused after disconnect can
// never inherit queued traffic or connections from the previous session.
func (p *serverPeer) deviceLoop(device io.ReadWriteCloser) {
	buf := make([]byte, 65535)
	for {
		n, err := device.Read(buf)
		if err != nil {
			p.mu.Lock()
			current := p.device == device
			p.mu.Unlock()
			if current {
				p.srv.removePeer(p, err)
			}
			return
		}
		p.mu.Lock()
		ready, tunnel, address := p.ready && !p.closed && p.device == device, p.tunnel, append(net.IP(nil), p.innerIP...)
		mtu := p.mtu
		p.mu.Unlock()
		if !ready {
			return
		}
		if tunnel == nil || !ipv4Dst(buf[:n]).Equal(address) {
			continue
		}
		// Session-local shaping avoids sharing mutable flow state across goroutines.
		if err := sendIPv4(tunnel, buf[:n], int(mtu), 0, func(reply []byte) { _, _ = device.Write(reply) }); err != nil {
			p.srv.removePeer(p, err)
			return
		}
	}
}

func (s *Server) KickUserSessions(user string) int {
	s.mu.Lock()
	var peers []*serverPeer
	seen := make(map[*serverPeer]bool)
	for _, p := range s.byCookie {
		if seen[p] {
			continue
		}
		seen[p] = true
		p.mu.Lock()
		match := p.username == user
		p.mu.Unlock()
		if match {
			peers = append(peers, p)
		}
	}
	s.mu.Unlock()
	for _, p := range peers {
		p.beginDrain(errors.New("l2tp: user disconnected"))
	}
	return len(peers)
}

// readFailed distinguishes administrative closure from a dead listener. The
// owner must see the latter even when the other UDP socket still works.
func (s *Server) readFailed(op string, err error) {
	select {
	case <-s.done:
		return
	default:
	}
	select {
	case s.serveErr <- fmt.Errorf("l2tp: %s: %w", op, err):
	default:
	}
}
func (p *serverPeer) releaseAdmission() {
	p.admissionOnce.Do(func() {
		if p.srv.gate != nil {
			p.srv.gate.Done()
		}
	})
}

// A HELLO tests both ESP and L2TP without requiring a vendor DPD extension.
// The absolute setup deadline also covers a silent PPP authentication peer.
func (p *serverPeer) monitor() { p.monitorWithTimeouts(time.Minute, 30*time.Second, 0) }

func (p *serverPeer) monitorWithTimeouts(setupTimeout, interval, probeTimeout time.Duration) {
	setup := time.NewTimer(setupTimeout)
	defer setup.Stop()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-p.done:
			return
		case <-setup.C:
			p.mu.Lock()
			ready := p.ready || p.draining
			p.mu.Unlock()
			if !ready {
				p.srv.removePeer(p, errors.New("l2tp: setup timed out"))
				return
			}
		case <-ticker.C:
			p.pruneSAs()
			p.mu.Lock()
			tunnel, ready := p.tunnel, p.ready
			p.mu.Unlock()
			if !ready || tunnel == nil {
				continue
			}
			// HELLO is a reliable control message. Let its retransmission budget
			// decide peer failure instead of racing it with a shorter idle timeout.
			// Explicit short deadlines remain useful for isolated lifecycle tests.
			ctx, cancel := context.WithCancel(context.Background())
			if probeTimeout > 0 {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), probeTimeout)
			}
			err := tunnel.SendHello(ctx)
			cancel()
			if err != nil {
				p.mu.Lock()
				draining := p.draining
				p.mu.Unlock()
				if draining {
					return
				}
				p.srv.removePeer(p, fmt.Errorf("l2tp: liveness: %w", err))
				return
			}
		}
	}
}

type timedSA struct {
	transport ikev1.TransportPolicy
	sa        *esp.SA
	expires   time.Time
}

// A Delete names the peer's inbound SPI, which is our outbound SPI.
func (p *serverPeer) DeleteESP(spi uint32) {
	p.srv.mu.Lock()
	p.mu.Lock()
	current := p.sa != nil && p.sa.SPIOut == spi
	for in, entry := range p.sas {
		if entry.sa.SPIOut == spi {
			delete(p.sas, in)
			if p.srv.bySPI[in] == p {
				delete(p.srv.bySPI, in)
			}
		}
	}
	p.mu.Unlock()
	p.srv.mu.Unlock()
	if current {
		p.srv.removePeer(p, errors.New("l2tp: peer deleted active ESP SA"))
	}
}

// Deadlines reject packets immediately; this also releases expired index entries.
func (p *serverPeer) pruneSAs() {
	p.srv.mu.Lock()
	defer p.srv.mu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	for spi, entry := range p.sas {
		if !time.Now().Before(entry.expires) {
			delete(p.sas, spi)
			if p.srv.bySPI[spi] == p {
				delete(p.srv.bySPI, spi)
			}
		}
	}
}

func (p *serverPeer) RegisterIKE(cookie [8]byte) {
	p.srv.mu.Lock()
	defer p.srv.mu.Unlock()
	if p.srv.byCookie[p.cookie] == p {
		p.srv.byCookie[cookie] = p
	}
}
func (p *serverPeer) UnregisterIKE(cookie [8]byte) {
	p.srv.mu.Lock()
	defer p.srv.mu.Unlock()
	// The primary cookie is the owner's registry key until the PPP session ends.
	if cookie != p.cookie && p.srv.byCookie[cookie] == p {
		delete(p.srv.byCookie, cookie)
	}
}

// NetworkDown invalidates the old network lifetime before LCP renegotiation.
func (h serverPPP) NetworkDown() {
	p := h.p
	p.mu.Lock()
	device := p.device
	p.device = nil
	p.ready = false
	p.mu.Unlock()
	if device != nil {
		_ = device.Close()
	}
}

// RFC 2661 section 5.7 retains control state for a full retransmission cycle.
// Business traffic stops immediately; only encrypted close acknowledgements
// and retransmissions use the retained ESP mapping.
func (p *serverPeer) beginDrain(err error) {
	p.mu.Lock()
	if p.closed || p.draining {
		p.mu.Unlock()
		return
	}
	p.draining = true
	p.ready = false
	device, ps, tunnel := p.device, p.ppp, p.tunnel
	p.device = nil
	p.drainTimer = time.AfterFunc(31*time.Second, func() { p.srv.removePeer(p, err) })
	p.mu.Unlock()
	if device != nil {
		_ = device.Close()
	}
	if ps != nil {
		go ps.Close()
	}
	if tunnel != nil {
		tunnel.Close()
	}
}
