package ppp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"github.com/wanan9999/veepin/internal/mschap"
)

// Authenticator returns the password for a username, or ok=false if unknown. The
// server session uses it to verify a client's MS-CHAPv2 response.
type Authenticator func(username string) (password string, ok bool)

// ServerHandler receives the server session's lifecycle events. The SSTP layer
// implements it: Authenticated hands back the credentials the crypto binding
// needs, NetworkUp signals the tunnel can carry IP, and Closed reports teardown.
type ServerHandler interface {
	Authenticated(username, password string, ntResponse [mschap.NTResponseLen]byte)
	NetworkDown()
	NetworkUp(mtu uint16)
	Closed(err error)
}

// ServerConfig is the addressing a server assigns a client over IPCP.
type ServerConfig struct {
	ClientIP net.IP // address assigned to the client
	ServerIP net.IP // server's own inner address (its IPCP request)
	DNS      []net.IP
	Auth     Authenticator
	// NoAuth runs the link without PPP-level authentication: LCP omits the
	// Auth-Protocol option and the link goes straight to IPCP with no CHAP
	// challenge. It is for carriers that authenticate above PPP -- Fortinet, whose
	// SVPNCOOKIE has already done so. With it unset (the SSTP default) MS-CHAPv2
	// is required and cfg.Auth verifies the client.
	NoAuth bool
}

// ServerSession is the authenticator side of a PPP link: it opens LCP requiring
// MS-CHAPv2, challenges the client and verifies its response, then assigns the
// client an address over IPCP. Like the client Session it assumes a reliable,
// in-order transport and drives purely from received packets.
type ServerSession struct {
	peerIPCPRequest []byte
	lcpNoMRU        bool
	localMRU        uint16
	cfg             ServerConfig
	tr              Transport
	h               ServerHandler

	mu    sync.Mutex
	phase phase
	magic uint32
	reqID byte

	lcpReqID                    byte
	lcpConfigReq                []byte // the outstanding request, for retransmission
	lcpLocalOpen, lcpRemoteOpen bool
	lcpNoMagic                  bool // set if a NoAuth client rejected Magic-Number

	authID                                 byte
	authRequest, authResponse, authSuccess []byte
	authRestart                            restartTimer
	peerMRU                                uint16
	ipcpNoAddress                          bool
	configChanges                          int
	peerLCPRequest                         []byte
	authChallenge                          [mschap.ChallengeLen]byte
	username                               string
	password                               string
	ntResponse                             [mschap.NTResponseLen]byte

	ipcpReqID                     byte
	ipcpConfigReq                 []byte // the outstanding request, for retransmission
	ipcpLocalOpen, ipcpRemoteOpen bool

	lcpRestart, ipcpRestart restartTimer
}

// NewServer builds a PPP server session that authenticates clients via cfg.Auth,
// assigns cfg.ClientIP, sends frames through tr, and reports events to h.
func NewServer(cfg ServerConfig, tr Transport, h ServerHandler) *ServerSession {
	var magic [4]byte
	_, _ = rand.Read(magic[:])
	return &ServerSession{
		cfg:      cfg,
		tr:       tr,
		h:        h,
		magic:    binary.BigEndian.Uint32(magic[:]),
		peerMRU:  1500,
		localMRU: DefaultMRU,
	}
}

// Start opens the link by sending the server's LCP Configure-Request, which
// demands MS-CHAPv2 authentication.
func (s *ServerSession) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != phaseClosed {
		s.sendLCPConfigReq()
	}
}

// Close stops owner-managed teardown without re-entering its callback.
func (s *ServerSession) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.phase = phaseClosed
	s.lcpRestart.stop()
	s.ipcpRestart.stop()
	s.authRestart.stop()
}

// Receive dispatches one inbound PPP frame by protocol.
func (s *ServerSession) Receive(frame []byte) {
	protocol, payload, ok := decodeFrame(frame)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase == phaseClosed {
		return
	}
	switch protocol {
	case ProtocolLCP:
		s.handleLCP(payload)
	case ProtocolCHAP:
		if s.phase >= phaseAuth {
			s.handleCHAP(payload)
		}
	case ProtocolIP:
	// The carrier gates IP on NetworkUp; premature data is discarded.
	case ProtocolIPCP:
		if s.phase >= phaseIPCP {
			s.handleIPCP(payload)
		}
	default:
		if s.phase >= phaseAuth {
			body := append([]byte{byte(protocol >> 8), byte(protocol)}, payload...)
			s.send(ProtocolLCP, cpPacket{Code: 8, ID: s.nextID(), Body: body[:min(len(body), int(s.peerMRU)-4)]}.marshal())
		}
	}
}

func (s *ServerSession) send(protocol uint16, payload []byte) {
	if err := s.tr.SendPPP(encodeFrame(protocol, payload)); err != nil {
		s.failLocked(fmt.Errorf("ppp: send: %w", err))
	}
}

func (s *ServerSession) nextID() byte {
	s.reqID++
	return s.reqID
}

func (s *ServerSession) failLocked(err error) {
	if s.phase == phaseClosed {
		return
	}
	s.phase = phaseClosed
	s.lcpRestart.stop()
	s.ipcpRestart.stop()
	s.authRestart.stop()
	s.h.Closed(err)
}

// withLock runs fn with the session locked, for the Restart timer's callback.
func (s *ServerSession) withLock(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase == phaseClosed {
		return
	}
	fn()
}

// --- LCP ---

func (s *ServerSession) sendLCPConfigReq() {
	var magic [4]byte
	binary.BigEndian.PutUint32(magic[:], s.magic)
	var opts []option
	if !s.lcpNoMRU {
		opts = append(opts, option{Type: optMRU, Value: []byte{byte(s.localMRU >> 8), byte(s.localMRU)}})
	}
	if !s.cfg.NoAuth {
		// The authenticator is the side that requests an Auth-Protocol; omitting it
		// is how the peer is told this link does no PPP-level authentication.
		opts = append(opts, option{Type: optAuthProto, Value: authMSCHAPv2})
	}
	if !s.lcpNoMagic {
		opts = append(opts, option{Type: optMagic, Value: magic[:]})
	}
	s.lcpReqID = s.nextID()
	s.lcpConfigReq = cpPacket{Code: codeConfigureRequest, ID: s.lcpReqID, Body: marshalOptions(opts)}.marshal()
	s.resendLCPConfigReq()
}

// resendLCPConfigReq (re)transmits the outstanding LCP Configure-Request and
// re-arms the Restart timer, reusing the original identifier.
func (s *ServerSession) resendLCPConfigReq() {
	s.send(ProtocolLCP, s.lcpConfigReq)
	s.lcpRestart.arm(s.withLock, s.resendLCPConfigReq, func() {
		s.failLocked(fmt.Errorf("ppp: no reply to the LCP Configure-Request"))
	})
}

func (s *ServerSession) handleLCP(payload []byte) {
	pkt, ok := parseCP(payload)
	if !ok {
		return
	}

	switch pkt.Code {
	case codeConfigureRequest:
		s.handleLCPConfigReq(pkt)
	case codeConfigureAck:
		if !s.lcpLocalOpen && matchesAck(pkt, s.lcpConfigReq) {
			s.lcpRestart.stop()
			s.lcpLocalOpen = true
			s.maybeLCPUp()
		}
	case codeConfigureNak, codeConfigureReject:
		if s.lcpLocalOpen || !validConfigReply(pkt, s.lcpConfigReq) {
			return
		}
		opts, _ := parseOptions(pkt.Body)
		for _, o := range opts {
			switch o.Type {
			case optAuthProto:
				if pkt.Code == codeConfigureReject || !bytes.Equal(o.Value, authMSCHAPv2) {
					s.failLocked(fmt.Errorf("ppp: client rejected MS-CHAPv2 authentication"))
					return
				}
			case optMRU:
				if len(o.Value) != 2 {
					return
				}
				if pkt.Code == codeConfigureReject {
					s.lcpNoMRU = true
					s.localMRU = 1500
				} else {
					mru := binary.BigEndian.Uint16(o.Value)
					if mru < 128 {
						return
					}
					s.localMRU = mru
				}
			case optMagic:
				if len(o.Value) != 4 {
					return
				}
				if pkt.Code == codeConfigureReject {
					s.lcpNoMagic = true
				} else {
					var magic [4]byte
					_, _ = rand.Read(magic[:])
					s.magic = binary.BigEndian.Uint32(magic[:])
				}
			default:
				return
			}
		}
		s.configChanges++
		if s.configChanges > maxConfigure {
			s.failLocked(fmt.Errorf("ppp: LCP negotiation did not converge"))
			return
		}
		s.lcpRestart.stop()
		s.sendLCPConfigReq()
	case codeTerminateRequest:
		s.send(ProtocolLCP, cpPacket{Code: codeTerminateAck, ID: pkt.ID}.marshal())
		s.failLocked(fmt.Errorf("ppp: client closed the link"))
	case codeEchoRequest:
		if s.phase >= phaseAuth && len(pkt.Body) >= 4 {
			s.sendEchoReply(pkt)
		}
	case codeEchoReply, codeTerminateAck, 11:
	case 7:
		if len(pkt.Body) >= 1 && pkt.Body[0] >= 1 && pkt.Body[0] <= 7 {
			s.failLocked(fmt.Errorf("ppp: peer rejected required LCP code"))
		}
	case 8:
		if len(pkt.Body) >= 2 {
			protocol := binary.BigEndian.Uint16(pkt.Body)
			if protocol == ProtocolLCP || protocol == ProtocolCHAP && !s.cfg.NoAuth || protocol == ProtocolIPCP || protocol == ProtocolIP {
				s.failLocked(fmt.Errorf("ppp: peer rejected required protocol"))
			}
		}
	default:
		s.send(ProtocolLCP, cpPacket{Code: 7, ID: s.nextID(), Body: payload[:min(len(payload), int(s.peerMRU)-4)]}.marshal())
	}
}

func (s *ServerSession) handleLCPConfigReq(pkt cpPacket) {
	opts, ok := parseOptions(pkt.Body)
	if !ok {
		return
	}
	if s.phase != phaseLCP {
		if bytes.Equal(pkt.marshal(), s.peerLCPRequest) {
			s.send(ProtocolLCP, cpPacket{Code: codeConfigureAck, ID: pkt.ID, Body: pkt.Body}.marshal())
			return
		}
		s.h.NetworkDown()
		s.phase = phaseLCP
		s.lcpLocalOpen, s.lcpRemoteOpen = false, false
		s.ipcpLocalOpen, s.ipcpRemoteOpen = false, false
		s.authRestart.stop()
		s.ipcpRestart.stop()
		s.lcpRestart.stop()
		s.authRequest, s.authResponse, s.authSuccess = nil, nil, nil
		s.username, s.password = "", ""
		s.peerMRU = 1500
		s.configChanges = 0
		s.sendLCPConfigReq()
	}
	var rejected []option
	var seen [256]bool
	for _, o := range opts {
		if seen[o.Type] {
			rejected = append(rejected, o)
			continue
		}
		seen[o.Type] = true
		switch o.Type {
		case optMRU, optMagic, optPFC, optACFC:
			if !validLinkOption(o) {
				rejected = append(rejected, o)
			}
		default:
			rejected = append(rejected, o)
		}
	}
	if len(rejected) > 0 {
		s.send(ProtocolLCP, cpPacket{Code: codeConfigureReject, ID: pkt.ID, Body: marshalOptions(rejected)}.marshal())
		return
	}
	for _, o := range opts {
		if o.Type == optMagic && binary.BigEndian.Uint32(o.Value) == s.magic && !s.lcpNoMagic {
			var magic [4]byte
			_, _ = rand.Read(magic[:])
			s.send(ProtocolLCP, cpPacket{Code: codeConfigureNak, ID: pkt.ID, Body: marshalOptions([]option{{Type: optMagic, Value: magic[:]}})}.marshal())
			return
		}
		if o.Type == optMRU {
			mru := binary.BigEndian.Uint16(o.Value)
			if mru < 128 {
				s.send(ProtocolLCP, cpPacket{Code: codeConfigureNak, ID: pkt.ID, Body: marshalOptions([]option{{Type: optMRU, Value: []byte{0, 128}}})}.marshal())
				return
			}
			s.peerMRU = mru
		}
	}
	s.send(ProtocolLCP, cpPacket{Code: codeConfigureAck, ID: pkt.ID, Body: pkt.Body}.marshal())
	s.peerLCPRequest = pkt.marshal()
	s.lcpRemoteOpen = true
	s.maybeLCPUp()
}

func (s *ServerSession) sendEchoReply(req cpPacket) {
	var magic [4]byte
	if !s.lcpNoMagic {
		binary.BigEndian.PutUint32(magic[:], s.magic)
	}
	body := magic[:]
	if len(req.Body) >= 4 {
		body = append(magic[:], req.Body[4:]...)
	}
	s.send(ProtocolLCP, cpPacket{Code: codeEchoReply, ID: req.ID, Body: body}.marshal())
}

func (s *ServerSession) maybeLCPUp() {
	if s.phase != phaseLCP || !s.lcpLocalOpen || !s.lcpRemoteOpen {
		return
	}
	if s.cfg.NoAuth {
		// No PPP authentication: the carrier authenticated already, so assign the
		// address straight away.
		s.phase = phaseIPCP
		s.sendIPCPConfigReq()
		return
	}
	s.phase = phaseAuth
	s.sendChallenge()
}

// --- MS-CHAPv2 authentication (authenticator role) ---

func (s *ServerSession) sendChallenge() {
	if _, err := rand.Read(s.authChallenge[:]); err != nil {
		s.failLocked(fmt.Errorf("ppp: challenge: %w", err))
		return
	}
	s.authID = s.nextID()
	s.authRequest = cpPacket{Code: chapChallenge, ID: s.authID, Body: buildChallenge(s.authChallenge, "veepin")}.marshal()
	s.resendChallenge()
}

func (s *ServerSession) resendChallenge() {
	s.send(ProtocolCHAP, s.authRequest)
	if s.phase != phaseAuth {
		return
	}
	s.authRestart.arm(s.withLock, s.resendChallenge, func() { s.failLocked(fmt.Errorf("ppp: authentication timed out")) })
}

func (s *ServerSession) handleCHAP(payload []byte) {
	pkt, ok := parseCP(payload)
	if !ok || pkt.Code != chapResponse || pkt.ID != s.authID {
		return
	}
	if s.phase != phaseAuth {
		if bytes.Equal(pkt.Body, s.authResponse) && len(s.authSuccess) > 0 {
			s.send(ProtocolCHAP, s.authSuccess)
		}
		return
	}
	peerCh, ntResp, username, ok := parseResponse(pkt.Body)
	if !ok {
		return
	}
	if s.cfg.Auth == nil {
		s.failLocked(fmt.Errorf("ppp: authenticator unavailable"))
		return
	}
	password, known := s.cfg.Auth(username)
	if !known || !verifyResponse(s.authChallenge, peerCh, username, password, ntResp) {
		s.send(ProtocolCHAP, cpPacket{Code: chapFailure, ID: pkt.ID, Body: buildFailure()}.marshal())
		s.failLocked(fmt.Errorf("ppp: authentication failed for %q", username))
		return
	}

	s.username, s.password, s.ntResponse = username, password, ntResp
	success := buildSuccess(s.authChallenge, peerCh, username, password, ntResp)
	s.authRestart.stop()
	s.authResponse = bytes.Clone(pkt.Body)
	s.authSuccess = cpPacket{Code: chapSuccess, ID: pkt.ID, Body: success}.marshal()
	s.send(ProtocolCHAP, s.authSuccess)
	if s.phase == phaseClosed {
		return
	}

	s.h.Authenticated(username, password, ntResp)
	s.phase = phaseIPCP
	s.sendIPCPConfigReq()
}

// --- IPCP ---

func (s *ServerSession) sendIPCPConfigReq() {
	var opts []option
	if !s.ipcpNoAddress {
		opts = append(opts, option{Type: optIPAddress, Value: s.cfg.ServerIP.To4()})
	}
	s.ipcpReqID = s.nextID()
	s.ipcpConfigReq = cpPacket{Code: codeConfigureRequest, ID: s.ipcpReqID, Body: marshalOptions(opts)}.marshal()
	s.resendIPCPConfigReq()
}

// resendIPCPConfigReq (re)transmits the outstanding IPCP Configure-Request and
// re-arms the Restart timer, reusing the original identifier.
func (s *ServerSession) resendIPCPConfigReq() {
	s.send(ProtocolIPCP, s.ipcpConfigReq)
	s.ipcpRestart.arm(s.withLock, s.resendIPCPConfigReq, func() {
		s.failLocked(fmt.Errorf("ppp: no reply to the IPCP Configure-Request"))
	})
}

func (s *ServerSession) handleIPCP(payload []byte) {
	pkt, ok := parseCP(payload)
	if !ok {
		return
	}

	switch pkt.Code {
	case codeConfigureRequest:
		s.handleIPCPConfigReq(pkt)
	case codeConfigureAck:
		if !s.ipcpLocalOpen && matchesAck(pkt, s.ipcpConfigReq) {
			s.ipcpRestart.stop()
			s.authRestart.stop()
			s.ipcpLocalOpen = true
			s.maybeIPCPUp()
		}
	case codeConfigureNak, codeConfigureReject:
		if s.ipcpLocalOpen || !validConfigReply(pkt, s.ipcpConfigReq) {
			return
		}
		opts, _ := parseOptions(pkt.Body)
		if len(opts) != 1 || opts[0].Type != optIPAddress || len(opts[0].Value) != 4 {
			return
		}
		// The configured server address is policy, not a peer-controlled assignment.
		// It can be omitted after a Reject (RFC 1332), but not replaced by a Nak.
		if pkt.Code == codeConfigureNak {
			s.failLocked(fmt.Errorf("ppp: peer rejected configured server address"))
			return
		}
		s.ipcpNoAddress = true
		s.ipcpRestart.stop()
		s.sendIPCPConfigReq()
	case codeTerminateRequest:
		s.send(ProtocolIPCP, cpPacket{Code: codeTerminateAck, ID: pkt.ID}.marshal())
		s.failLocked(fmt.Errorf("ppp: peer closed IPCP"))
	case codeTerminateAck:
	case 7:
		s.failLocked(fmt.Errorf("ppp: peer rejected IPCP"))
	default:
		s.send(ProtocolIPCP, cpPacket{Code: 7, ID: s.nextID(), Body: payload[:min(len(payload), int(s.peerMRU)-4)]}.marshal())
	}
}

// handleIPCPConfigReq answers the client's address request: it Naks any option
// whose value is not what the server assigns (the client's address and DNS),
// steering the client to the assigned values; once they match it Acks.
func (s *ServerSession) handleIPCPConfigReq(pkt cpPacket) {
	if s.phase == phaseUp {
		if bytes.Equal(pkt.marshal(), s.peerIPCPRequest) {
			s.send(ProtocolIPCP, cpPacket{Code: codeConfigureAck, ID: pkt.ID, Body: pkt.Body}.marshal())
			return
		}
		s.h.NetworkDown()
		s.phase = phaseIPCP
		s.ipcpLocalOpen, s.ipcpRemoteOpen = false, false
		s.ipcpRestart.stop()
		s.sendIPCPConfigReq()
	}

	opts, ok := parseOptions(pkt.Body)
	if !ok {
		return
	}
	var rejected []option
	var seen [256]bool
	for _, o := range opts {
		supported := o.Type == optIPAddress || o.Type == optPrimaryDNS && s.dnsAt(0) != nil || o.Type == optSecondaryDNS && s.dnsAt(1) != nil
		if !supported || len(o.Value) != 4 || seen[o.Type] {
			rejected = append(rejected, o)
		}
		seen[o.Type] = true
	}
	if len(rejected) > 0 {
		s.send(ProtocolIPCP, cpPacket{Code: codeConfigureReject, ID: pkt.ID, Body: marshalOptions(rejected)}.marshal())
		return
	}
	var nak []option
	for _, o := range opts {
		switch o.Type {
		case optIPAddress:
			if !ipEq(o.Value, s.cfg.ClientIP) {
				nak = append(nak, option{Type: optIPAddress, Value: s.cfg.ClientIP.To4()})
			}
		case optPrimaryDNS:
			if want := s.dnsAt(0); want != nil && !ipEq(o.Value, want) {
				nak = append(nak, option{Type: optPrimaryDNS, Value: want.To4()})
			}
		case optSecondaryDNS:
			if want := s.dnsAt(1); want != nil && !ipEq(o.Value, want) {
				nak = append(nak, option{Type: optSecondaryDNS, Value: want.To4()})
			}
		}
	}
	if !seen[optIPAddress] {
		nak = append(nak, option{Type: optIPAddress, Value: s.cfg.ClientIP.To4()})
	}
	if len(nak) > 0 {
		s.send(ProtocolIPCP, cpPacket{Code: codeConfigureNak, ID: pkt.ID, Body: marshalOptions(nak)}.marshal())
		return
	}
	s.send(ProtocolIPCP, cpPacket{Code: codeConfigureAck, ID: pkt.ID, Body: pkt.Body}.marshal())
	s.peerIPCPRequest = pkt.marshal()
	s.ipcpRemoteOpen = true
	s.maybeIPCPUp()
}

func (s *ServerSession) dnsAt(i int) net.IP {
	if i < len(s.cfg.DNS) {
		return s.cfg.DNS[i]
	}
	return nil
}

func (s *ServerSession) maybeIPCPUp() {
	if s.phase != phaseIPCP || !s.ipcpLocalOpen || !s.ipcpRemoteOpen {
		return
	}
	s.phase = phaseUp
	s.h.NetworkUp(min(s.peerMRU, DefaultMRU))
}

// ipEq reports whether a 4-byte option value equals an IP address.
func ipEq(value []byte, ip net.IP) bool {
	v4 := ip.To4()
	return len(value) == 4 && v4 != nil && value[0] == v4[0] && value[1] == v4[1] && value[2] == v4[2] && value[3] == v4[3]
}
