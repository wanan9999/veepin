package l2tp

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/wanan9999/veepin/internal/ikev2/esp"
)

func lifecycleServer(t *testing.T) *Server {
	t.Helper()
	listen := func() *net.UDPConn {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	s := NewServer(listen(), listen(), nil, ServerConfig{})
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestExhaustedControlRetriesDoNotStartAnotherDrainPeriod(t *testing.T) {
	s := lifecycleServer(t)
	p := s.peerFor([8]byte{1}, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 500}, false)
	p.Closed(ErrControlTimeout)
	p.mu.Lock()
	closed, draining := p.closed, p.draining
	p.mu.Unlock()
	if !closed || draining || s.gate.HalfOpen() != 0 {
		t.Fatal("expired control channel retained resources for a second retry cycle")
	}
}

func TestAdmissionIsReleasedAfterRepeatedDisconnects(t *testing.T) {
	s := lifecycleServer(t)
	for n := range 600 {
		var cookie [8]byte
		binary.BigEndian.PutUint64(cookie[:], uint64(n+1))
		p := s.peerFor(cookie, &net.UDPAddr{IP: net.IPv4(10, byte(n>>8), byte(n), 1), Port: 500}, false)
		if p == nil {
			t.Fatalf("rejected sequential peer %d", n)
		}
		s.removePeer(p, errors.New("test disconnect"))
		s.removePeer(p, errors.New("duplicate close"))
		if got := s.gate.HalfOpen(); got != 0 {
			t.Fatalf("leaked %d slots", got)
		}
	}
}

func TestAdmissionIsReleasedOnSuccessfulIKE(t *testing.T) {
	s := lifecycleServer(t)
	p := s.peerFor([8]byte{1}, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 500}, false)
	p.releaseAdmission()
	p.releaseAdmission()
	if s.gate.HalfOpen() != 0 {
		t.Fatal("successful handshake still reserved")
	}
}

func TestUnexpectedListenerExitIsReported(t *testing.T) {
	s := lifecycleServer(t)
	// A packet-device mode avoids a host TUN in this unit test.
	s.cfg.PacketDeviceFactory = func(string, net.IP, uint16) (io.ReadWriteCloser, error) { return nil, nil }
	result := make(chan error, 1)
	go func() { result <- s.Serve() }()
	_ = s.ikeConn.Close()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("read failure reported success")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second socket masked dead IKE listener")
	}
}

func TestSilentSetupAndEstablishedPeersAreReaped(t *testing.T) {
	for _, ready := range []bool{false, true} {
		t.Run(map[bool]string{false: "setup", true: "established"}[ready], func(t *testing.T) {
			s := lifecycleServer(t)
			p := &serverPeer{srv: s, cookie: [8]byte{1}, done: make(chan struct{}), addr: &net.UDPAddr{}, ready: ready}
			s.byCookie[p.cookie] = p
			if ready {
				p.tunnel = NewTunnel(RoleLNS, func([]byte) error { return nil }, p)
			}
			go p.monitorWithTimeouts(20*time.Millisecond, 10*time.Millisecond, 20*time.Millisecond)
			select {
			case <-p.done:
			case <-time.After(time.Second):
				t.Fatal("silent peer leaked")
			}
			s.mu.Lock()
			remaining := len(s.byCookie)
			s.mu.Unlock()
			if remaining != 0 {
				t.Fatal("peer index survived teardown")
			}
		})
	}
}

func TestOldESPDeleteAndExpiryPreserveCurrentSA(t *testing.T) {
	s := lifecycleServer(t)
	p := &serverPeer{srv: s, cookie: [8]byte{1}, done: make(chan struct{}), addr: &net.UDPAddr{}}
	old := &esp.SA{SPIIn: 1, SPIOut: 2}
	current := &esp.SA{SPIIn: 3, SPIOut: 4}
	p.sa, p.inSPI = current, 3
	p.sas = map[uint32]timedSA{1: {sa: old, expires: time.Now().Add(time.Hour)}, 3: {sa: current, expires: time.Now().Add(time.Hour)}}
	s.byCookie[p.cookie], s.bySPI[1], s.bySPI[3] = p, p, p
	p.DeleteESP(2)
	if p.closed || p.sa != current || len(p.sas) != 1 || s.bySPI[1] != nil {
		t.Fatal("deleting old SA damaged active session or leaked index")
	}
	p.sas[5] = timedSA{sa: &esp.SA{SPIIn: 5}, expires: time.Now().Add(-time.Second)}
	s.bySPI[5] = p
	p.pruneSAs()
	if s.bySPI[5] != nil || len(p.sas) != 1 {
		t.Fatal("expired SA retained")
	}
	p.DeleteESP(4)
	if !p.closed || len(s.bySPI) != 0 {
		t.Fatal("active deletion retained session")
	}
	// A late handshake callback must never resurrect a removed index.
	s.mapSPI(9, p)
	s.mapIP(net.IPv4(10, 20, 0, 2), p)
	if len(s.bySPI) != 0 || len(s.byIP) != 0 {
		t.Fatal("late callback resurrected peer")
	}
}
