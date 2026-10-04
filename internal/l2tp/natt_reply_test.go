package l2tp

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/ikev2/esp"
)

// Connected UDP clients reject replies from the wrong source port, just as
// TunnelForge does. Ephemeral loopback ports model 500/4500 without privileges
// or assuming that a client's NAT mapping uses port 4500.
func TestIKERepliesFollowObservedTransport(t *testing.T) {
	listen := func() *net.UDPConn {
		t.Helper()
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	ike, natt := listen(), listen()
	dial := func(server *net.UDPConn) *net.UDPConn {
		t.Helper()
		c, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	plainClient, nattClient := dial(ike), dial(natt)
	srv := &Server{ikeConn: dataplane.NewPacketConn(ike), nattConn: dataplane.NewPacketConn(natt)}
	plainAddr := plainClient.LocalAddr().(*net.UDPAddr)
	nattAddr := nattClient.LocalAddr().(*net.UDPAddr)
	newPeer := func() *serverPeer {
		return &serverPeer{srv: srv, addr: plainAddr, nattAddr: &net.UDPAddr{IP: plainAddr.IP, Port: nattPort}}
	}
	msg := []byte("synthetic IKE response")
	expect := func(t *testing.T, p *serverPeer, requestedNATT bool, client *net.UDPConn, marked bool) {
		t.Helper()
		if err := p.sendIKE(msg, requestedNATT); err != nil {
			t.Fatal(err)
		}
		if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 256)
		n, err := client.Read(buf)
		if err != nil {
			t.Fatalf("reply did not reach the client's observed transport: %v", err)
		}
		want := msg
		if marked {
			want = markIKE(msg)
		}
		if !bytes.Equal(buf[:n], want) {
			t.Fatalf("reply = %x, want %x", buf[:n], want)
		}
	}
	t.Run("late-float-after-MM6", func(t *testing.T) {
		p := newPeer()
		p.noteIKEAddr(plainAddr, false)
		// The IKE state already negotiated NAT-T, but MM5 arrived on UDP/500.
		expect(t, p, true, plainClient, false)
		p.noteIKEAddr(nattAddr, true) // QM1 reveals the real NAT mapping.
		expect(t, p, true, nattClient, true)
	})
	t.Run("early-float-before-MM5", func(t *testing.T) {
		p := newPeer()
		expect(t, p, false, plainClient, false) // MM4
		p.noteIKEAddr(nattAddr, true)
		expect(t, p, true, nattClient, true) // MM6
		p.noteIKEAddr(plainAddr, false)      // delayed pre-float traffic cannot undo it.
		expect(t, p, true, nattClient, true)
	})
	t.Run("initial-IKE-on-NATT", func(t *testing.T) {
		p := newPeer()
		p.noteIKEAddr(nattAddr, true)
		expect(t, p, false, nattClient, true) // MM2, before the engine negotiates NAT-T.
	})
}

func TestUnverifiedIKECannotMoveExistingPeer(t *testing.T) {
	original := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 40000}
	forged := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 99), Port: 41000}
	srv := &Server{cfg: ServerConfig{PublicIP: net.IPv4(192, 0, 2, 2)},
		gate: dataplane.NewGate(dataplane.AdmissionConfig{}), byCookie: make(map[[8]byte]*serverPeer)}
	cookie := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	p := srv.peerFor(cookie, original, false)
	if p == nil {
		t.Fatal("test peer admission failed")
	}
	// Syntactically valid but unauthenticated Informational packet carrying
	// the existing cookie; it must not commit a NAT-T float or address change.
	pkt := make([]byte, 28)
	copy(pkt, cookie[:])
	pkt[17], pkt[18] = 0x10, 5
	binary.BigEndian.PutUint32(pkt[24:], uint32(len(pkt)))
	srv.dispatchIKE(pkt, forged, true)
	if p.ikeNATT || p.addr != original || !p.nattAddr.IP.Equal(original.IP) {
		t.Fatal("unverified IKE changed the peer's transport or address")
	}
	p.noteIKEAddr(original, true) // model a successful authenticated float.
	srv.dispatchIKE(pkt, forged, false)
	if !p.ikeNATT || p.addr != original || p.nattAddr != original {
		t.Fatal("old UDP/500 traffic changed the floated endpoint")
	}
}

// Knowing the public ESP SPI does not authenticate a NAT rebinding. Only a
// fresh integrity-checked packet can change where subsequent traffic goes.
func TestESPRebindingRequiresIntegrityAndFreshSequence(t *testing.T) {
	original := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 40000}
	rebound := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 41000}
	forged := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 99), Port: 42000}
	tr := esp.Transform{EncrID: 12, EncrKeyLn: 128, IntegID: 2,
		EncKey: bytes.Repeat([]byte{0x11}, 16), IntegKey: bytes.Repeat([]byte{0x22}, 20)}
	sender := &esp.SA{SPIOut: 0x12345678, Out: tr, In: tr}
	receiver := &esp.SA{SPIIn: 0x12345678, Out: tr, In: tr}
	p := &serverPeer{srv: &Server{}, nattAddr: original, sa: receiver,
		tunnel: NewTunnel(RoleLNS, func([]byte) error { return nil }, newEndpoint(RoleLNS))}
	packet, err := sender.Encapsulate(wrapUDP([]byte{0}), ipProtoUDP)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), packet...)
	tampered[len(tampered)-1] ^= 1
	p.handleESP(tampered, forged)
	if p.nattAddr != original {
		t.Fatal("forged ESP moved the endpoint")
	}
	p.handleESP(packet, rebound)
	if p.nattAddr != rebound {
		t.Fatal("authenticated ESP did not move the endpoint")
	}
	p.handleESP(packet, forged)
	if p.nattAddr != rebound {
		t.Fatal("replayed ESP moved the endpoint")
	}
}
