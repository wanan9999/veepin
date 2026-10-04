package l2tp

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/xen0bit/veepin/dataplane"
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
