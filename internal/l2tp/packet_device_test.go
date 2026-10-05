package l2tp

import (
	"bytes"
	"io"
	"net"
	"testing"

	"github.com/wanan9999/veepin/internal/ppp"
)

type testSessionDevice struct{ bytes.Buffer }

func (*testSessionDevice) Close() error { return nil }

func TestSessionPacketAdmission(t *testing.T) {
	address := net.IPv4(10, 20, 0, 2)
	packet := make([]byte, 20)
	packet[0], packet[3] = 0x45, 20
	copy(packet[12:16], address.To4())
	for _, tc := range []struct {
		name                 string
		ready, closed, spoof bool
		want                 int
	}{
		{name: "before PPP authentication"},
		{name: "negotiated session", ready: true, want: 20},
		{name: "forged source", ready: true, spoof: true},
		{name: "closed session", ready: true, closed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			device := &testSessionDevice{}
			p := &serverPeer{innerIP: address, ready: tc.ready, closed: tc.closed, device: device}
			data := append([]byte(nil), packet...)
			if tc.spoof {
				data[15]++
			}
			p.DataFrame(ppp.EncapsulateIPPadded(data, 0))
			if device.Len() != tc.want {
				t.Fatalf("admitted %d bytes, want %d", device.Len(), tc.want)
			}
		})
	}
}

func TestClosedSessionDoesNotCreateDevice(t *testing.T) {
	called := false
	p := &serverPeer{closed: true, username: "test", srv: &Server{cfg: ServerConfig{
		PacketDeviceFactory: func(string, net.IP, uint16) (io.ReadWriteCloser, error) { called = true; return nil, nil },
	}}}
	serverPPP{p}.NetworkUp(1400)
	if called {
		t.Fatal("closed peer created a network stack")
	}
}
