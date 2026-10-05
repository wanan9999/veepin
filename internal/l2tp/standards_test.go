package l2tp

import (
	"encoding/binary"
	"github.com/wanan9999/veepin/dataplane"
	"github.com/wanan9999/veepin/internal/ikev1"
	"github.com/wanan9999/veepin/internal/ppp"
	"net"
	"testing"
	"testing/synctest"
	"time"
)

type auditHandler struct{ data, up, closed int }

func (h *auditHandler) DataFrame([]byte) { h.data++ }
func (h *auditHandler) SessionUp()       { h.up++ }
func (h *auditHandler) Closed(error)     { h.closed++ }
func auditTunnel(t *testing.T) (*Tunnel, *auditHandler, *[][]byte) {
	h := &auditHandler{}
	sent := new([][]byte)
	tun := NewTunnel(RoleLNS, func(b []byte) error { *sent = append(*sent, b); return nil }, h)
	t.Cleanup(tun.Abort)
	return tun, h, sent
}

func TestSmallMRUFragmentsIPv4AndReportsDF(t *testing.T) {
	tun, _, sent := auditTunnel(t)
	tun.peerTunnelID.Store(7)
	tun.peerSessionID.Store(9)
	packet := make([]byte, 1400)
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = 17
	binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
	copy(packet[12:], net.IPv4(192, 0, 2, 1).To4())
	copy(packet[16:], net.IPv4(10, 0, 0, 2).To4())
	for i := 20; i < len(packet); i++ {
		packet[i] = byte(i)
	}
	if err := sendIPv4(tun, packet, 576, 0, func([]byte) { t.Fatal("fragmentable packet caused ICMP") }); err != nil {
		t.Fatal(err)
	}
	recovered := make([]byte, 1380)
	for _, frame := range *sent {
		h, err := parseHeader(frame)
		if err != nil {
			t.Fatal(err)
		}
		ip, ok := ppp.IsIP(h.payload)
		if !ok || len(ip) > 576 {
			t.Fatal("fragment exceeds negotiated MRU")
		}
		offset := int(binary.BigEndian.Uint16(ip[6:])&8191) * 8
		copy(recovered[offset:], ip[20:])
	}
	for i, b := range recovered {
		if b != packet[i+20] {
			t.Fatal("fragmented payload changed")
		}
	}
	*sent = nil
	packet[6] = 0x40
	var feedback []byte
	if err := sendIPv4(tun, packet, 576, 0, func(b []byte) { feedback = b }); err != nil {
		t.Fatal(err)
	}
	mtu, ok := dataplane.ParseFragNeeded(feedback)
	if len(*sent) != 0 || !ok || mtu != 576 {
		t.Fatal("DF packet did not receive correct PMTU feedback")
	}
}

func TestClosedTunnelAcknowledgesRepeatedStopWithoutDeliveringData(t *testing.T) {
	tun, h, sent := auditTunnel(t)
	tun.state = stateEstablished
	tun.peerTunnelID.Store(7)
	var b avpBuilder
	b.addUint16(avpMessageType, msgStopCCN)
	b.addUint16(avpResultCode, 1)
	b.addUint16(avpAssignedTunnelID, 7)
	pkt := marshalControl(tun.localTunnelID, 0, 0, 0, b.bytes())
	tun.HandleInbound(pkt)
	first := len(*sent)
	tun.HandleInbound(pkt)
	tun.HandleInbound(marshalData(tun.localTunnelID, tun.localSessionID, []byte{1}))
	if len(*sent) != first+1 || h.closed != 1 || h.data != 0 {
		t.Fatal("close tombstone did not ACK exactly once without reopening data")
	}
}

func TestAdministrativeCloseRetransmitsUntilAcknowledged(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tun, _, sent := auditTunnel(t)
		tun.state = stateEstablished
		tun.peerTunnelID.Store(7)
		tun.Close()
		first := len(*sent)
		time.Sleep(time.Second)
		synctest.Wait()
		if len(*sent) != first+1 {
			t.Fatal("lost StopCCN was not retransmitted")
		}
		tun.HandleInbound(marshalControl(tun.localTunnelID, 0, 0, 1, nil))
		first = len(*sent)
		time.Sleep(3 * time.Second)
		synctest.Wait()
		if len(*sent) != first {
			t.Fatal("acknowledged StopCCN still retransmitted")
		}
	})
}

func TestControlWindowNeverSendsAnUnacknowledgedSecondMessage(t *testing.T) {
	tun, _, sent := auditTunnel(t)
	tun.peerTunnelID.Store(7)
	var b avpBuilder
	b.addUint16(avpMessageType, msgHELLO)
	tun.queueControl(0, b.bytes())
	tun.queueControl(0, b.bytes())
	if len(*sent) != 1 {
		t.Fatal("exceeded the conservative receive window")
	}
	tun.HandleInbound(marshalControl(tun.localTunnelID, 0, 0, 2, nil))
	if len(*sent) != 1 {
		t.Fatal("accepted acknowledgement for unsent sequence")
	}
	tun.HandleInbound(marshalControl(tun.localTunnelID, 0, 0, 1, nil))
	if len(*sent) != 2 {
		t.Fatal("did not release next queued message")
	}
}

func TestUDPSelectorsAndOriginalAddressChecksum(t *testing.T) {
	policy := ikev1.TransportPolicy{LocalPort: 1701, PeerPort: 49152, LocalIP: net.IPv4(192, 0, 2, 1), PeerIP: net.IPv4(10, 0, 0, 2)}
	packet := wrapUDP([]byte{1, 2, 3}, 49152, 1701)
	sum := uint32(17 + len(packet))
	for _, b := range [][]byte{policy.PeerIP.To4(), policy.LocalIP.To4(), packet} {
		for len(b) >= 2 {
			sum += uint32(binary.BigEndian.Uint16(b))
			b = b[2:]
		}
		if len(b) > 0 {
			sum += uint32(b[0]) << 8
		}
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(packet[6:], ^uint16(sum))
	if _, ok := unwrapUDP(packet, policy); !ok {
		t.Fatal("valid ephemeral-port UDP checksum rejected")
	}
	changed := policy
	changed.PeerPort = 1701
	if _, ok := unwrapUDP(packet, changed); ok {
		t.Fatal("wrong source port accepted")
	}
	changed = policy
	changed.PeerIP = net.IPv4(198, 51, 100, 2)
	if _, ok := unwrapUDP(packet, changed); ok {
		t.Fatal("checksum verified with wrong pre-NAT address")
	}
}
func TestStandardsWrongIDsMustDrop(t *testing.T) {
	tun, h, _ := auditTunnel(t)
	tun.state = stateEstablished
	tun.HandleInbound(marshalData(tun.localTunnelID^1, tun.localSessionID^1, []byte{1}))
	if h.data != 0 {
		t.Fatal("delivered data with wrong tunnel/session IDs")
	}
}
func TestStandardsUnknownMandatoryAVPMustReject(t *testing.T) {
	tun, h, _ := auditTunnel(t)
	var b avpBuilder
	b.addUint16(avpMessageType, msgSCCRQ)
	b.add(avpProtocolVersion, []byte{1, 0})
	b.addUint32(avpFramingCapabilities, 3)
	b.add(avpHostName, []byte("audit"))
	b.addUint16(avpAssignedTunnelID, 7)
	b.addUint16(60000, 1)
	tun.HandleInbound(marshalControl(0, 0, 0, 0, b.bytes()))
	if h.closed == 0 {
		t.Fatal("accepted unknown mandatory AVP")
	}
}
func TestStandardsSequencingRequiredMustBeHonored(t *testing.T) {
	tun, _, sent := auditTunnel(t)
	tun.state = stateWaitICCN
	tun.peerTunnelID.Store(7)
	tun.peerSessionID.Store(9)
	var b avpBuilder
	b.addUint16(avpMessageType, msgICCN)
	b.addUint32(avpTxConnectSpeed, 100000)
	b.addUint32(avpFramingType, 1)
	b.add(39, nil)
	tun.HandleInbound(marshalControl(tun.localTunnelID, tun.localSessionID, 0, 0, b.bytes()))
	_ = tun.SendPPP([]byte{1})
	h, _ := parseHeader((*sent)[len(*sent)-1])
	if !h.hasSeq {
		t.Fatal("accepted Sequencing Required then emitted unsequenced data")
	}
}
func TestStandardsCloseMustNotify(t *testing.T) {
	tun, _, sent := auditTunnel(t)
	tun.state = stateEstablished
	tun.peerTunnelID.Store(7)
	tun.peerSessionID.Store(9)
	tun.Close()
	if len(*sent) == 0 {
		t.Fatal("administrative close sent no CDN/StopCCN")
	}
}
func TestStandardsInnerUDPMustValidate(t *testing.T) {
	pkt := []byte{0, 53, 0, 53, 0, 8, 0, 0, 1, 2, 3}
	if _, ok := unwrapUDP(pkt, ikev1.TransportPolicy{}); ok {
		t.Fatal("accepted unrelated UDP ports and bytes outside UDP length")
	}
}

func TestStandardsStopCCNMustBeAcknowledged(t *testing.T) {
	tun, _, sent := auditTunnel(t)
	tun.state = stateEstablished
	tun.peerTunnelID.Store(7)
	var b avpBuilder
	b.addUint16(avpMessageType, msgStopCCN)
	b.addUint16(1, 1)
	b.addUint16(avpAssignedTunnelID, 7)
	tun.HandleInbound(marshalControl(tun.localTunnelID, 0, 0, 0, b.bytes()))
	if len(*sent) == 0 {
		t.Fatal("StopCCN closed immediately without ZLB acknowledgement")
	}
}
