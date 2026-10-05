package ikev1

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestTransportSelectorsPreserveEphemeralPortAndRejectOtherServices(t *testing.T) {
	s := &Session{cfg: Config{Role: Responder, Phase2: Phase2L2TP, LocalIP: net.IPv4(192, 0, 2, 1), PeerIP: net.IPv4(198, 51, 100, 2)}}
	peer := buildID(l2tpSelector(net.IPv4(10, 0, 0, 2)))
	binary.BigEndian.PutUint16(peer[2:], 49152)
	local := buildID(l2tpSelector(s.cfg.LocalIP))
	ps := []payload{{typ: payloadID, body: peer}, {typ: payloadID, body: local}}
	if err := s.acceptSelectors(ps, false); err != nil {
		t.Fatal(err)
	}
	if s.transport.PeerPort != 49152 || s.transport.LocalPort != 1701 {
		t.Fatal("lost negotiated ports")
	}
	binary.BigEndian.PutUint16(local[2:], 53)
	if err := s.acceptSelectors(ps, false); err == nil {
		t.Fatal("accepted unrelated destination service")
	}
}

func TestRFCNATTOnlyAndTwoOriginalAddresses(t *testing.T) {
	if ids := natTVendorPayloads(); len(ids) != 1 || !peerSupportsNATT(ids) {
		t.Fatal("RFC NAT-T advertisement mismatch")
	}
	if peerSupportsNATT([]payload{{typ: payloadVendorID, body: mustHex("90cb80913ebb696e086381b5ec427b1f")}}) {
		t.Fatal("negotiated unsupported draft")
	}
	s := &Session{cfg: Config{Role: Responder, LocalIP: net.IPv4(192, 0, 2, 1), PeerIP: net.IPv4(198, 51, 100, 2)}}
	oa := s.originalAddresses()
	if len(oa) != 2 || !net.IP(oa[0].body[4:]).Equal(s.cfg.PeerIP) || !net.IP(oa[1].body[4:]).Equal(s.cfg.LocalIP) {
		t.Fatal("responder NAT-OA order incorrect")
	}
}

func TestStandardsWrongIKEVersionMustReject(t *testing.T) {
	p := marshalMessage(header{exchange: exchangeMain}, nil)
	p[17] = 0x20
	if _, _, _, err := parseHeader(p); err == nil {
		t.Fatal("IKEv1 parser accepted IKEv2 version byte")
	}
}
