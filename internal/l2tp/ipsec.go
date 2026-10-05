package l2tp

import (
	"encoding/binary"
	"time"

	"github.com/wanan9999/veepin/internal/ikev1"
	"github.com/wanan9999/veepin/internal/ikev2/esp"
)

// The IPsec layer under L2TP is ESP in transport mode: it protects the UDP/1701
// datagrams the L2TP engine exchanges. In transport mode the ESP-protected
// payload is the upper-layer segment — here a UDP header followed by the L2TP
// datagram — with an ESP next-header of UDP (17). We always UDP-encapsulate ESP
// on the NAT-T port so the data path is a plain userspace socket, never a raw
// IP-protocol-50 socket.

const (
	// udpHeaderLen is the fixed UDP header prepended to each L2TP datagram to
	// form the transport-mode inner payload.
	udpHeaderLen = 8
	// l2tpUDPPort is the L2TP port carried in that inner UDP header (both source
	// and destination, since both ends run L2TP there).
	l2tpUDPPort = 1701
	// ipProtoUDP is the ESP next-header for a UDP transport-mode payload.
	ipProtoUDP = 17
	// nonESPMarkerLen is the 4-octet zero prefix distinguishing an IKE message
	// from an ESP packet on the shared NAT-T port (RFC 3948 section 2.2).
	nonESPMarkerLen = 4
	// defaultIKEPort carries Main Mode; nattPort carries IKE and ESP after the
	// NAT-T float (RFC 3947).
	defaultIKEPort = 500
	nattPort       = 4500
)

// newESPSA builds a transport-mode ESP SA from a completed IKEv1 exchange. The
// Result already expresses the transform in the IKEv2 IDs the esp package
// consumes and orients the keys/SPIs for the local end.
func newESPSA(r ikev1.Result) *esp.SA {
	deadline := time.Time{}
	if r.Lifetime > 0 {
		deadline = time.Now().Add(r.Lifetime)
	}
	return &esp.SA{
		ExpiresAt: deadline,
		ByteLimit: r.ByteLimit,
		SPIOut:    r.OutSPI,
		SPIIn:     r.InSPI,
		Out: esp.Transform{
			EncrID:    r.EncrID,
			EncrKeyLn: r.EncrKeyLn,
			IntegID:   r.IntegID,
			EncKey:    r.OutEncKey,
			IntegKey:  r.OutIntegKey,
		},
		In: esp.Transform{
			EncrID:    r.EncrID,
			EncrKeyLn: r.EncrKeyLn,
			IntegID:   r.IntegID,
			EncKey:    r.InEncKey,
			IntegKey:  r.InIntegKey,
		},
	}
}

// wrapUDP prepends the inner UDP header to an L2TP datagram, producing the
// transport-mode ESP payload. The checksum is left zero: IPv4 UDP permits it,
// which spares the peer a pseudo-header recomputation after decryption.
func wrapUDP(l2tp []byte, source, destination uint16) []byte {
	out := make([]byte, udpHeaderLen+len(l2tp))
	binary.BigEndian.PutUint16(out[0:], source)
	binary.BigEndian.PutUint16(out[2:], destination)
	binary.BigEndian.PutUint16(out[4:], uint16(udpHeaderLen+len(l2tp)))
	// out[6:8] checksum stays zero.
	copy(out[udpHeaderLen:], l2tp)
	return out
}

// unwrapUDP strips the inner UDP header from a decapsulated transport-mode
// payload, returning the L2TP datagram.
func unwrapUDP(inner []byte, policy ikev1.TransportPolicy) ([]byte, bool) {
	if len(inner) < udpHeaderLen {
		return nil, false
	}
	length := int(binary.BigEndian.Uint16(inner[4:]))
	if length < udpHeaderLen || length > len(inner) {
		return nil, false
	}
	src, dst := binary.BigEndian.Uint16(inner), binary.BigEndian.Uint16(inner[2:])
	local := policy.LocalPort
	if local == 0 {
		local = l2tpUDPPort
	}
	if src == 0 || dst != local || policy.PeerPort != 0 && src != policy.PeerPort {
		return nil, false
	}
	inner = inner[:length]
	if binary.BigEndian.Uint16(inner[6:]) != 0 {
		source, destination := policy.PeerIP.To4(), policy.LocalIP.To4()
		if source == nil || destination == nil {
			return nil, false
		}
		sum := uint32(ipProtoUDP) + uint32(length)
		for _, b := range [][]byte{source, destination, inner} {
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
		if uint16(sum) != 65535 {
			return nil, false
		}
	}
	return inner[udpHeaderLen:], true
}

// isIKE reports whether a datagram on the shared NAT-T port is an IKE message
// (four leading zero octets) rather than an ESP packet, and returns the message
// with the marker stripped.
func isIKE(pkt []byte) ([]byte, bool) {
	if len(pkt) >= nonESPMarkerLen && pkt[0] == 0 && pkt[1] == 0 && pkt[2] == 0 && pkt[3] == 0 {
		return pkt[nonESPMarkerLen:], true
	}
	return nil, false
}

// markIKE prepends the non-ESP marker to an IKE message for the shared port.
func markIKE(msg []byte) []byte {
	out := make([]byte, nonESPMarkerLen+len(msg))
	copy(out[nonESPMarkerLen:], msg)
	return out
}
