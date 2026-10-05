package ikev1

import (
	"encoding/binary"
	"net"
)

// identity is a decoded Identification payload body (RFC 2407 section 4.6.2).
type identity struct {
	idType uint8
	proto  uint8
	port   uint16
	data   []byte
}

// buildID renders an Identification payload body: ID Type, Protocol ID, Port,
// then the identity data.
func buildID(id identity) []byte {
	out := make([]byte, 4+len(id.data))
	out[0] = id.idType
	out[1] = id.proto
	binary.BigEndian.PutUint16(out[2:], id.port)
	copy(out[4:], id.data)
	return out
}

// ipv4ID is a phase-1 identity: an IPv4 address with no protocol/port constraint.
func ipv4ID(ip net.IP) identity {
	v4 := ip.To4()
	if v4 == nil {
		v4 = net.IPv4zero.To4()
	}
	return identity{idType: idIPv4Addr, data: v4}
}

// l2tpSelector is a phase-2 traffic selector for L2TP/IPsec transport mode: an
// IPv4 host with protocol UDP on the L2TP port, which is exactly the traffic the
// transport SA protects.
func l2tpSelector(ip net.IP) identity {
	id := ipv4ID(ip)
	id.proto = ipProtoUDP
	id.port = l2tpPort
	return id
}

// anySubnetID is the remote-access gateway-side traffic selector: 0.0.0.0/0 as
// an ID_IPV4_ADDR_SUBNET, which is a network followed by its mask. It says the
// tunnel carries everything, and it is what a client's default route through the
// gateway is expressed as in phase 2.
func anySubnetID() identity {
	return identity{idType: idIPv4AddrSubnet, data: make([]byte, 2*net.IPv4len)}
}

// NAT-T phase-1 identities carry port zero (RFC 3947 section 4).
func validPhase1ID(body []byte) bool {
	if len(body) < 4 || binary.BigEndian.Uint16(body[2:]) != 0 {
		return false
	}
	switch body[0] {
	case idIPv4Addr:
		return len(body) == 8
	case 5:
		return len(body) == 20 // ID_IPV6_ADDR
	case idFQDN, idUserFQDN, idKeyID:
		return len(body) > 4
	}
	return false
}
