package ikev1

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

// TransportPolicy binds the authenticated Quick Mode selectors and original
// addresses to one ESP SA. Ports of zero denote the DOI's wildcard port.
type TransportPolicy struct {
	LocalPort, PeerPort uint16
	LocalIP, PeerIP     net.IP
}

func (s *Session) originalAddresses() []payload {
	if s.cfg.Phase2 != Phase2L2TP {
		return nil
	}
	local, peer := s.cfg.LocalIP.To4(), s.cfg.PeerIP.To4()
	if local == nil {
		local = net.IPv4zero.To4()
	}
	if peer == nil {
		peer = net.IPv4zero.To4()
	}
	if s.cfg.Role == Responder {
		local, peer = peer, local
	}
	return []payload{{typ: payloadNATOA, body: append([]byte{idIPv4Addr, 0, 0, 0}, local...)}, {typ: payloadNATOA, body: append([]byte{idIPv4Addr, 0, 0, 0}, peer...)}}
}

func (s *Session) acceptSelectors(ps []payload, reply bool) error {
	var ids, originals [][]byte
	for _, p := range ps {
		if p.typ == payloadID {
			ids = append(ids, p.body)
		}
		if p.typ == payloadNATOA {
			originals = append(originals, p.body)
		}
	}
	if len(ids) != 0 && len(ids) != 2 {
		return fmt.Errorf("ikev1: Quick Mode requires a pair of selectors")
	}
	if reply {
		if len(ids) != 2 || !bytes.Equal(ids[0], s.qmLocalID) || !bytes.Equal(ids[1], s.qmPeerID) {
			return fmt.Errorf("ikev1: responder changed traffic selectors")
		}
	}
	if s.cfg.Phase2 != Phase2L2TP {
		return nil
	}
	if len(ids) == 0 {
		ids = [][]byte{buildID(ipv4ID(s.cfg.PeerIP)), buildID(ipv4ID(s.cfg.LocalIP))}
	}
	for _, id := range ids {
		if len(id) != 8 || id[0] != idIPv4Addr || (id[1] != 0 && id[1] != ipProtoUDP) || (id[1] == 0 && binary.BigEndian.Uint16(id[2:]) != 0) {
			return fmt.Errorf("ikev1: unsupported L2TP transport selector")
		}
	}
	local, peer := ids[1], ids[0]
	if s.cfg.Role == Initiator {
		local, peer = ids[0], ids[1]
	}
	// A responder protects the configured L2TP listener, not arbitrary services.
	if s.cfg.Role == Responder && binary.BigEndian.Uint16(local[2:]) != 0 && binary.BigEndian.Uint16(local[2:]) != l2tpPort {
		return fmt.Errorf("ikev1: selector does not name the L2TP listener")
	}
	if ip := s.cfg.LocalIP.To4(); ip != nil && !ip.IsUnspecified() && !net.IP(local[4:]).Equal(ip) {
		return fmt.Errorf("ikev1: selector does not name the local host")
	}
	s.transport = TransportPolicy{LocalPort: binary.BigEndian.Uint16(local[2:]), PeerPort: binary.BigEndian.Uint16(peer[2:]), LocalIP: bytes.Clone(local[4:]), PeerIP: bytes.Clone(peer[4:])}
	if len(originals) != 0 {
		if len(originals) != 2 {
			return fmt.Errorf("ikev1: invalid NAT-OA pair")
		}
		for _, oa := range originals {
			if len(oa) != 8 || oa[0] != idIPv4Addr {
				return fmt.Errorf("ikev1: invalid IPv4 NAT-OA")
			}
		}
		// These are the sender's pseudo-header addresses, before any NAT rewrite.
		src, dst := originals[0][4:], originals[1][4:]
		if s.cfg.Role == Initiator {
			src, dst = dst, src
		}
		s.transport.PeerIP = bytes.Clone(src)
		s.transport.LocalIP = bytes.Clone(dst)
	}
	s.qmLocalID = bytes.Clone(local)
	s.qmPeerID = bytes.Clone(peer)
	return nil
}
