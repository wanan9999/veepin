package l2tp

import "fmt"

// validateControl checks the RFC 2661 message contract before state changes.
// Optional unknown AVPs are ignored; unsupported mandatory capabilities are
// rejected, never acknowledged as if they had been implemented.
func validateControl(mt uint16, avps []avp) error {
	var required []uint16
	switch mt {
	case msgSCCRQ, msgSCCRP:
		required = []uint16{avpProtocolVersion, avpFramingCapabilities, avpHostName, avpAssignedTunnelID}
	case msgSCCCN, msgHELLO:
	case msgStopCCN:
		required = []uint16{avpResultCode, avpAssignedTunnelID}
	case msgICRQ:
		required = []uint16{avpAssignedSessionID, avpCallSerialNumber}
	case msgICRP:
		required = []uint16{avpAssignedSessionID}
	case msgICCN:
		required = []uint16{avpTxConnectSpeed, avpFramingType}
	case msgCDN:
		required = []uint16{avpResultCode, avpAssignedSessionID}
	case 16: // Set-Link-Info: ACCM has no effect on this synchronous PPP carrier.
		required = []uint16{35}
	default:
		return fmt.Errorf("l2tp: unsupported control message %d", mt)
	}
	seen := make(map[uint16]bool, len(avps))
	for _, a := range avps {
		minLen, maxLen := 0, 0
		if a.vendorID == 0 {
			switch a.typ {
			case avpMessageType, avpProtocolVersion, 6, avpAssignedTunnelID, avpReceiveWindowSize, avpAssignedSessionID:
				minLen, maxLen = 2, 2
			case avpFramingCapabilities, 4, avpCallSerialNumber, avpFramingType, 18, avpTxConnectSpeed, 38:
				minLen, maxLen = 4, 4
			case avpHostName, 8, 21, 22, 23:
				minLen, maxLen = 1, 1017
			case avpResultCode:
				minLen, maxLen = 2, 1017
			case avpSequencingRequired:
				if mt != msgICCN {
					return fmt.Errorf("l2tp: misplaced Sequencing Required")
				}
				minLen, maxLen = 0, 0
			case 35:
				minLen, maxLen = 10, 10
			default:
				minLen = -1
			}
		} else {
			minLen = -1
		}
		if minLen < 0 {
			if a.mandatory {
				return fmt.Errorf("l2tp: unsupported mandatory AVP %d:%d", a.vendorID, a.typ)
			}
			continue
		}
		if seen[a.typ] || len(a.value) < minLen || len(a.value) > maxLen {
			return fmt.Errorf("l2tp: invalid AVP %d", a.typ)
		}
		seen[a.typ] = true
	}
	for _, typ := range required {
		if !seen[typ] {
			return fmt.Errorf("l2tp: missing required AVP %d", typ)
		}
	}
	if v, ok := findAVP(avps, avpProtocolVersion); ok && (v[0] != 1 || v[1] != 0) {
		return fmt.Errorf("l2tp: unsupported protocol version")
	}
	for _, typ := range []uint16{avpAssignedTunnelID, avpAssignedSessionID, avpReceiveWindowSize} {
		if v, ok := findUint16(avps, typ); ok && v == 0 {
			return fmt.Errorf("l2tp: zero AVP %d", typ)
		}
	}
	return nil
}
