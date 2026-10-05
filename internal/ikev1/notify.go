package ikev1

import (
	"encoding/binary"
	"fmt"
)

// Notification payloads (RFC 2408 section 3.14).
//
// IKEv1 has no separate error channel: a peer reports both failures and status
// events by sending a Notification payload, and in phase 1 it commonly arrives
// inside the very exchange type Main Mode uses. Without recognizing them, a
// notify reads as a malformed Main Mode message and the session fails with a
// misleading parse error instead of the reason the peer actually gave.
//
// Types below 16384 are errors; the caller decides whether the message is
// authenticated enough to end an exchange. Pre-key Informational errors are
// diagnostic only. The remaining types are status notifications.

const notifyStatusBase = 16384

// notifyNames covers the errors a PSK Main Mode exchange realistically draws, so
// the common misconfigurations report themselves in words.
var notifyNames = map[uint16]string{
	1:  "INVALID-PAYLOAD-TYPE",
	7:  "INVALID-EXCHANGE-TYPE",
	8:  "INVALID-FLAGS",
	9:  "INVALID-MESSAGE-ID",
	13: "ATTRIBUTES-NOT-SUPPORTED",
	14: "NO-PROPOSAL-CHOSEN",
	17: "INVALID-KEY-INFORMATION",
	18: "INVALID-ID-INFORMATION",
	20: "INVALID-CERTIFICATE",
	23: "INVALID-HASH-INFORMATION",
	24: "AUTHENTICATION-FAILED",
	29: "UNSUPPORTED-EXCHANGE-TYPE",
	30: "UNEQUAL-PAYLOAD-LENGTHS",
}

// notifyType extracts the message type from a Notification payload body.
func notifyType(body []byte) (uint16, bool) {
	// DOI (4) | Protocol-ID (1) | SPI Size (1) | Notify Message Type (2).
	if len(body) < 8 || len(body) < 8+int(body[5]) {
		return 0, false
	}
	return binary.BigEndian.Uint16(body[6:8]), true
}

// handleNotifies inspects a message's Notification payloads. It reports an error
// for a peer-signalled failure, and otherwise reports whether the message was
// purely informational and should be ignored rather than fed to the Main Mode or
// Quick Mode handlers.
func (s *Session) handleNotifies(payloads []payload) (informational bool, err error) {
	var sawNotify bool
	for _, p := range payloads {
		if p.typ != payloadNotify {
			continue
		}
		sawNotify = true
		typ, ok := notifyType(p.body)
		if !ok {
			continue
		}
		if typ < notifyStatusBase {
			name := notifyNames[typ]
			if name == "" {
				name = fmt.Sprintf("error %d", typ)
			}
			return false, fmt.Errorf("ikev1: peer reported %s", name)
		}
		s.logger.Printf("ikev1: status notification %d from peer", typ)
	}
	// A message carrying nothing but notifications is not a step in the
	// exchange, so the state machine must not advance on it.
	if !sawNotify {
		return false, nil
	}
	for _, p := range payloads {
		switch p.typ {
		case payloadNotify, payloadVendorID:
		default:
			return false, nil
		}
	}
	return true, nil
}
