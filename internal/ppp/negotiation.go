package ppp

import "bytes"

// RFC 1661 section 5.2 requires an exact copy, including option order.
func matchesAck(pkt cpPacket, request []byte) bool {
	req, ok := parseCP(request)
	return ok && pkt.ID == req.ID && bytes.Equal(pkt.Body, req.Body)
}

// Rejects must be an unchanged, ordered subset of the request. Naks may
// suggest values, but duplicate options and malformed lists are not replies.
func validConfigReply(pkt cpPacket, request []byte) bool {
	req, ok := parseCP(request)
	if !ok || pkt.ID != req.ID {
		return false
	}
	opts, ok := parseOptions(pkt.Body)
	if !ok || len(opts) == 0 {
		return false
	}
	offered, ok := parseOptions(req.Body)
	if !ok {
		return false
	}
	var seen [256]bool
	pos := 0
	for _, o := range opts {
		if seen[o.Type] {
			return false
		}
		seen[o.Type] = true
		if pkt.Code != codeConfigureReject {
			continue
		}
		for pos < len(offered) && offered[pos].Type != o.Type {
			pos++
		}
		if pos == len(offered) || !bytes.Equal(o.Value, offered[pos].Value) {
			return false
		}
		pos++
	}
	return true
}

func validLinkOption(o option) bool {
	switch o.Type {
	case optMRU:
		return len(o.Value) == 2
	case optMagic:
		return len(o.Value) == 4
	case optPFC, optACFC:
		return len(o.Value) == 0
	}
	return false
}
