package l2tp

import (
	"encoding/binary"
	"fmt"
	"github.com/wanan9999/veepin/dataplane"
	"github.com/wanan9999/veepin/internal/ppp"
)

// sendIPv4 enforces the negotiated MRU for the OS-TUN path as well as the
// userspace device. DF packets get the existing PMTU response; other IPv4
// packets are fragmented with copied options and offsets per RFC 791.
func sendIPv4(t *Tunnel, packet []byte, mtu, pad int, feedback func([]byte)) error {
	packet = dataplane.TrimToIP(packet)
	if len(packet) < 20 || packet[0]>>4 != 4 || mtu < 68 {
		return nil
	}
	if len(packet) <= mtu {
		return t.SendPPP(ppp.EncapsulateIPPadded(packet, min(pad, mtu)))
	}
	if dataplane.NeedsFragmentation(packet, mtu) {
		if reply := dataplane.FragNeeded(packet, mtu); reply != nil {
			feedback(reply)
		}
		return nil
	}
	ihl := int(packet[0]&15) * 4
	if ihl < 20 || ihl > len(packet) {
		return nil
	}
	copied := make([]byte, 0, 40)
	for opts := packet[20:ihl]; len(opts) > 0; {
		if opts[0] == 0 {
			break
		}
		if opts[0] == 1 {
			opts = opts[1:]
			continue
		}
		if len(opts) < 2 || opts[1] < 2 || int(opts[1]) > len(opts) {
			return nil
		}
		size := int(opts[1])
		if opts[0]&128 != 0 {
			copied = append(copied, opts[:size]...)
		}
		opts = opts[size:]
	}
	for len(copied)%4 != 0 {
		copied = append(copied, 0)
	}
	originalFlags := binary.BigEndian.Uint16(packet[6:])
	baseOffset := int(originalFlags&0x1fff) * 8
	for offset := 0; offset < len(packet)-ihl; {
		headerLen := ihl
		if offset > 0 {
			headerLen = 20 + len(copied)
		}
		size := min((mtu-headerLen)&^7, len(packet)-ihl-offset)
		if size <= 0 || baseOffset+offset+size > 65535 {
			return fmt.Errorf("l2tp: invalid IPv4 fragment size")
		}
		fragment := make([]byte, headerLen+size)
		copy(fragment, packet[:20])
		if offset == 0 {
			copy(fragment[20:], packet[20:ihl])
		} else {
			copy(fragment[20:], copied)
		}
		fragment[0] = 0x40 | byte(headerLen/4)
		binary.BigEndian.PutUint16(fragment[2:], uint16(len(fragment)))
		flags := uint16((baseOffset+offset)/8) | (originalFlags & 0x2000)
		if offset+size < len(packet)-ihl {
			flags |= 0x2000
		}
		binary.BigEndian.PutUint16(fragment[6:], flags)
		fragment[10], fragment[11] = 0, 0
		var sum uint32
		for i := 0; i < headerLen; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(fragment[i:]))
		}
		for sum>>16 != 0 {
			sum = (sum & 65535) + (sum >> 16)
		}
		binary.BigEndian.PutUint16(fragment[10:], ^uint16(sum))
		copy(fragment[headerLen:], packet[ihl+offset:ihl+offset+size])
		if err := t.SendPPP(ppp.EncapsulateIP(fragment)); err != nil {
			return err
		}
		offset += size
	}
	return nil
}
