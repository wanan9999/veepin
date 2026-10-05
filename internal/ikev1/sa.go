package ikev1

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"iter"
)

// Attribute order and integer encoding may differ, values and presence may
// not (RFC 2409 section 5 and Appendix A). Lifetime unit/duration pairing is
// separately validated by proposalLifetimes before this comparison.
func matchesOfferedTransform(selected parsedTransform, offer []byte) bool {
	proposals, err := parseSA(offer)
	if err != nil {
		return false
	}
	var proto uint8
	var transforms []parsedTransform
	for p := range standaloneProposals(proposals) {
		if p.number == selected.proposal {
			proto, transforms = p.proto, p.transforms
			break
		}
	}
	typeID, durationID := uint16(attrLifeType), uint16(attrLifeDuration)
	if proto == protoESP {
		typeID, durationID = ipsecAttrLifeType, ipsecAttrLifeDuration
	}
	seconds, kilobytes, valid := proposalLifetimes(selected.attrs, typeID, durationID)
	if !valid {
		return false
	}
	for _, t := range transforms {
		if selected.proposal != t.proposal || selected.num != t.num || selected.id != t.id || len(selected.attrs) != len(t.attrs) {
			continue
		}
		// Comparing attributes as a set must not permit swapping durations
		// between seconds and kilobytes.
		offerSeconds, offerKilobytes, ok := proposalLifetimes(t.attrs, typeID, durationID)
		if !ok || seconds != offerSeconds || kilobytes != offerKilobytes {
			continue
		}
		used := make([]bool, len(t.attrs))
		for _, a := range selected.attrs {
			found := false
			for i, b := range t.attrs {
				if !used[i] && a.typ == b.typ && bytes.Equal(bytes.TrimLeft(a.value, "\x00"), bytes.TrimLeft(b.value, "\x00")) {
					used[i], found = true, true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	}
	return false
}

// ikeProposal is a phase-1 (IKE SA) cipher suite. veepin pins a small set — the
// initiator offers them in preference order and the responder selects the first
// it also supports.
type ikeProposal struct {
	encr        uint16 // encrAES
	keyBits     uint16 // AES key length in bits
	hash        uint16 // hashSHA2256 / hashSHA
	group       uint16 // groupMODP2048 / groupMODP1024
	auth        uint16 // authPSK
	lifeSeconds uint32
}

// defaultIKEProposals is what the initiator offers,
// preferred first. AES-256 over MODP-2048 with SHA2-256, then a SHA-1 fallback
// for older native clients. Only MODP-2048 is offered — the sole finite-field
// group cryptoutil implements; MODP-1024 (group 2) can be added there if a stock
// client requires it.
//
// auth is the authentication method the profile runs: plain PSK, or
// XAUTHInitPreShared where extended authentication follows phase 1.
func defaultIKEProposals(auth uint16) []ikeProposal {
	return []ikeProposal{
		{encr: encrAES, keyBits: 256, hash: hashSHA2256, group: groupMODP2048, auth: auth, lifeSeconds: 3600},
		{encr: encrAES, keyBits: 256, hash: hashSHA, group: groupMODP2048, auth: auth, lifeSeconds: 3600},
	}
}

func (p ikeProposal) attrs() []byte {
	attrs := []attr{
		basicAttr(attrEncryption, p.encr),
		basicAttr(attrKeyLength, p.keyBits),
		basicAttr(attrHash, p.hash),
		basicAttr(attrGroup, p.group),
		basicAttr(attrAuthMethod, p.auth),
		basicAttr(attrLifeType, lifeTypeSeconds),
		varAttr(attrLifeDuration, be32(p.lifeSeconds)),
	}
	return encodeAttrs(attrs)
}

// buildTransform renders one Transform payload (its generic header plus body).
func buildTransform(next, num, id uint8, attrs []byte) []byte {
	body := make([]byte, 4+len(attrs))
	body[0] = num
	body[1] = id
	copy(body[4:], attrs)
	return withGenericHeader(next, body)
}

// buildProposal renders one Proposal payload containing the given transforms
// (already rendered with generic headers). proto is ISAKMP or ESP; spi is empty
// for phase 1 and the 4-octet SPI for phase 2.
func buildProposal(next, num, proto uint8, spi []byte, ntrans uint8, transforms []byte) []byte {
	body := make([]byte, 4+len(spi)+len(transforms))
	body[0] = num
	body[1] = proto
	body[2] = uint8(len(spi))
	body[3] = ntrans
	copy(body[4:], spi)
	copy(body[4+len(spi):], transforms)
	return withGenericHeader(next, body)
}

// withGenericHeader prepends the 4-octet generic payload header. The Next Payload
// field is set by the caller (transforms chain with 3, proposals/last with 0).
func withGenericHeader(next uint8, body []byte) []byte {
	out := make([]byte, 4+len(body))
	out[0] = next
	binary.BigEndian.PutUint16(out[2:], uint16(4+len(body)))
	copy(out[4:], body)
	return out
}

// buildPhase1SA renders the SA payload body (DOI, Situation, one Proposal with
// all offered transforms) for Main Mode.
func buildPhase1SA(proposals []ikeProposal) []byte {
	var transforms []byte
	for i, p := range proposals {
		next := uint8(payloadTransform)
		if i == len(proposals)-1 {
			next = payloadNone
		}
		transforms = append(transforms, buildTransform(next, uint8(i+1), transformKeyIKE, p.attrs())...)
	}
	prop := buildProposal(payloadNone, 1, protoISAKMP, nil, uint8(len(proposals)), transforms)
	return append(saPrefix(), prop...)
}

// buildSelectedSA preserves the selected offer's attributes, including absent
// optional attributes and lifetime encodings (RFC 2409 section 5). Local
// lifetime limits are enforced by the timers, never by rewriting this offer.
func buildSelectedSA(proto uint8, spi []byte, selected parsedTransform) []byte {
	tr := buildTransform(payloadNone, selected.num, selected.id, encodeAttrs(selected.attrs))
	return append(saPrefix(), buildProposal(payloadNone, selected.proposal, proto, spi, 1, tr)...)
}

// saPrefix is the DOI + Situation that opens every IPsec-DOI SA payload body.
func saPrefix() []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b[0:], doiIPsec)
	binary.BigEndian.PutUint32(b[4:], situationIdentityOnly)
	return b
}

// parsedTransform is one transform decoded from an SA payload: its number and
// attributes.
type parsedTransform struct {
	proposal uint8
	num      uint8
	id       uint8
	attrs    []attr
}

// parsedProposal keeps each alternative's SPI and transforms together. Equal
// proposal numbers form an inseparable protocol bundle (RFC 2408 section 4.2).
type parsedProposal struct {
	number     uint8
	proto      uint8
	spi        []byte
	transforms []parsedTransform
}

// parseSA validates the whole proposal/transform chain before selection. A
// later malformed proposal cannot be hidden behind an acceptable first one.
func parseSA(body []byte) ([]parsedProposal, error) {
	if len(body) < 8 {
		return nil, fmt.Errorf("ikev1: SA body too short")
	}
	if binary.BigEndian.Uint32(body[:4]) != doiIPsec || binary.BigEndian.Uint32(body[4:8]) != situationIdentityOnly {
		return nil, fmt.Errorf("ikev1: unsupported DOI or situation")
	}
	chain := body[8:]
	if len(chain) == 0 {
		return nil, fmt.Errorf("ikev1: SA without a proposal")
	}
	var proposals []parsedProposal
	var lastProposal uint8
	for len(chain) != 0 {
		if len(chain) < 8 {
			return nil, fmt.Errorf("ikev1: truncated proposal")
		}
		size := int(binary.BigEndian.Uint16(chain[2:]))
		if size < 8 || size > len(chain) {
			return nil, fmt.Errorf("ikev1: proposal length out of range")
		}
		next := uint8(payloadNone)
		if size < len(chain) {
			next = payloadProposal
		}
		if chain[0] != next || chain[4] < lastProposal {
			return nil, fmt.Errorf("ikev1: invalid proposal chain")
		}
		lastProposal = chain[4]
		prop := chain[4:size]
		spiSize, ntrans := int(prop[2]), int(prop[3])
		if ntrans == 0 {
			return nil, fmt.Errorf("ikev1: empty proposal")
		}
		if len(prop) < 4+spiSize {
			return nil, fmt.Errorf("ikev1: proposal SPI overruns")
		}
		p := parsedProposal{number: prop[0], proto: prop[1], spi: prop[4 : 4+spiSize]}
		tchain := prop[4+spiSize:]
		var lastTransform uint8
		for i := range ntrans {
			if len(tchain) < 8 {
				return nil, fmt.Errorf("ikev1: truncated transform")
			}
			size := int(binary.BigEndian.Uint16(tchain[2:]))
			if size < 8 || size > len(tchain) {
				return nil, fmt.Errorf("ikev1: transform length out of range")
			}
			next := uint8(payloadNone)
			if i < ntrans-1 {
				next = payloadTransform
			}
			if tchain[0] != next || (i > 0 && tchain[4] <= lastTransform) {
				return nil, fmt.Errorf("ikev1: invalid transform chain")
			}
			lastTransform = tchain[4]
			attrs, err := parseAttrs(tchain[8:size])
			if err != nil {
				return nil, err
			}
			p.transforms = append(p.transforms, parsedTransform{proposal: p.number, num: tchain[4], id: tchain[5], attrs: attrs})
			tchain = tchain[size:]
		}
		if len(tchain) != 0 {
			return nil, fmt.Errorf("ikev1: trailing transform data")
		}
		proposals = append(proposals, p)
		chain = chain[size:]
	}
	return proposals, nil
}

// parseSingleProposalSA enforces RFC 2409 section 5 for phase one and validates
// selected responses to our own single-protocol offers.
func parseSingleProposalSA(body []byte) (uint8, []byte, []parsedTransform, error) {
	proposals, err := parseSA(body)
	if err != nil {
		return 0, nil, nil, err
	}
	if len(proposals) != 1 {
		return 0, nil, nil, fmt.Errorf("ikev1: expected one proposal")
	}
	p := proposals[0]
	return p.proto, p.spi, p.transforms, nil
}

// standaloneProposals excludes every member of a multi-protocol AND bundle.
// Unsupported suites may be skipped only as a whole, never silently weakened.
func standaloneProposals(proposals []parsedProposal) iter.Seq[parsedProposal] {
	return func(yield func(parsedProposal) bool) {
		for i, p := range proposals {
			if i > 0 && proposals[i-1].number == p.number || i+1 < len(proposals) && proposals[i+1].number == p.number {
				continue
			}
			if !yield(p) {
				return
			}
		}
	}
}

func (s *Session) selectIKEOffer(body []byte) (ikeProposal, parsedTransform, error) {
	proto, spi, transforms, err := parseSingleProposalSA(body)
	if err != nil {
		return ikeProposal{}, parsedTransform{}, err
	}
	if proto != protoISAKMP || len(spi) != 0 {
		return ikeProposal{}, parsedTransform{}, fmt.Errorf("ikev1: phase-1 SA malformed")
	}
	if suite, transform, ok := s.selectIKEProposal(transforms); ok {
		return suite, transform, nil
	}
	return ikeProposal{}, parsedTransform{}, fmt.Errorf("ikev1: no acceptable IKE proposal offered")
}

func (s *Session) selectESPOffer(body []byte) (espProposal, parsedTransform, []byte, error) {
	proposals, err := parseSA(body)
	if err != nil {
		return espProposal{}, parsedTransform{}, nil, err
	}
	for p := range standaloneProposals(proposals) {
		if p.proto != protoESP || len(p.spi) != 4 {
			continue
		}
		if suite, transform, ok := s.selectESPProposal(p.transforms); ok {
			return suite, transform, p.spi, nil
		}
	}
	return espProposal{}, parsedTransform{}, nil, fmt.Errorf("ikev1: no acceptable ESP proposal offered")
}

// espProposal is a phase-2 (IPsec ESP) cipher suite for Quick Mode.
type espProposal struct {
	transformID   uint8  // espTransformAES
	keyBits       uint16 // AES key length in bits
	authAlg       uint16 // authHMACSHA2256 / authHMACSHA
	encap         uint16 // encapUDPTransport
	lifeSeconds   uint32
	lifeKilobytes uint32
}

func (p espProposal) attrs() []byte {
	attrs := []attr{
		basicAttr(ipsecAttrEncapMode, p.encap),
		basicAttr(ipsecAttrAuthAlg, p.authAlg),
		basicAttr(ipsecAttrKeyLength, p.keyBits),
		basicAttr(ipsecAttrLifeType, lifeTypeSeconds),
		varAttr(ipsecAttrLifeDuration, be32(p.lifeSeconds)),
	}
	if p.lifeKilobytes != 0 {
		attrs = append(attrs, basicAttr(ipsecAttrLifeType, 2), varAttr(ipsecAttrLifeDuration, be32(p.lifeKilobytes)))
	}
	return encodeAttrs(attrs)
}

// buildPhase2SA renders an ESP SA payload body carrying spi and the given ESP
// proposals (all offered when initiating, the single chosen one when replying).
func buildPhase2SA(spi uint32, props []espProposal) []byte {
	var transforms []byte
	for i, p := range props {
		next := uint8(payloadTransform)
		if i == len(props)-1 {
			next = payloadNone
		}
		transforms = append(transforms, buildTransform(next, uint8(i+1), p.transformID, p.attrs())...)
	}
	prop := buildProposal(payloadNone, 1, protoESP, be32(spi), uint8(len(props)), transforms)
	return append(saPrefix(), prop...)
}

func be32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}
