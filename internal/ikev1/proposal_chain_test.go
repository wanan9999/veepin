package ikev1

import (
	"bytes"
	"testing"
)

// RFC 2408 section 4.2 wire fixture, independent of our proposal encoder:
// proposal 1 offers 3DES, proposal 2 offers AES-128, with distinct inbound SPIs.
// This models standard alternative proposals, not a captured client credential.
const alternativeESP = "0000000100000001" +
	"0200001c010304011122334400000010010300008004000480050002" +
	"00000020020304011234567800000014010c0000800400048005000280060080"

func TestQuickModeAlternativeProposalsAndESP(t *testing.T) {
	runAES128Handshake(t, false, wireHex(t, alternativeESP))
}

func TestQuickModeZeroNumberedProposalAndESP(t *testing.T) {
	offer := wireHex(t, tunnelForgeESP)
	offer[12] = 0
	offer[24], offer[44] = 0, 1 // The first transform may also start at zero.
	runAES128Handshake(t, false, offer)
}

func TestAlternativeProposalsPreserveSelectedSPI(t *testing.T) {
	s := &Session{cfg: Config{Role: Responder}}
	offer := wireHex(t, alternativeESP)
	suite, transform, spi, err := s.selectESPOffer(offer)
	if err != nil || suite.keyBits != 128 || transform.proposal != 2 || !bytes.Equal(spi, be32(0x12345678)) {
		t.Fatalf("wrong selection: %+v, proposal=%d, SPI=%x, error=%v", suite, transform.proposal, spi, err)
	}
	if !matchesOfferedTransform(transform, offer) {
		t.Fatal("selected alternative does not match offer")
	}
	if _, _, _, err := parseSingleProposalSA(offer); err == nil {
		t.Fatal("initiator accepted a response containing alternatives")
	}
}

func TestProposalBundlesAreNeverPartiallyAccepted(t *testing.T) {
	s := &Session{cfg: Config{Role: Responder}}
	tr := buildTransform(payloadNone, 1, espTransformAES, encodeAttrs([]attr{
		basicAttr(ipsecAttrEncapMode, encapUDPTransport), basicAttr(ipsecAttrAuthAlg, authHMACSHA), basicAttr(ipsecAttrKeyLength, 128),
	}))
	// ESP AND AH is one suite. Even if its ESP transform is supported,
	// selecting just that half would silently remove requested protection.
	for _, espFirst := range []bool{false, true} {
		first, second := uint8(2), uint8(protoESP) // IPsec AH = 2
		if espFirst {
			first, second = second, first
		}
		bundle := append(saPrefix(), buildProposal(payloadProposal, 1, first, be32(1), 1, tr)...)
		bundle = append(bundle, buildProposal(payloadNone, 1, second, be32(2), 1, tr)...)
		if _, _, _, err := s.selectESPOffer(bundle); err == nil {
			t.Fatal("accepted only part of an AND bundle")
		}
		// A separate alternative after the bundle remains usable.
		bundle[8+len(buildProposal(payloadProposal, 1, first, be32(1), 1, tr))] = payloadProposal
		bundle = append(bundle, buildProposal(payloadNone, 2, protoESP, be32(3), 1, tr)...)
		_, selected, spi, err := s.selectESPOffer(bundle)
		if err != nil || selected.proposal != 2 || !bytes.Equal(spi, be32(3)) {
			t.Fatalf("standalone alternative after bundle lost: %x, %v", spi, err)
		}
	}
}

func TestProposalChainValidatesAllBoundaries(t *testing.T) {
	offer := wireHex(t, alternativeESP)
	for n := range len(offer) {
		if _, err := parseSA(offer[:n]); err == nil {
			t.Fatalf("accepted truncated chain of %d bytes", n)
		}
	}
	for _, mutate := range []func([]byte){
		func(b []byte) { b[8] = payloadNone },
		func(b []byte) { b[36] = payloadProposal },
		func(b []byte) { b[40] = 0 },
		func(b []byte) { b[12], b[40] = 2, 1 },
		func(b []byte) { b[43] = 2 },
		func(b []byte) { b[38], b[39] = 0xff, 0xff },
	} {
		bad := bytes.Clone(offer)
		mutate(bad)
		if _, err := parseSA(bad); err == nil {
			t.Fatalf("accepted malformed chain: %x", bad)
		}
	}
	// Even an acceptable first proposal cannot hide malformed trailing data.
	bad := append(saPrefix(), offer[36:]...)
	bad[8] = payloadProposal
	bad = append(bad, 0)
	if _, _, _, err := (&Session{cfg: Config{Role: Responder}}).selectESPOffer(bad); err == nil {
		t.Fatal("selection ignored trailing bytes")
	}
}

func TestPhaseOneAlternativeProposalSelection(t *testing.T) {
	s := &Session{cfg: Config{Role: Responder}}
	p := defaultIKEProposals(authPSK)[0]
	tr := buildTransform(payloadNone, 1, transformKeyIKE, p.attrs())
	bad := bytes.Clone(tr)
	bad[5] = 255
	offer := append(saPrefix(), buildProposal(payloadProposal, 1, protoISAKMP, nil, 1, bad)...)
	offer = append(offer, buildProposal(payloadNone, 2, protoISAKMP, nil, 1, tr)...)
	_, selected, err := s.selectIKEOffer(offer)
	if err != nil || selected.proposal != 2 || !matchesOfferedTransform(selected, offer) {
		t.Fatalf("valid phase-one alternative rejected: %v", err)
	}
	zero := append(saPrefix(), buildProposal(payloadNone, 0, protoISAKMP, nil, 1, tr)...)
	zero[20] = 0
	_, selected, err = s.selectIKEOffer(zero)
	if err != nil || selected.proposal != 0 || selected.num != 0 || !matchesOfferedTransform(selected, zero) {
		t.Fatalf("zero-numbered phase-one proposal rejected: %v", err)
	}
}
