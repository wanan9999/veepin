package ikev1

import (
	"bytes"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/wanan9999/veepin/internal/vlog"
)

// Windows offers an eight-hour SA and rejects an MM2 that rewrites it to
// one hour. Use a literal selected transform, independent of our encoder.
func TestWindowsOfferIsReturnedWithoutAttributeChanges(t *testing.T) {
	// Synthetic SA: proposal 1, transform 3, AES-256/SHA1/MODP2048/PSK,
	// lifetime 28800. No production identity, cookie or credential is retained.
	offer := wireHex(t, "00000001000000010000003001010001000000280301000080010007800e0100800200028004000e80030001800b0001000c000400007080")
	var reply []byte
	s := NewSession(Config{Role: Responder, IKELifetime: time.Hour, PSK: []byte("test-only"), Handler: newCapture(), Send: func(p []byte, _ bool) error { reply = bytes.Clone(p); return nil }})
	defer s.Close()
	first, body := payloadChain(append([]payload{{typ: payloadSA, body: offer}}, natTVendorPayloads()...))
	if err := s.respHandleMM1(header{initCookie: [8]byte{1}}, first, body); err != nil {
		t.Fatal(err)
	}
	_, first, body, err := parseHeader(reply)
	if err != nil {
		t.Fatal(err)
	}
	ps, _, err := parsePayloads(first, body)
	if err != nil {
		t.Fatal(err)
	}
	sa, ok := findPayload(ps, payloadSA)
	if !ok || !bytes.Equal(sa.body, offer) {
		t.Fatalf("MM2 changed selected offer: %x", sa.body)
	}
	if s.prop.lifeSeconds != 28800 {
		t.Fatal("wire lifetime was replaced by local policy")
	}
}

func TestUnsupportedAndDuplicateProposalAttributesAreRejected(t *testing.T) {
	p := defaultIKEProposals(authPSK)[0]
	attrs, _ := parseAttrs(p.attrs())
	for _, extra := range []attr{basicAttr(999, 1), basicAttr(attrEncryption, encrAES)} {
		if _, ok := ikePropFromAttrs(append(append([]attr(nil), attrs...), extra)); ok {
			t.Fatal("unsupported or ambiguous attributes accepted")
		}
	}
}

func TestPreKeyInformationalIsLoggedWithoutChangingSession(t *testing.T) {
	var logs bytes.Buffer
	s := NewSession(Config{Role: Responder, Handler: newCapture(), Logger: vlog.From(slog.New(slog.NewTextHandler(&logs, nil)))})
	defer s.Close()
	s.state = stWaitMM3
	s.initCookie, s.respCookie = [8]byte{1}, [8]byte{2}
	// A peer rejection before authentication is diagnostic, not authority to
	// close a session. Spoofed plaintext must not become a disconnect primitive.
	n := append([]byte{0, 0, 0, 1, protoISAKMP, 16, 0, 14}, s.initCookie[:]...)
	n = append(n, s.respCookie[:]...)
	packet := marshalMessage(s.mmHeader(exchangeInformational, 0, 42), []payload{{typ: payloadNotify, body: n}})
	s.HandleInbound(packet)
	if s.state != stWaitMM3 || !strings.Contains(logs.String(), "unauthenticated informational") || !strings.Contains(logs.String(), "NO-PROPOSAL-CHOSEN") {
		t.Fatalf("rejection not safely diagnosed: state=%v log=%s", s.state, logs.String())
	}
}

func TestSelectedOfferPreservesOmittedAndVolumeLifetimes(t *testing.T) {
	for _, raw := range [][]byte{wireHex(t, tunnelForgeIKE), wireHex(t, tunnelForgeESP)} {
		proto, spi, ts, err := parseSA(raw)
		if err != nil {
			t.Fatal(err)
		}
		_, _, selected, err := parseSA(buildSelectedSA(proto, spi, ts[0]))
		if err != nil || !bytes.Equal(encodeAttrs(selected[0].attrs), encodeAttrs(ts[0].attrs)) {
			t.Fatalf("omitted attributes were inserted: %v", err)
		}
	}
	p := espProposal{transformID: espTransformAES, keyBits: 256, authAlg: authHMACSHA, encap: encapUDPTransport, lifeSeconds: 28800, lifeKilobytes: 500000}
	attrs, _ := parseAttrs(p.attrs())
	ts := []parsedTransform{{proposal: 1, num: 3, id: espTransformAES, attrs: attrs}}
	_, _, selected, err := parseSA(buildSelectedSA(protoESP, be32(42), ts[0]))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := espPropFromAttrs(selected[0].id, selected[0].attrs)
	if !ok || got != p {
		t.Fatalf("volume lifetime changed: %+v", got)
	}
}

func TestInitiatorRejectsRewrittenOffer(t *testing.T) {
	offer := buildPhase1SA(defaultIKEProposals(authPSK))
	_, _, ts, err := parseSA(offer)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"lifetime", "number", "missing", "extra"} {
		t.Run(change, func(t *testing.T) {
			s := ts[0]
			s.attrs = append([]attr(nil), s.attrs...)
			switch change {
			case "lifetime":
				s.attrs[len(s.attrs)-1] = varAttr(attrLifeDuration, be32(7200))
			case "number":
				s.num = 8
			case "missing":
				s.attrs = s.attrs[:len(s.attrs)-2]
			case "extra":
				s.attrs = append(s.attrs, basicAttr(999, 1))
			}
			if matchesOfferedTransform(s, offer) {
				t.Fatal("modified offer accepted")
			}
		})
	}
	s := ts[0]
	s.attrs = append([]attr(nil), s.attrs...)
	s.attrs[len(s.attrs)-1] = basicAttr(attrLifeDuration, 3600)
	if !matchesOfferedTransform(s, offer) {
		t.Fatal("legal lifetime encoding change rejected")
	}
}

func TestInitiatorRejectsSwappedLifetimeUnits(t *testing.T) {
	p := espProposal{transformID: espTransformAES, keyBits: 256, authAlg: authHMACSHA, encap: encapUDPTransport, lifeSeconds: 28800, lifeKilobytes: 500000}
	offer := buildPhase2SA(42, []espProposal{p})
	_, _, ts, err := parseSA(offer)
	if err != nil {
		t.Fatal(err)
	}
	s := ts[0]
	if !matchesOfferedTransform(s, offer) {
		t.Fatal("unchanged lifetime pairs rejected")
	}
	s.attrs[4], s.attrs[6] = s.attrs[6], s.attrs[4]
	if matchesOfferedTransform(s, offer) {
		t.Fatal("swapped lifetime durations accepted")
	}
}

func TestMalformedProposalStructureIsRejected(t *testing.T) {
	for _, offset := range []int{3, 7, 8, 12, 15, 16, 20} {
		offer := buildPhase1SA(defaultIKEProposals(authPSK))
		// DOI, situation, proposal chain/number/count and transform chain/number.
		offer[offset] = 0xff
		if offset == 12 {
			offer[offset] = 0 // Proposal numbers begin at one.
		}
		if _, _, _, err := parseSA(offer); err == nil {
			t.Fatalf("malformed structure accepted at offset %d", offset)
		}
	}
}

func TestDifferentLocalLifetimesDoNotRewriteNegotiation(t *testing.T) {
	for _, mode := range []Mode{ModeMain, ModeAggressive} {
		a, b := newCapture(), newCapture()
		toA, toB := make(chan []byte, 32), make(chan []byte, 32)
		cfg := Config{Mode: mode, Role: Initiator, ManageLifetime: true, IKELifetime: 8 * time.Hour, ESPLifetime: 8 * time.Hour, PSK: []byte("test-only"), LocalIP: net.IPv4(192, 0, 2, 1), PeerIP: net.IPv4(192, 0, 2, 2), Handler: a, Send: func(p []byte, _ bool) error { toB <- bytes.Clone(p); return nil }}
		i := NewSession(cfg)
		cfg.Role, cfg.Handler = Responder, b
		cfg.IKELifetime, cfg.ESPLifetime = time.Hour, time.Hour
		cfg.LocalIP, cfg.PeerIP = cfg.PeerIP, cfg.LocalIP
		cfg.Send = func(p []byte, _ bool) error { toA <- bytes.Clone(p); return nil }
		r := NewSession(cfg)
		done := make(chan struct{})
		go pumpIKE(done, toA, i)
		go pumpIKE(done, toB, r)
		t.Cleanup(func() { close(done); i.Close(); r.Close() })
		i.Start()
		ir, rr := waitResult(t, "initiator", a), waitResult(t, "responder", b)
		if ir.Lifetime != 8*time.Hour || rr.Lifetime != time.Hour {
			t.Fatalf("local ESP lifetime: %v / %v", ir.Lifetime, rr.Lifetime)
		}
		r.mu.Lock()
		remaining := time.Until(r.ikeDeadline)
		r.mu.Unlock()
		if remaining > time.Hour || remaining < 59*time.Minute {
			t.Fatalf("local IKE deadline: %v", remaining)
		}
	}
}
