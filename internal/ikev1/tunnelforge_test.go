package ikev1

import (
	"bytes"
	"encoding/hex"
	"net"
	"testing"

	"github.com/xen0bit/veepin/internal/ikev2/esp"
)

// These SA bodies follow build_p1_sa/build_p2_esp_sa in TunnelForge's
// android/app/src/main/cpp/ikev1.c at v0.7.4
// (bf3df64da2aa24c8b0ff379614dc991fa42f3f2a).
// Keep literal wire bytes, not veepin's proposal builders: TunnelForge offers
// AES-128 first, then 3DES, and omits the lifetime attributes we normally emit.
// The ESP fixture uses the synthetic inbound SPI 0x12345678.
const tunnelForgeIKE = "00000001000000010000003c010100020300001c0101000080010007800e008080020002800300018004000e00000018020100008001000580020002800300018004000e"
const tunnelForgeESP = "000000010000000100000030010304021234567803000014010c000080040004800500028006008000000010020300008004000480050002"

func wireHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTunnelForgeProposalsSelectAES128Without3DES(t *testing.T) {
	s := NewSession(Config{Role: Responder})
	_, _, transforms, err := parseSA(wireHex(t, tunnelForgeIKE))
	if err != nil {
		t.Fatal(err)
	}
	p, num, ok := s.selectIKEProposal(transforms)
	if !ok || num != 1 || p.keyBits != 128 || p.hash != hashSHA || p.group != groupMODP2048 {
		t.Fatalf("TunnelForge IKE offer rejected or misselected: %+v, number=%d, ok=%v", p, num, ok)
	}
	if _, _, ok := s.selectIKEProposal(transforms[1:]); ok {
		t.Fatal("3DES-only IKE offer accepted")
	}
	_, _, transforms, err = parseSA(wireHex(t, tunnelForgeESP))
	if err != nil {
		t.Fatal(err)
	}
	e, num, ok := s.selectESPProposal(transforms)
	if !ok || num != 1 || e.keyBits != 128 || e.authAlg != authHMACSHA || e.encap != encapUDPTransport {
		t.Fatalf("TunnelForge ESP offer rejected or misselected: %+v, number=%d, ok=%v", e, num, ok)
	}
	if _, _, ok := s.selectESPProposal(transforms[1:]); ok {
		t.Fatal("3DES-only ESP offer accepted")
	}
}

// Only L2TP responders gain the additional key length. In particular, an
// initiator must reject a server choosing AES-128 from its AES-256-only offer.
func TestAES128CompatibilityDoesNotChangeOtherProfiles(t *testing.T) {
	for _, cfg := range []Config{
		{Role: Initiator},
		{Role: Initiator, Phase2: Phase2RemoteAccess},
		{Role: Responder, Phase2: Phase2RemoteAccess},
	} {
		s := NewSession(cfg)
		if s.supportedAESKeyBits(128) || !s.supportedAESKeyBits(256) {
			t.Fatalf("unexpected AES policy for %+v", cfg)
		}
	}
	s := NewSession(Config{Role: Responder})
	for _, bits := range []uint16{0, 64, 129, 192, 512} {
		if s.supportedAESKeyBits(bits) {
			t.Errorf("accepted unsupported key length %d", bits)
		}
	}
	p := ikeProposal{encr: encrAES, keyBits: 128, hash: hashSHA, group: groupMODP2048, auth: authPSK}
	p.group = groupMODP1024
	if s.supportedIKE(p) {
		t.Fatal("compatibility enabled MODP-1024")
	}
	p.group, p.auth = groupMODP2048, authXAuthInitPSK
	if s.supportedIKE(p) {
		t.Fatal("compatibility bypassed authentication-method matching")
	}
	if s.supportedESP(espProposal{transformID: espTransformAES, keyBits: 128, authAlg: authHMACSHA, encap: encapUDPTunnel}) {
		t.Fatal("L2TP accepted a tunnel-mode SA")
	}
}

// Drive all nine Main/Quick Mode messages using the peer's literal proposals,
// then move UDP bytes both ways with the derived ESP keys. This is a wire-level
// regression, not a claim that the Android application has been exercised.
func TestTunnelForgeAES128MainQuickModeAndESP(t *testing.T) {
	runTunnelForgeHandshake(t, false)
}

func TestTunnelForgeAES128RejectsWrongPSK(t *testing.T) {
	runTunnelForgeHandshake(t, true)
}

func runTunnelForgeHandshake(t *testing.T, wrongPSK bool) {
	t.Helper()
	result := newCapture()
	out := make(chan []byte, 16)
	authenticated := 0
	sentAfterAuthentication := 0
	s := NewSession(Config{
		Role: Responder, PSK: []byte("synthetic-interop-secret"),
		LocalIP: net.IPv4(192, 0, 2, 1), PeerIP: net.IPv4(192, 0, 2, 2),
		LocalPort: 500, PeerPort: 40000,
		Send: func(b []byte, _ bool) error {
			sentAfterAuthentication = authenticated
			out <- b
			return nil
		}, Handler: result,
	})
	process := func(b []byte) {
		s.HandleInboundAuthenticated(b, func() { authenticated++ })
	}
	t.Cleanup(func() { s.mu.Lock(); defer s.mu.Unlock(); s.advance() })
	h := header{initCookie: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, exchange: exchangeMain}
	var lastReply []byte
	receive := func() (header, uint8, []byte) {
		t.Helper()
		select {
		case err := <-result.fail:
			t.Fatal(err)
		default:
		}
		select {
		case b := <-out:
			lastReply = append([]byte(nil), b...)
			hr, first, rest, err := parseHeader(b)
			if err != nil {
				t.Fatal(err)
			}
			return hr, first, rest
		default:
			t.Fatal("responder did not send the next handshake message")
		}
		return header{}, 0, nil
	}
	decode := func(first uint8, b []byte) []payload {
		t.Helper()
		ps, _, err := parsePayloads(first, b)
		if err != nil {
			t.Fatal(err)
		}
		return ps
	}
	body := func(ps []payload, kind uint8) []byte {
		t.Helper()
		p, ok := findPayload(ps, kind)
		if !ok {
			t.Fatalf("missing payload %d", kind)
		}
		return p.body
	}
	sa := wireHex(t, tunnelForgeIKE)
	mm1 := marshalMessage(h, append([]payload{{typ: payloadSA, body: sa}}, natTVendorPayloads()...))
	process(mm1)
	hr, _, _ := receive()
	mm2Reply := append([]byte(nil), lastReply...)
	process(mm1)
	receive()
	if !bytes.Equal(mm2Reply, lastReply) {
		t.Fatal("MM1 retry did not replay MM2")
	}
	h.respCookie = hr.respCookie
	dh, err := dhGroup(groupMODP2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := dh.Generate()
	if err != nil {
		t.Fatal(err)
	}
	ni := bytes.Repeat([]byte{0x31}, 32)
	mm3 := marshalMessage(h, []payload{{typ: payloadKE, body: pub}, {typ: payloadNonce, body: ni}})
	process(mm3)
	_, first, rest := receive()
	mm4 := decode(first, rest)
	mm4Reply := append([]byte(nil), lastReply...)
	process(mm3)
	receive()
	if !bytes.Equal(mm4Reply, lastReply) {
		t.Fatal("MM3 retry did not replay MM4")
	}
	if authenticated != 0 {
		t.Fatal("unauthenticated Main Mode changed the endpoint")
	}
	peerPub := body(mm4, payloadKE)
	shared, err := dh.ComputeSecret(peerPub)
	if err != nil {
		t.Fatal(err)
	}
	prf, err := newPRF(hashSHA)
	if err != nil {
		t.Fatal(err)
	}
	newHash, err := hashCtor(hashSHA)
	if err != nil {
		t.Fatal(err)
	}
	psk := []byte("synthetic-interop-secret")
	if wrongPSK {
		psk = []byte("synthetic-wrong-secret")
	}
	keys := derivePhase1(prf, newHash, psk, ni, body(mm4, payloadNonce), shared, h.initCookie, h.respCookie, 16)
	if !bytes.Equal(keys.encKey, keys.skeyidE[:16]) {
		t.Fatal("AES-128 must truncate SKEYID_e")
	}
	keys.setInitialIV(pub, peerPub)
	sendEncrypted := func(iv *[]byte, ps []payload) []byte {
		t.Helper()
		first, plain := payloadChain(ps)
		ct, err := cbcEncrypt(keys.encKey, *iv, plain)
		if err != nil {
			t.Fatal(err)
		}
		*iv = lastBlock(ct)
		packet := assemble(h, first, ct)
		if h.exchange == exchangeMain {
			// Neither a mismatched responder cookie nor stripped encryption
			// flag can authorize a mapping update, even with valid ciphertext.
			badCookie := append([]byte(nil), packet...)
			badCookie[8] ^= 1
			process(badCookie)
			plainFlag := append([]byte(nil), packet...)
			plainFlag[19] &^= flagEncryption
			process(plainFlag)
			if authenticated != 0 {
				t.Fatal("invalid header authorized endpoint change")
			}
		}
		process(packet)
		return packet
	}
	decrypt := func(iv *[]byte) ([]payload, []byte, int) {
		t.Helper()
		_, first, ct := receive()
		plain, err := cbcDecrypt(keys.encKey, *iv, ct)
		if err != nil {
			t.Fatal(err)
		}
		*iv = lastBlock(ct)
		ps, consumed, err := parsePayloads(first, plain)
		if err != nil {
			t.Fatal(err)
		}
		return ps, plain, consumed
	}
	id := buildID(ipv4ID(net.IPv4(192, 0, 2, 2)))
	h.flags = flagEncryption
	mm5 := sendEncrypted(&keys.iv, []payload{{typ: payloadID, body: id}, {typ: payloadHash, body: keys.hashI(pub, peerPub, h.initCookie, h.respCookie, sa, id)}})
	if wrongPSK {
		if authenticated != 0 {
			t.Fatal("wrong PSK authorized endpoint change")
		}
		// A wrong PSK also changes the CBC key, so rejection may happen while
		// parsing the decrypted payload, before HASH_I can be checked.
		select {
		case err := <-result.fail:
			if err == nil {
				t.Fatal("wrong PSK returned no error")
			}
		case <-result.res:
			t.Fatal("wrong PSK established an SA")
		default:
			t.Fatal("wrong PSK was not rejected")
		}
		return
	}
	mm6, _, _ := decrypt(&keys.iv)
	if authenticated != 1 || sentAfterAuthentication != 1 {
		t.Fatal("MM6 was sent before its authenticated endpoint was committed")
	}
	// Model a lost MM6. An exact MM5 retry must return the same ciphertext,
	// preserving the CBC IV and retry budget while already waiting for QM1.
	cachedMM6 := append([]byte(nil), lastReply...)
	cachedIV := append([]byte(nil), s.keys.iv...)
	retries := s.retries
	process(mm5)
	receive()
	if !bytes.Equal(lastReply, cachedMM6) || !bytes.Equal(s.keys.iv, cachedIV) || s.retries != retries {
		t.Fatal("MM5 retransmission changed the response, CBC IV or retry budget")
	}
	if authenticated != 1 {
		t.Fatal("cached MM5 changed the endpoint again")
	}
	modified := append([]byte(nil), mm5...)
	modified[len(modified)-1] ^= 1
	process(modified)
	select {
	case <-out:
		t.Fatal("modified MM5 replayed a cached response")
	default:
	}
	if !bytes.Equal(body(mm6, payloadHash), keys.hashR(pub, peerPub, h.initCookie, h.respCookie, sa, body(mm6, payloadID))) {
		t.Fatal("responder HASH_R did not authenticate")
	}
	h.exchange, h.messageID = exchangeQuick, 0x10203040
	iv := keys.quickModeIV(h.messageID)
	qmNi := bytes.Repeat([]byte{0x42}, 32)
	content := []payload{{typ: payloadSA, body: wireHex(t, tunnelForgeESP)}, {typ: payloadNonce, body: qmNi},
		{typ: payloadID, body: buildID(l2tpSelector(net.IPv4(192, 0, 2, 2)))},
		{typ: payloadID, body: buildID(l2tpSelector(net.IPv4(192, 0, 2, 1)))}}
	_, chain := payloadChain(content)
	hash1 := prf.Apply(keys.skeyidA, concat(be32(h.messageID), chain))
	sendEncrypted(&iv, append([]payload{{typ: payloadHash, body: hash1}}, content...))
	qm2, plain, consumed := decrypt(&iv)
	if authenticated != 2 || sentAfterAuthentication != 2 {
		t.Fatal("QM2 was sent before its authenticated endpoint was committed")
	}
	if !bytes.Equal(body(qm2, payloadHash), prf.Apply(keys.skeyidA, concat(be32(h.messageID), qmNi, afterHash(plain, qm2, consumed)))) {
		t.Fatal("responder HASH(2) did not authenticate")
	}
	_, spi, transforms, err := parseSA(body(qm2, payloadSA))
	if err != nil {
		t.Fatal(err)
	}
	if len(transforms) != 1 {
		t.Fatal("responder did not select exactly one ESP transform")
	}
	chosen, ok := espPropFromAttrs(transforms[0].id, transforms[0].attrs)
	if !ok || chosen.keyBits != 128 || chosen.authAlg != authHMACSHA {
		t.Fatalf("unexpected ESP selection: %+v", chosen)
	}
	qmNr := body(qm2, payloadNonce)
	hash3 := prf.Apply(keys.skeyidA, concat([]byte{0}, be32(h.messageID), qmNi, qmNr))
	sendEncrypted(&iv, []payload{{typ: payloadHash, body: hash3}})
	r := waitResult(t, "AES-128 responder", result)
	if authenticated != 3 {
		t.Fatal("QM3 did not authenticate before establishment")
	}
	if r.EncrKeyLn != 128 || r.IntegID != espAuthHMACSHA196 || !r.NATT {
		t.Fatalf("unexpected result: %+v", r)
	}
	clientOut := keys.keymat(protoESP, spi, qmNi, qmNr, 36)
	clientIn := keys.keymat(protoESP, be32(0x12345678), qmNi, qmNr, 36)
	transform := func(enc, auth []byte) esp.Transform {
		return esp.Transform{EncrID: espEncrAESCBC, EncrKeyLn: 128, IntegID: espAuthHMACSHA196, EncKey: enc, IntegKey: auth}
	}
	clientSA := &esp.SA{SPIOut: be32ToU32(spi), SPIIn: 0x12345678, Out: transform(clientOut[:16], clientOut[16:]), In: transform(clientIn[:16], clientIn[16:])}
	serverSA := &esp.SA{SPIOut: r.OutSPI, SPIIn: r.InSPI, Out: transform(r.OutEncKey, r.OutIntegKey), In: transform(r.InEncKey, r.InIntegKey)}
	for _, pair := range [][2]*esp.SA{{clientSA, serverSA}, {serverSA, clientSA}} {
		udp := []byte{0x06, 0xa5, 0x06, 0xa5, 0, 12, 0, 0, 1, 2, 3, 4}
		packet, err := pair[0].Encapsulate(udp, 17)
		if err != nil {
			t.Fatal(err)
		}
		got, next, err := pair[1].Decapsulate(packet)
		if err != nil || next != 17 || !bytes.Equal(got, udp) {
			t.Fatalf("ESP transport round trip: %x, next=%d, err=%v", got, next, err)
		}
		packet, err = pair[0].Encapsulate(udp, 17)
		if err != nil {
			t.Fatal(err)
		}
		tampered := append([]byte(nil), packet...)
		tampered[len(tampered)-1] ^= 1
		if _, _, err := pair[1].Decapsulate(tampered); err == nil {
			t.Fatal("AES-128 ESP accepted a modified integrity tag")
		}
		if _, _, err := pair[1].Decapsulate(packet); err != nil {
			t.Fatalf("invalid packet poisoned the replay window: %v", err)
		}
	}
}
