package ppp

import (
	"bytes"
	"net"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestFailureContainsACompleteMSCHAPChallenge(t *testing.T) {
	s, _, _ := auditServer(t)
	for i := range s.authChallenge {
		s.authChallenge[i] = byte(i)
	}
	failure := string(buildFailure(s.authChallenge))
	if !strings.Contains(failure, "C=000102030405060708090A0B0C0D0E0F ") {
		t.Fatal("MS-CHAPv2 Failure challenge is incomplete")
	}
}

func auditServer(t *testing.T) (*ServerSession, *serverRecordHandler, *packetCapture) {
	t.Helper()
	h := &serverRecordHandler{}
	sent := &packetCapture{}
	s := NewServer(ServerConfig{ClientIP: net.IPv4(10, 0, 0, 2), ServerIP: net.IPv4(10, 0, 0, 1), Auth: func(string) (string, bool) { return "test-only", true }}, transportFunc(func(b []byte) error { sent.add(b); return nil }), h)
	t.Cleanup(s.Close)
	return s, h, sent
}

func TestChallengeRetransmissionReusesIdentifierAndChallenge(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, _, sent := auditServer(t)
		s.mu.Lock()
		s.phase = phaseAuth
		s.sendChallenge()
		s.mu.Unlock()
		first := bytes.Clone(sent.snapshot()[0])
		time.Sleep(restartInterval)
		synctest.Wait()
		if len(sent.snapshot()) != 2 || !bytes.Equal(first, sent.snapshot()[1]) {
			t.Fatal("challenge retransmission changed or disappeared")
		}
		s.Close()
	})
}

func TestStaleRestartCallbackCannotResendReplacement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var timer restartTimer
		var pending func()
		timer.arm(func(f func()) { pending = f }, func() { t.Error("obsolete callback resent") }, func() { t.Error("obsolete callback expired") })
		time.Sleep(restartInterval)
		synctest.Wait()
		if pending == nil {
			t.Fatal("timer did not fire")
		}
		timer.stop()
		timer.arm(func(f func()) { f() }, func() {}, func() {})
		pending()
		timer.stop()
	})
}

func TestRejectedOptionMustMatchOriginalBytes(t *testing.T) {
	s, _, _ := auditServer(t)
	s.Start()
	before := bytes.Clone(s.lcpConfigReq)
	s.Receive(encodeFrame(ProtocolLCP, cpPacket{Code: codeConfigureReject, ID: s.lcpReqID, Body: marshalOptions([]option{{Type: optMagic, Value: []byte{0, 0, 0, 0}}})}.marshal()))
	if !bytes.Equal(before, s.lcpConfigReq) || s.lcpNoMagic {
		t.Fatal("accepted forged Reject")
	}
}

func TestDuplicateAuthenticationCannotChangeAccount(t *testing.T) {
	s, h, _ := auditServer(t)
	s.phase = phaseAuth
	s.sendChallenge()
	first, _, _, _ := buildResponse(s.authChallenge, "alice", "test-only")
	s.Receive(encodeFrame(ProtocolCHAP, cpPacket{Code: chapResponse, ID: s.authID, Body: first}.marshal()))
	second, _, _, _ := buildResponse(s.authChallenge, "bob", "test-only")
	s.Receive(encodeFrame(ProtocolCHAP, cpPacket{Code: chapResponse, ID: s.authID, Body: second}.marshal()))
	if h.username != "alice" {
		t.Fatal("account changed after authentication")
	}
}

func TestUnsupportedQualityIsRejectedAndMRUIsRetained(t *testing.T) {
	s, _, sent := auditServer(t)
	s.Receive(encodeFrame(ProtocolLCP, cpPacket{Code: codeConfigureRequest, ID: 9, Body: marshalOptions([]option{{Type: optQuality, Value: []byte{0xc0, 0x25, 0, 0, 0, 1}}})}.marshal()))
	_, body, _ := decodeFrame(sent.snapshot()[0])
	pkt, _ := parseCP(body)
	if pkt.Code != codeConfigureReject {
		t.Fatal("accepted unimplemented quality protocol")
	}
	s.Receive(encodeFrame(ProtocolLCP, cpPacket{Code: codeConfigureRequest, ID: 10, Body: marshalOptions([]option{{Type: optMRU, Value: []byte{2, 64}}})}.marshal()))
	if s.peerMRU != 576 {
		t.Fatal("peer MRU discarded")
	}
}
func TestStandardsAckMustMatchBody(t *testing.T) {
	s, _, _ := auditServer(t)
	s.Start()
	s.Receive(encodeFrame(ProtocolLCP, cpPacket{Code: codeConfigureAck, ID: s.lcpReqID}.marshal()))
	if s.lcpLocalOpen {
		t.Fatal("accepted empty Ack for nonempty LCP request")
	}
}
func TestStandardsUnknownIPCPMustReject(t *testing.T) {
	s, _, sent := auditServer(t)
	s.phase = phaseIPCP
	s.Receive(encodeFrame(ProtocolIPCP, cpPacket{Code: codeConfigureRequest, ID: 7, Body: marshalOptions([]option{{Type: 250, Value: []byte{1}}})}.marshal()))
	_, payload, _ := decodeFrame(sent.snapshot()[0])
	p, _ := parseCP(payload)
	if p.Code != codeConfigureReject {
		t.Fatalf("unknown IPCP option response code=%d, want Reject", p.Code)
	}
}
func TestStandardsMagicNakMustNotRejectAuthentication(t *testing.T) {
	s, _, _ := auditServer(t)
	s.Start()
	s.Receive(encodeFrame(ProtocolLCP, cpPacket{Code: codeConfigureNak, ID: s.lcpReqID, Body: marshalOptions([]option{{Type: optMagic, Value: []byte{1, 2, 3, 4}}})}.marshal()))
	if s.phase == phaseClosed {
		t.Fatal("valid Magic-Number Nak closed authentication")
	}
}
func TestStandardsCHAPIdentifierMustMatch(t *testing.T) {
	s, h, _ := auditServer(t)
	s.phase = phaseAuth
	s.sendChallenge()
	body, _, _, err := buildResponse(s.authChallenge, "audit", "test-only")
	if err != nil {
		t.Fatal(err)
	}
	s.Receive(encodeFrame(ProtocolCHAP, cpPacket{Code: chapResponse, ID: s.reqID + 1, Body: body}.marshal()))
	if h.authed {
		t.Fatal("accepted response with wrong CHAP identifier")
	}
}
func TestStandardsRepeatedCHAPMustNotRestartIPCP(t *testing.T) {
	s, _, _ := auditServer(t)
	s.phase = phaseAuth
	s.sendChallenge()
	id := s.reqID
	body, _, _, err := buildResponse(s.authChallenge, "audit", "test-only")
	if err != nil {
		t.Fatal(err)
	}
	frame := encodeFrame(ProtocolCHAP, cpPacket{Code: chapResponse, ID: id, Body: body}.marshal())
	s.Receive(frame)
	s.phase = phaseUp
	s.Receive(frame)
	if s.phase != phaseUp {
		t.Fatal("duplicate CHAP response restarted IPCP instead of cached Success")
	}
}

type packetCapture struct {
	mu     sync.Mutex
	frames [][]byte
}

func (c *packetCapture) add(b []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.frames = append(c.frames, append([]byte(nil), b...))
}
func (c *packetCapture) snapshot() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.frames...)
}
