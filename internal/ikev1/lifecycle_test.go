package ikev1

import (
	"bytes"
	"encoding/binary"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func managedPair(t *testing.T, options ...func(*Config)) (*Session, *Session, *capture, *capture) {
	t.Helper()
	a, b := newCapture(), newCapture()
	a.res, b.res = make(chan Result, 64), make(chan Result, 64)
	toA, toB := make(chan []byte, 64), make(chan []byte, 64)
	cfg := Config{ManageLifetime: true, PSK: []byte("test-only-secret"), LocalIP: net.IPv4(192, 0, 2, 1), PeerIP: net.IPv4(192, 0, 2, 2), Handler: a, Send: func(p []byte, _ bool) error { toB <- bytes.Clone(p); return nil }}
	for _, option := range options {
		option(&cfg)
	}
	i := NewSession(cfg)
	cfg.Role, cfg.LocalIP, cfg.PeerIP, cfg.Handler = Responder, cfg.PeerIP, cfg.LocalIP, b
	cfg.Send = func(p []byte, _ bool) error { toA <- bytes.Clone(p); return nil }
	for _, option := range options {
		option(&cfg)
	}
	r := NewSession(cfg)
	done := make(chan struct{})
	t.Cleanup(func() { i.Close(); r.Close(); close(done) })
	go pumpIKE(done, toA, i)
	go pumpIKE(done, toB, r)
	i.Start()
	x, y := waitResult(t, "initial initiator", a), waitResult(t, "initial responder", b)
	checkMirrored(t, x, y)
	return i, r, a, b
}
func checkMirrored(t *testing.T, a, b Result) {
	t.Helper()
	if a.InSPI != b.OutSPI || a.OutSPI != b.InSPI {
		t.Fatal("SPI directions do not match")
	}
	mirror(t, "out/in", a.OutEncKey, b.InEncKey)
	mirror(t, "in/out", a.InEncKey, b.OutEncKey)
}

func TestRepeatedQuickModeAndControlSARenewal(t *testing.T) {
	i, r, a, b := managedPair(t)
	for n, peer := range []*Session{i, r, i} {
		if err := peer.Rekey(); err != nil {
			t.Fatal(err)
		}
		x, y := waitResult(t, "rekey initiator", a), waitResult(t, "rekey responder", b)
		checkMirrored(t, x, y)
		if !x.Rekey || !y.Rekey {
			t.Fatalf("exchange %d recreated initial SA", n)
		}
	}
	for _, peer := range []*Session{r, i, r} {
		if err := peer.RenewIKE(); err != nil {
			t.Fatal(err)
		}
		x, y := waitResult(t, "IKE renewal initiator", a), waitResult(t, "IKE renewal responder", b)
		checkMirrored(t, x, y)
		if err := peer.Rekey(); err != nil {
			t.Fatal(err)
		}
		checkMirrored(t, waitResult(t, "ESP after IKE", a), waitResult(t, "ESP after IKE peer", b))
	}
}

func TestLifetimeAttributesAreNotSilentlyIgnored(t *testing.T) {
	for _, tc := range []struct {
		attrs []attr
		want  uint32
		ok    bool
	}{
		{nil, 28800, true},
		{[]attr{basicAttr(attrLifeType, 1), varAttr(attrLifeDuration, be32(60))}, 60, true},
		{[]attr{basicAttr(attrLifeType, 1), basicAttr(attrLifeDuration, 20)}, 20, true},
		{[]attr{basicAttr(attrLifeType, 1)}, 0, false},
		{[]attr{basicAttr(attrLifeType, 1), varAttr(attrLifeDuration, be32(0))}, 0, false},
		{[]attr{basicAttr(attrLifeType, 2), varAttr(attrLifeDuration, be32(1024))}, 0, false},
	} {
		got, ok := proposalLifetime(tc.attrs, attrLifeType, attrLifeDuration)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Fatalf("lifetime = %d/%v, want %d/%v", got, ok, tc.want, tc.ok)
		}
	}
}

func TestExpiredSAFailsClosed(t *testing.T) {
	i, _, a, _ := managedPair(t)
	i.mu.Lock()
	i.espDeadline = time.Now().Add(-time.Second)
	i.dataDeadline.Store(i.espDeadline.UnixNano())
	i.mu.Unlock()
	i.maintain()
	select {
	case err := <-a.fail:
		if err != ErrExpired {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("expired SA remained usable")
	}
}

func TestAutomaticRenewalAcrossMultipleLifetimes(t *testing.T) {
	i, r, a, b := managedPair(t, func(c *Config) { c.IKELifetime = 4 * time.Second; c.ESPLifetime = 2 * time.Second })
	// Timers, rather than direct method calls, must keep the session usable
	// across more than two complete control-SA lifetimes.
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	var countA, countB int
	for {
		select {
		case <-a.res:
			countA++
		case <-b.res:
			countB++
		case err := <-a.fail:
			t.Fatal(err)
		case err := <-b.fail:
			t.Fatal(err)
		case <-deadline.C:
			if countA < 5 || countB < 5 {
				t.Fatalf("not enough renewals: %d/%d", countA, countB)
			}
			i.mu.Lock()
			ca := i.activeIKE
			i.mu.Unlock()
			r.mu.Lock()
			cb := r.activeIKE
			r.mu.Unlock()
			if ca == nil || cb == nil {
				t.Fatal("control SAs were not renewed")
			}
			return
		}
	}
}

func TestESPTimeAndVolumeLifetimes(t *testing.T) {
	attrs := []attr{basicAttr(ipsecAttrLifeType, 1), varAttr(ipsecAttrLifeDuration, be32(3600)), basicAttr(ipsecAttrLifeType, 2), varAttr(ipsecAttrLifeDuration, be32(250000))}
	sec, kb, ok := proposalLifetimes(attrs, ipsecAttrLifeType, ipsecAttrLifeDuration)
	if !ok || sec != 3600 || kb != 250000 {
		t.Fatalf("got %d/%d/%v", sec, kb, ok)
	}
	if _, _, ok := proposalLifetimes(append(attrs, attrs[:2]...), ipsecAttrLifeType, ipsecAttrLifeDuration); ok {
		t.Fatal("duplicate lifetime accepted")
	}
}

func TestControlExpiryDoesNotExpireDataSA(t *testing.T) {
	i, _, a, _ := managedPair(t)
	i.mu.Lock()
	i.ikeDeadline = time.Now().Add(-time.Second)
	i.renewAt = time.Now().Add(time.Hour) // isolate expiry from renewal
	i.mu.Unlock()
	i.maintain()
	select {
	case err := <-a.fail:
		t.Fatalf("valid ESP expired with IKE: %v", err)
	default:
	}
	if err := i.Rekey(); err != ErrExpired {
		t.Fatalf("expired control allowed Quick Mode: %v", err)
	}
}

func TestLostQM3IsRecoveredByDuplicateQM2(t *testing.T) {
	var sent atomic.Int32
	i, _, a, b := managedPair(t, func(c *Config) {
		if c.Role != Initiator {
			return
		}
		send := c.Send
		c.Send = func(pkt []byte, natt bool) error {
			h, _, _, _ := parseHeader(pkt)
			if h.exchange == exchangeQuick && sent.Add(1) == 4 {
				return nil
			}
			return send(pkt, natt)
		}
	})
	if err := i.Rekey(); err != nil {
		t.Fatal(err)
	}
	checkMirrored(t, waitResult(t, "initiator", a), waitResult(t, "responder after retransmission", b))
	if sent.Load() < 5 {
		t.Fatal("QM3 was not retransmitted")
	}
}

func TestCrossedIKERenewalsAllowIndependentControlSelection(t *testing.T) {
	i, r, a, b := managedPair(t)
	// Allocate both Main Modes before sending either to reproduce a collision.
	i.mu.Lock()
	ci := i.newRenewalLocked(Initiator, [8]byte{})
	i.mu.Unlock()
	r.mu.Lock()
	cr := r.newRenewalLocked(Initiator, [8]byte{})
	r.mu.Unlock()
	ci.Start()
	cr.Start()
	// Both exchanges must install SAs, even if completion order differs.
	for range 2 {
		waitResult(t, "crossed initiator", a)
		waitResult(t, "crossed responder", b)
	}
	// Request Quick Mode through each independently initiated control SA,
	// including one that the other endpoint no longer proactively uses.
	for _, peer := range []*Session{ci, cr} {
		if err := peer.Rekey(); err != nil {
			t.Fatal(err)
		}
		checkMirrored(t, waitResult(t, "crossed ESP", a), waitResult(t, "crossed ESP peer", b))
	}
}

func TestSelectedTransformNumberIsPreserved(t *testing.T) {
	_, _, ts, err := parseSA(buildSelectedSA(protoESP, be32(42), parsedTransform{proposal: 1, num: 7, id: espTransformAES, attrs: []attr{basicAttr(ipsecAttrEncapMode, encapUDPTransport)}}))
	if err != nil || len(ts) != 1 || ts[0].num != 7 {
		t.Fatalf("transform selection lost: %+v, %v", ts, err)
	}
}

type deleteCapture struct {
	*capture
	deleted chan uint32
}

func (c *deleteCapture) DeleteESP(spi uint32) { c.deleted <- spi }

func TestDeleteRequiresAuthenticatedInformational(t *testing.T) {
	var recorder *deleteCapture
	i, r, _, _ := managedPair(t, func(c *Config) {
		if c.Role == Responder {
			recorder = &deleteCapture{c.Handler.(*capture), make(chan uint32, 2)}
			c.Handler = recorder
		}
	})
	body := make([]byte, 12)
	binary.BigEndian.PutUint32(body, doiIPsec)
	body[4], body[5], body[7] = protoESP, 4, 1
	binary.BigEndian.PutUint32(body[8:], 42)
	var pkt []byte
	i.mu.Lock()
	original := i.cfg.Send
	i.cfg.Send = func(p []byte, _ bool) error { pkt = bytes.Clone(p); return nil }
	err := i.sendInformational([]payload{{typ: payloadDelete, body: body}})
	i.cfg.Send = original
	i.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	damaged := bytes.Clone(pkt)
	damaged[len(damaged)-1] ^= 1
	r.HandleInbound(damaged)
	select {
	case <-recorder.deleted:
		t.Fatal("unauthenticated Delete accepted")
	default:
	}
	r.HandleInbound(pkt)
	select {
	case spi := <-recorder.deleted:
		if spi != 42 {
			t.Fatal(spi)
		}
	default:
		t.Fatal("valid Delete ignored")
	}
}

func TestFailedRekeyDoesNotExtendHardDeadline(t *testing.T) {
	var drop atomic.Bool
	i, _, a, _ := managedPair(t, func(c *Config) {
		if c.Role != Initiator {
			return
		}
		send := c.Send
		c.Send = func(pkt []byte, natt bool) error {
			h, _, _, _ := parseHeader(pkt)
			if drop.Load() && h.exchange == exchangeQuick {
				return nil
			}
			return send(pkt, natt)
		}
	})
	drop.Store(true)
	i.mu.Lock()
	deadline := i.espDeadline
	i.mu.Unlock()
	if err := i.Rekey(); err != nil {
		t.Fatal(err)
	}
	i.mu.Lock()
	var child *Session
	for _, c := range i.exchanges {
		child = c
	}
	i.mu.Unlock()
	for range ikeMaxRetransmits + 1 {
		child.onRetransmitGeneration(child.timerGeneration)
	}
	i.mu.Lock()
	changed, closed := !i.espDeadline.Equal(deadline), i.closed
	i.mu.Unlock()
	if changed || closed {
		t.Fatal("failed renewal changed the still-valid data SA lifetime")
	}
	select {
	case err := <-a.fail:
		t.Fatalf("failed rekey prematurely closed data SA: %v", err)
	default:
	}
	i.mu.Lock()
	i.espDeadline = time.Now().Add(-time.Second)
	i.dataDeadline.Store(i.espDeadline.UnixNano())
	i.mu.Unlock()
	i.maintain()
	select {
	case err := <-a.fail:
		if err != ErrExpired {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("hard expiry ignored after failed rekey")
	}
}

func TestDataRekeyRequestDoesNotWaitForControlLock(t *testing.T) {
	i, _, a, b := managedPair(t)
	i.mu.Lock()
	returned := make(chan struct{})
	go func() { i.RequestRekey(); close(returned) }()
	select {
	case <-returned:
		i.mu.Unlock()
	case <-time.After(time.Second):
		i.mu.Unlock()
		t.Fatal("data callback blocked on IKE lock")
	}
	checkMirrored(t, waitResult(t, "data triggered initiator", a), waitResult(t, "data triggered responder", b))
}

func TestRenewalIdentityIgnoresLegalPhase1Selectors(t *testing.T) {
	zero := []byte{1, 0, 0, 0, 192, 0, 2, 1}
	udp := []byte{1, 17, 1, 244, 192, 0, 2, 1}
	if !samePhase1Identity(zero, udp) {
		t.Fatal("equivalent IKE identity rejected")
	}
	udp[7] = 2
	if samePhase1Identity(zero, udp) {
		t.Fatal("different identity accepted")
	}
}
