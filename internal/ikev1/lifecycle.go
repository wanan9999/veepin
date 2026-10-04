package ikev1

// Each post-establishment Quick Mode has its own IV, message ID and retry
// state (RFC 2409 section 5.5). The parent retains the authenticated IKE SA.
import (
	"bytes"
	"encoding/binary"
	"errors"
	"time"
)

var ErrExpired = errors.New("ikev1: security association expired")

func lifetimeSeconds(d time.Duration) uint32 {
	if d <= 0 {
		return 3600
	}
	return uint32(max(1, min(int64(d/time.Second), int64(^uint32(0)))))
}

// RFC 2407 defaults an omitted IPsec lifetime to 28800 seconds. Each
// duration must immediately follow its unit; duplicate units are ambiguous.
func proposalLifetimes(attrs []attr, typeID, durationID uint16) (seconds, kilobytes uint32, ok bool) {
	seconds = 28800
	var unit uint16
	seen := [3]bool{}
	for _, a := range attrs {
		if unit != 0 && a.typ != durationID {
			return 0, 0, false
		}
		switch a.typ {
		case typeID:
			v, valid := attrUint16(a)
			if !valid || v < 1 || v > 2 || unit != 0 || seen[v] {
				return 0, 0, false
			}
			unit = v
		case durationID:
			if unit == 0 || len(a.value) == 0 || len(a.value) > 4 {
				return 0, 0, false
			}
			var v uint32
			for _, b := range a.value {
				v = v<<8 | uint32(b)
			}
			if v == 0 {
				return 0, 0, false
			}
			if unit == 1 {
				seconds = v
			} else {
				kilobytes = v
			}
			seen[unit], unit = true, 0
		}
	}
	return seconds, kilobytes, unit == 0
}

// IKE volume lifetimes are deliberately rejected until the control channel
// accounts encrypted octets, rather than promising a limit it does not enforce.
func proposalLifetime(attrs []attr, typeID, durationID uint16) (uint32, bool) {
	seconds, kb, ok := proposalLifetimes(attrs, typeID, durationID)
	return seconds, ok && kb == 0
}

func (s *Session) installLifetimeLocked(d time.Duration) {
	s.dataRekeyPending.Store(false)
	now := time.Now()
	s.espDeadline = now.Add(d)
	if s.renewalRoot == nil {
		s.dataDeadline.Store(s.espDeadline.UnixNano())
	}
	if s.retired {
		return
	}
	// Opposite preferences reduce simultaneous rekeys; independent exchanges
	// still handle a peer that starts at the same time.
	numerator := 8
	if s.cfg.Role == Responder {
		numerator = 9
	}
	s.rekeyAt = now.Add(d * time.Duration(numerator) / 10)
	if s.lifetimeTimer != nil {
		s.lifetimeTimer.Stop()
	}
	s.lifetimeTimer = time.AfterFunc(min(time.Second, d/10), s.maintain)
}

func (s *Session) maintain() {
	s.mu.Lock()
	if s.closed || s.retired || !s.established {
		s.mu.Unlock()
		return
	}
	now := time.Now()
	owner := s
	if s.renewalRoot != nil {
		owner = s.renewalRoot
	}
	deadline := time.Unix(0, owner.dataDeadline.Load())
	if !now.Before(deadline) {
		s.closed = true
		s.mu.Unlock()
		s.cfg.Handler.Failed(ErrExpired)
		return
	}
	var stale []*Session
	for id, expiry := range s.exchangeExpiry {
		if !now.Before(expiry) {
			stale = append(stale, s.exchanges[id])
			delete(s.exchanges, id)
			delete(s.exchangeExpiry, id)
		}
	}
	renew := !now.Before(s.renewAt)
	if renew {
		s.renewAt = now.Add(10 * time.Second)
	}
	start := !renew && !s.rekeying && !now.Before(s.rekeyAt)
	next := time.Second
	for _, deadline := range []time.Time{deadline, s.rekeyAt, s.renewAt} {
		if remaining := deadline.Sub(now); remaining > 0 && remaining < next {
			next = remaining
		}
	}
	s.lifetimeTimer = time.AfterFunc(max(time.Millisecond, next), s.maintain)
	s.mu.Unlock()
	for _, child := range stale {
		child.Close()
	}
	if renew {
		_ = s.RenewIKE()
	}
	if start {
		_ = s.Rekey()
	}
}

// RequestRekey is safe from a data/control send callback holding the L2TP
// lock. It must not acquire the IKE lock there: a Delete handler may already
// own that lock while closing the L2TP tunnel. Coalesce until completion.
func (s *Session) RequestRekey() {
	if !s.dataRekeyPending.CompareAndSwap(false, true) {
		return
	}
	go func() {
		if err := s.Rekey(); err != nil {
			s.dataRekeyPending.Store(false)
		}
	}()
}

// Rekey starts a new ESP exchange while the existing data SA remains usable.
func (s *Session) Rekey() error {
	s.mu.Lock()
	if s.activeIKE != nil {
		active := s.activeIKE
		s.mu.Unlock()
		return active.Rekey()
	}
	defer s.mu.Unlock()
	if s.closed || s.state != stDone || !s.cfg.ManageLifetime {
		return errors.New("ikev1: cannot start rekey")
	}
	if s.rekeying {
		return nil
	} // A request already in flight satisfies the trigger.
	if !time.Now().Before(s.ikeDeadline) {
		return ErrExpired
	}
	id := randSPI()
	for {
		_, used := s.usedQuickIDs[id]
		if !used && id != s.qmMsgID {
			break
		}
		id = randSPI()
	}
	child := s.newQuickLocked(id, Initiator)
	if child == nil {
		return errors.New("ikev1: too many Quick Mode exchanges")
	}
	s.rekeying = true
	child.mu.Lock()
	err := child.startQuickMode()
	child.mu.Unlock()
	if err != nil {
		s.rekeying = false
		s.rekeyAt = time.Now().Add(5 * time.Second)
	}
	return err
}

func (s *Session) newQuickLocked(id uint32, role Role) *Session {
	// An older control SA has no proactive timer, but must still reclaim its
	// completed exchanges while servicing the peer's Quick Modes.
	for previousID, expiry := range s.exchangeExpiry {
		if !time.Now().Before(expiry) {
			previous := s.exchanges[previousID]
			delete(s.exchanges, previousID)
			delete(s.exchangeExpiry, previousID)
			go previous.Close()
		}
	}
	if s.exchanges == nil {
		s.exchanges = make(map[uint32]*Session)
		s.exchangeExpiry = make(map[uint32]time.Time)
	}
	if len(s.exchanges) >= 32 || len(s.usedQuickIDs) >= 1024 {
		return nil
	}
	cfg := s.cfg
	cfg.Role, cfg.ManageLifetime = role, false
	child := NewSession(cfg)
	child.cfg.Handler = quickHandler{parent: s, id: id}
	child.quickParent = s
	child.initCookie, child.respCookie = s.initCookie, s.respCookie
	child.keys, child.prop, child.esp = s.keys, s.prop, s.esp
	child.peerNATT, child.floated = s.peerNATT, s.floated
	child.assigned, child.qmMsgID = s.assigned, id
	child.state = stWaitQM1
	if s.usedQuickIDs == nil {
		s.usedQuickIDs = make(map[uint32]struct{})
	}
	s.usedQuickIDs[id] = struct{}{}
	s.exchanges[id] = child
	s.exchangeExpiry[id] = time.Now().Add(30 * time.Second)
	return child
}

func (s *Session) quickExchangeLocked(h header, first uint8, rest []byte) *Session {
	if h.messageID == 0 || h.messageID == s.qmMsgID || !time.Now().Before(s.ikeDeadline) {
		return nil
	}
	if c := s.exchanges[h.messageID]; c != nil {
		return c
	}
	if _, used := s.usedQuickIDs[h.messageID]; used {
		return nil
	}
	// Authenticate before allocating exchange state or changing the endpoint.
	iv := s.keys.quickModeIV(h.messageID)
	ps, plain, consumed, err := s.recvDecrypt(&iv, first, rest)
	if err != nil || len(ps) == 0 || ps[0].typ != payloadHash {
		return nil
	}
	if _, ok := findPayload(ps, payloadSA); !ok {
		return nil
	}
	want := s.keys.prf.Apply(s.keys.skeyidA, concat(be32(h.messageID), afterHash(plain, ps, consumed)))
	if !constEq(want, ps[0].body) {
		return nil
	}
	return s.newQuickLocked(h.messageID, Responder)
}

type quickHandler struct {
	parent *Session
	id     uint32
}

func (h quickHandler) Established(r Result) {
	s := h.parent
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	if child := s.exchanges[h.id]; child != nil && child.cfg.Role == Initiator {
		s.rekeying = false
	}
	s.installLifetimeLocked(r.Lifetime)
	s.cfg.Handler.Established(r)
}
func (h quickHandler) Failed(err error) {
	s := h.parent
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.retired {
		return
	}
	s.rekeying = false
	s.dataRekeyPending.Store(false)
	if s.renewalRoot != nil {
		s.renewalRoot.dataRekeyPending.Store(false)
	}
	s.rekeyAt = time.Now().Add(5 * time.Second)
	s.logger.Printf("ikev1: rekey failed, retaining unexpired SA: %v", err)
}

// Close cancels timers without re-entering the owner's failure callback.
func (s *Session) Close() {
	s.mu.Lock()
	s.closed = true
	if s.timer != nil {
		s.timer.Stop()
	}
	if s.lifetimeTimer != nil {
		s.lifetimeTimer.Stop()
	}
	if s.retireTimer != nil {
		s.retireTimer.Stop()
	}
	children := s.exchanges
	renewals := s.renewals
	s.exchanges = nil
	s.renewals = nil
	s.mu.Unlock()
	for _, child := range children {
		child.Close()
	}
	for _, child := range renewals {
		child.Close()
	}
}

// processDelete runs only after the Informational HASH has been verified.
func (s *Session) processDelete(body []byte) error {
	if len(body) < 8 || binary.BigEndian.Uint32(body) != doiIPsec {
		return errors.New("ikev1: malformed Delete")
	}
	proto, size, count := body[4], int(body[5]), int(binary.BigEndian.Uint16(body[6:]))
	if count == 0 || size == 0 || len(body) != 8+size*count {
		return errors.New("ikev1: malformed Delete SPIs")
	}
	for off := 8; off < len(body); off += size {
		spi := body[off : off+size]
		if proto == protoISAKMP && size == 16 && bytes.Equal(spi[:8], s.initCookie[:]) && bytes.Equal(spi[8:], s.respCookie[:]) {
			// Expire the control SA. Existing ESP SAs have independent lifetimes.
			s.ikeDeadline = time.Now()
			s.renewAt = time.Now()
		} else if proto == protoESP && size == 4 {
			if handler, ok := s.cfg.Handler.(interface{ DeleteESP(uint32) }); ok {
				handler.DeleteESP(binary.BigEndian.Uint32(spi))
			}
		}
	}
	return nil
}
