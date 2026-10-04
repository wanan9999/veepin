package ikev1

// IKEv1 renews the control SA through a fresh Main Mode, with new cookies and
// keys. Old and new control SAs must be demultiplexed independently of ESP.
import (
	"bytes"
	"encoding/binary"
	"errors"
	"time"
)

// Cookie is available before Start so a UDP server can register an outbound
// Main Mode exchange before the first reply arrives.
func (s *Session) Cookie() [8]byte { return s.initCookie }

func IsInitialMainMode(pkt []byte) bool {
	h, _, _, err := parseHeader(pkt)
	return err == nil && h.exchange == exchangeMain && h.messageID == 0 && h.flags == 0 && h.respCookie == [8]byte{} && h.initCookie != [8]byte{}
}

func (s *Session) RenewIKE() error {
	root := s
	if s.renewalRoot != nil {
		root = s.renewalRoot
	}
	root.mu.Lock()
	if root.closed || !root.established || !root.cfg.ManageLifetime || root.renewalPending {
		root.mu.Unlock()
		return errors.New("ikev1: IKE renewal unavailable")
	}
	child := root.newRenewalLocked(Initiator, [8]byte{})
	if child == nil {
		root.mu.Unlock()
		return errors.New("ikev1: IKE renewal capacity exceeded")
	}
	root.renewalPending = true
	root.mu.Unlock()
	child.Start()
	return nil
}

func (s *Session) newRenewalLocked(role Role, cookie [8]byte) *Session {
	if s.renewals == nil {
		s.renewals = make(map[[8]byte]*Session)
	}
	if len(s.renewals) >= 8 {
		return nil
	}
	cfg := s.cfg
	cfg.Role, cfg.Mode, cfg.ManageLifetime = role, ModeMain, true
	child := NewSession(cfg)
	child.renewalRoot = s
	child.baseGeneration = s.controlGeneration
	child.prop = s.prop
	child.floated = true
	if role == Responder {
		child.initCookie = cookie
	}
	child.cfg.Handler = renewalHandler{root: s, child: child}
	s.renewals[child.initCookie] = child
	if h, ok := s.cfg.Handler.(interface{ RegisterIKE([8]byte) }); ok {
		h.RegisterIKE(child.initCookie)
	}
	return child
}

// Called with the root lock held, released while a child invokes its handler.
func (s *Session) routeRenewalLocked(pkt []byte, authenticated func()) bool {
	h, _, _, err := parseHeader(pkt)
	if err != nil || h.initCookie == s.initCookie {
		return false
	}
	child := s.renewals[h.initCookie]
	if child == nil && IsInitialMainMode(pkt) {
		child = s.newRenewalLocked(Responder, h.initCookie)
	}
	if child == nil {
		return true
	}
	s.mu.Unlock()
	child.HandleInboundAuthenticated(pkt, authenticated)
	s.mu.Lock()
	return true
}

type renewalHandler struct{ root, child *Session }

func (h renewalHandler) Established(r Result) {
	s := h.root
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.dataRekeyPending.Store(false)
	// Sharing a PSK is insufficient to replace another authenticated identity.
	if !samePhase1Identity(s.peerID, r.PeerID) {
		go h.child.Close()
		delete(s.renewals, h.child.initCookie)
		if owner, ok := s.cfg.Handler.(interface{ UnregisterIKE([8]byte) }); ok {
			owner.UnregisterIKE(h.child.initCookie)
		}
		s.renewalPending = false
		return
	}
	s.renewalPending = false
	s.dataDeadline.Store(time.Now().Add(r.Lifetime).UnixNano())
	previous := s.activeIKE
	// Multiple authenticated IKE SAs may coexist. A late/crossed completion
	// remains usable by the peer, but must not move our preferred control SA
	// back to an older generation. Both sides may prefer different SAs.
	if previous != h.child {
		if previous != nil && h.child.baseGeneration < s.controlGeneration {
			go h.child.retireControl()
		} else {
			s.activeIKE = h.child
			s.controlGeneration = h.child.baseGeneration + 1
			if previous == nil {
				s.retired = true
				if s.lifetimeTimer != nil {
					s.lifetimeTimer.Stop()
				}
			} else {
				go previous.retireControl()
			}
		}
	}
	r.Rekey = true
	s.cfg.Handler.Established(r)
}
func (h renewalHandler) Failed(err error) {
	s := h.root
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	active := s.activeIKE == h.child
	s.renewalPending = false
	delete(s.renewals, h.child.initCookie)
	if owner, ok := s.cfg.Handler.(interface{ UnregisterIKE([8]byte) }); ok {
		owner.UnregisterIKE(h.child.initCookie)
	}
	s.mu.Unlock()
	go h.child.Close()
	if active {
		s.cfg.Handler.Failed(err)
	} else {
		s.logger.Printf("ikev1: IKE renewal failed: %v", err)
	}
}
func (h renewalHandler) DeleteESP(spi uint32) {
	if owner, ok := h.root.cfg.Handler.(interface{ DeleteESP(uint32) }); ok {
		owner.DeleteESP(spi)
	}
}

// Keep old control keys available for Quick Mode, Delete/DPD and cached
// retransmissions until their original deadline, then release the cookie alias.
func (s *Session) retireControl() {
	s.mu.Lock()
	if s.closed || s.retired {
		s.mu.Unlock()
		return
	}
	s.retired = true
	if s.lifetimeTimer != nil {
		s.lifetimeTimer.Stop()
	}
	s.retireTimer = time.AfterFunc(max(0, time.Until(s.ikeDeadline)), func() {
		root := s.renewalRoot
		root.mu.Lock()
		if root.activeIKE == s {
			root.mu.Unlock()
			return
		}
		delete(root.renewals, s.initCookie)
		if owner, ok := root.cfg.Handler.(interface{ UnregisterIKE([8]byte) }); ok {
			owner.UnregisterIKE(s.initCookie)
		}
		root.mu.Unlock()
		s.Close()
	})
	s.mu.Unlock()
}

// Phase-1 IDs may legally use either zero protocol/port or UDP/500
// (RFC 2407 section 4.6.2). Those selectors do not change the identity itself.
func samePhase1Identity(a, b []byte) bool {
	valid := func(id []byte) bool {
		if len(id) < 5 {
			return false
		}
		port := binary.BigEndian.Uint16(id[2:4])
		return (id[1] == 0 && port == 0) || (id[1] == 17 && port == 500)
	}
	return valid(a) && valid(b) && a[0] == b[0] && bytes.Equal(a[4:], b[4:])
}
