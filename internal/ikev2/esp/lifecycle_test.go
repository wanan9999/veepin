package esp

import (
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSequenceNeverWraps(t *testing.T) {
	k := cbcTransform(t, 1, 2)
	s := &SA{SPIOut: 1, SPIIn: 1, Out: k, In: k, seqOut: math.MaxUint32 - 1}
	if !s.NeedsRekey() {
		t.Fatal("missing early rekey signal")
	}
	if _, err := s.Encapsulate([]byte{1}, 17); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := s.Encapsulate([]byte{1}, 17); !errors.Is(err, ErrSequenceExhausted) {
			t.Fatal(err)
		}
	}
	if s.seqOut != math.MaxUint32 {
		t.Fatal("sequence wrapped")
	}
}

func TestExpiredSARejectsBothDirections(t *testing.T) {
	s := &SA{ExpiresAt: time.Now().Add(-time.Second)}
	if _, err := s.Encapsulate(nil, 17); !errors.Is(err, ErrSAExpired) {
		t.Fatal(err)
	}
	if _, _, err := s.Decapsulate(nil); !errors.Is(err, ErrSAExpired) {
		t.Fatal(err)
	}
}

func TestVolumeLimitsAndAuthenticatedReplay(t *testing.T) {
	k := cbcTransform(t, 1, 2)
	sender := &SA{SPIOut: 1, SPIIn: 1, Out: k, In: k, ByteLimit: 10}
	receiver := &SA{SPIOut: 1, SPIIn: 1, Out: k, In: k, ByteLimit: 10}
	pkt, err := sender.Encapsulate(make([]byte, 8), 17)
	if err != nil {
		t.Fatal(err)
	}
	if !sender.NeedsRekey() {
		t.Fatal("volume threshold not signaled")
	}
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if _, _, err := receiver.Decapsulate(pkt); err == nil {
				accepted.Add(1)
			}
		})
	}
	wg.Wait()
	if accepted.Load() != 1 || receiver.bytesIn != 8 {
		t.Fatal("replayed packet consumed volume or was accepted twice")
	}
	if _, err := sender.Encapsulate(make([]byte, 3), 17); !errors.Is(err, ErrSAExpired) {
		t.Fatal(err)
	}
	// A peer that ignores its send limit cannot overrun our receive limit.
	sender.ByteLimit = 0
	pkt, err = sender.Encapsulate(make([]byte, 3), 17)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := receiver.Decapsulate(pkt); !errors.Is(err, ErrSAExpired) {
		t.Fatal(err)
	}
}
