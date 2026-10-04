package ikev1

import (
	"testing"
	"testing/synctest"
	"time"
)

// Simulated clock, real state machines and cryptography. This verifies timer
// and resource lifecycles over a day; it is not a 24-hour network acceptance.
func TestDayOfControlAndDataSARenewals(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		i, r, a, b := managedPair(t, func(c *Config) { c.IKELifetime = 8 * time.Hour; c.ESPLifetime = time.Hour })
		deadline := time.NewTimer(25 * time.Hour)
		defer deadline.Stop()
		counts := [2]int{}
		for {
			select {
			case result := <-a.res:
				if !result.Rekey {
					t.Fatal("renewal recreated the access session")
				}
				counts[0]++
			case result := <-b.res:
				if !result.Rekey {
					t.Fatal("renewal recreated the access session")
				}
				counts[1]++
			case err := <-a.fail:
				t.Fatal(err)
			case err := <-b.fail:
				t.Fatal(err)
			case <-deadline.C:
				if counts[0] < 24 || counts[1] < 24 {
					t.Fatalf("too few ESP renewals: %v", counts)
				}
				for _, session := range []*Session{i, r} {
					session.mu.Lock()
					generation, retained, closed := session.controlGeneration, len(session.renewals), session.closed
					expired := false
					for _, child := range session.renewals {
						child.mu.Lock()
						expired = expired || !time.Now().Before(child.ikeDeadline)
						child.mu.Unlock()
					}
					session.mu.Unlock()
					if closed || expired || generation < 3 || retained > 4 {
						t.Fatalf("control lifecycle: closed=%v generation=%d retained=%d", closed, generation, retained)
					}
				}
				return
			}
		}
	})
}
