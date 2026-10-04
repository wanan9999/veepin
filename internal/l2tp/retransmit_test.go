package l2tp

import (
	"context"
	"testing"
	"testing/synctest"
	"time"
)

func TestReliableHelloBackoffAndFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		peer := newEndpoint(RoleLNS)
		var sent []time.Duration
		start := time.Now()
		tunnel := NewTunnel(RoleLNS, func([]byte) error { sent = append(sent, time.Since(start)); return nil }, peer)
		tunnel.state = stateEstablished
		result := make(chan error, 1)
		go func() { result <- tunnel.SendHello(context.Background()) }()
		synctest.Wait()
		time.Sleep(10 * time.Second)
		if tunnel.closedFlag.Load() {
			t.Fatal("brief loss cleared the session before the reliable retry budget")
		}
		time.Sleep(22 * time.Second)
		synctest.Wait()
		if !tunnel.closedFlag.Load() {
			t.Fatal("dead peer retained beyond retransmission budget")
		}
		if err := <-result; err == nil {
			t.Fatal("unacknowledged HELLO succeeded")
		}
		want := []time.Duration{0, time.Second, 3 * time.Second, 7 * time.Second, 15 * time.Second, 23 * time.Second}
		if len(sent) != len(want) {
			t.Fatalf("send times: %v", sent)
		}
		for i := range want {
			if sent[i] != want[i] {
				t.Fatalf("send times: %v, want %v", sent, want)
			}
		}
	})
}

func TestControlAcknowledgementAdvancesRetryBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		peer := newEndpoint(RoleLNS)
		tunnel := NewTunnel(RoleLNS, func([]byte) error { return nil }, peer)
		defer tunnel.Close()
		tunnel.state = stateEstablished
		tunnel.ns = 1
		tunnel.unacked = []pending{{ns: 65535}, {ns: 0}}
		tunnel.retries = 4
		tunnel.armTimer()
		previousTimer := tunnel.timerGeneration
		tunnel.purgeAcked(2)
		if len(tunnel.unacked) != 2 || tunnel.retries != 4 {
			t.Fatal("future acknowledgement changed state")
		}
		tunnel.purgeAcked(0)
		if len(tunnel.unacked) != 1 || tunnel.unacked[0].ns != 0 || tunnel.retries != 0 {
			t.Fatal("partial wraparound ACK did not reset oldest-message retry budget")
		}
		tunnel.onRetransmit(previousTimer)
		if tunnel.retries != 0 {
			t.Fatal("stopped timer consumed the new oldest message's retry budget")
		}
		tunnel.purgeAcked(1)
		if len(tunnel.unacked) != 0 || tunnel.timer != nil {
			t.Fatal("acknowledged queue retained a retry timer")
		}
	})
}
