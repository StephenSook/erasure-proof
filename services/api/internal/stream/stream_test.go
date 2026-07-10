package stream

import (
	"sync"
	"testing"
)

func TestHub_FansOutToAllSubscribers(t *testing.T) {
	h := NewHub(8, 8)
	a, unsubA, okA := h.Subscribe()
	b, unsubB, okB := h.Subscribe()
	if !okA || !okB {
		t.Fatal("subscribe should succeed under the cap")
	}
	defer unsubA()
	defer unsubB()

	h.Publish(DecisionEvent{Seq: 1, Action: "erasure"})
	if (<-a).Seq != 1 || (<-b).Seq != 1 {
		t.Error("both subscribers should receive the event")
	}
}

func TestHub_EnforcesSubscriberCap(t *testing.T) {
	h := NewHub(1, 4)
	_, unsub, ok := h.Subscribe()
	if !ok {
		t.Fatal("first subscribe should succeed")
	}
	defer unsub()
	if _, _, ok := h.Subscribe(); ok {
		t.Error("subscribing beyond the cap should be refused")
	}
}

func TestHub_DropsOldestNeverBlocks(t *testing.T) {
	// A subscriber that never reads must not block Publish; the newest events survive.
	h := NewHub(4, 2)
	ch, unsub, _ := h.Subscribe()
	defer unsub()
	for i := 1; i <= 100; i++ {
		h.Publish(DecisionEvent{Seq: int64(i)})
	}
	// Buffer is 2, so at most 2 events are queued; they must be the most recent (drop-oldest).
	e0 := <-ch
	e1 := <-ch
	got := []int64{e0.Seq, e1.Seq}
	if got[1] != 100 {
		t.Errorf("newest event should survive, got last %d, want 100", got[1])
	}
	if got[0] >= got[1] {
		t.Errorf("queued events out of order: %v", got)
	}
}

func TestHub_UnsubscribeIsIdempotentAndClosed(t *testing.T) {
	h := NewHub(4, 4)
	ch, unsub, _ := h.Subscribe()
	unsub()
	unsub() // second call must not panic
	if _, open := <-ch; open {
		t.Error("channel should be closed after unsubscribe")
	}
	if h.SubscriberCount() != 0 {
		t.Errorf("subscriber count = %d, want 0", h.SubscriberCount())
	}
}

func TestHub_ConcurrentPublishAndSubscribe(t *testing.T) {
	// Race detector guard: many goroutines publishing while subscribers come and go.
	h := NewHub(64, 8)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch, unsub, ok := h.Subscribe()
			if !ok {
				return
			}
			go func() {
				for range ch {
				}
			}()
			for j := 0; j < 50; j++ {
				h.Publish(DecisionEvent{Seq: int64(j)})
			}
			unsub()
		}()
	}
	wg.Wait()
}

func TestParseChangefeedValue_RealFormat(t *testing.T) {
	// The exact JSON a CockroachDB core changefeed emits for a decision_log row (captured from a
	// live spike): bytes columns render as \x-prefixed hex.
	value := []byte(`{"after": {"action": "erasure", "hash": "\\xcc", "lawful_basis": "gdpr_art_17", ` +
		`"occurred_at": "2026-07-10T21:21:19.314633Z", "prev_hash": "\\xbb", "seq": 3, ` +
		`"subject_hash": "\\x03"}}`)
	ev, err := parseChangefeedValue(value)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ev.Seq != 3 || ev.Action != "erasure" || ev.LawfulBasis != "gdpr_art_17" {
		t.Errorf("event = %+v, want the decoded row", ev)
	}
	// Bytes fields normalized to plain lowercase hex (no \x prefix).
	if ev.Hash != "cc" || ev.PrevHash != "bb" || ev.SubjectHash != "03" {
		t.Errorf("hex fields = hash %q prev %q subj %q, want cc/bb/03", ev.Hash, ev.PrevHash, ev.SubjectHash)
	}
}

func TestParseChangefeedValue_RejectsNullAfter(t *testing.T) {
	if _, err := parseChangefeedValue([]byte(`{"after": null}`)); err == nil {
		t.Error("a null 'after' (a deletion) should be rejected for an append-only log")
	}
	if _, err := parseChangefeedValue([]byte(`not json`)); err == nil {
		t.Error("unparseable value should error")
	}
}
