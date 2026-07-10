// Package stream turns a CockroachDB core changefeed on the decision log into a live SSE feed: as
// each erasure or ingest appends a hash-chained row, the row streams to every connected console in
// real time. The changefeed is CockroachDB tool #5 (Change Data Capture); decision_log carries no
// row-level security, so it is a safe CDC target (RLS and changefeeds are incompatible, and only
// agent_memory has RLS).
package stream

import "sync"

// DecisionEvent is one decision-log row as it appears on the live timeline. All bytes fields are
// hex so the browser can render them without decoding surprises.
type DecisionEvent struct {
	Seq         int64  `json:"seq"`
	SubjectHash string `json:"subject_hash"` // hex
	Action      string `json:"action"`
	LawfulBasis string `json:"lawful_basis"`
	OccurredAt  string `json:"occurred_at"`
	PrevHash    string `json:"prev_hash"` // hex
	Hash        string `json:"hash"`      // hex
}

// Hub fans out decision events to all connected SSE subscribers. A slow subscriber never blocks the
// changefeed: its buffer drops the oldest event rather than applying backpressure to the source.
type Hub struct {
	mu          sync.Mutex
	subscribers map[int]chan DecisionEvent
	next        int
	maxSubs     int
	bufferSize  int
}

// NewHub builds a Hub bounded to maxSubs concurrent subscribers, each with a bufferSize backlog.
func NewHub(maxSubs, bufferSize int) *Hub {
	if maxSubs < 1 {
		maxSubs = 64
	}
	if bufferSize < 1 {
		bufferSize = 16
	}
	return &Hub{subscribers: map[int]chan DecisionEvent{}, maxSubs: maxSubs, bufferSize: bufferSize}
}

// Subscribe registers a listener and returns its channel plus an unsubscribe func. ok is false when
// the subscriber cap is reached, so the SSE handler can refuse rather than fan out unbounded.
func (h *Hub) Subscribe() (ch <-chan DecisionEvent, unsubscribe func(), ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.subscribers) >= h.maxSubs {
		return nil, func() {}, false
	}
	id := h.next
	h.next++
	c := make(chan DecisionEvent, h.bufferSize)
	h.subscribers[id] = c
	return c, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if existing, present := h.subscribers[id]; present {
			delete(h.subscribers, id)
			close(existing)
		}
	}, true
}

// Publish delivers an event to every subscriber. If a subscriber's buffer is full, the OLDEST queued
// event is dropped to make room, so one stalled console never stalls the changefeed or the others.
func (h *Hub) Publish(ev DecisionEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, c := range h.subscribers {
		for {
			select {
			case c <- ev:
			default:
				// Full: drop the oldest, then retry the send. Terminates because we hold h.mu (no
				// other Publish or the unsubscribe-close can run concurrently), so after one drop
				// the channel has a free slot and the retry send succeeds; the reader only ever
				// frees more space, never less.
				select {
				case <-c:
					continue
				default:
				}
			}
			break
		}
	}
}

// SubscriberCount reports the number of connected subscribers (for the healthz/metrics surface).
func (h *Hub) SubscriberCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subscribers)
}
