package stream

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// changefeedSQL is a CockroachDB CORE (sinkless) changefeed: it streams new decision_log rows over
// the SQL connection with no external sink, so it works on the free Basic tier (enterprise
// changefeeds do not). no_initial_scan means only rows appended AFTER the feed starts are streamed;
// the SSE handler sends the current log snapshot first, so nothing is missed or double-sent.
const changefeedSQL = "EXPERIMENTAL CHANGEFEED FOR decision_log WITH no_initial_scan"

// Consumer runs the changefeed on a dedicated connection and publishes each row to the Hub,
// reconnecting with backoff if the feed drops. It requires kv.rangefeed.enabled (set by the
// deploy/local setup); if rangefeeds are off the feed errors and the consumer keeps retrying, and
// the SSE stream degrades to the snapshot-only view.
type Consumer struct {
	pool *pgxpool.Pool
	hub  *Hub
}

// NewConsumer builds a changefeed consumer over the given pool (use the operator pool; the
// changefeed is a read).
func NewConsumer(pool *pgxpool.Pool, hub *Hub) *Consumer {
	return &Consumer{pool: pool, hub: hub}
}

// Run streams until ctx is cancelled, reconnecting on error with capped backoff. Intended to run in
// its own goroutine for the process lifetime.
func (c *Consumer) Run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		if err := c.stream(ctx); err != nil && ctx.Err() == nil {
			log.Printf("stream: changefeed ended (%v); retrying in %s", err, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
	}
}

// stream opens one changefeed and publishes rows until it ends or ctx is cancelled.
func (c *Consumer) stream(ctx context.Context) error {
	conn, err := c.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire changefeed conn: %w", err)
	}
	defer conn.Release()

	rows, err := conn.Query(ctx, changefeedSQL)
	if err != nil {
		return fmt.Errorf("start changefeed: %w", err)
	}
	defer rows.Close()

	log.Print("stream: changefeed live on decision_log")
	for rows.Next() {
		var table string
		var key, value []byte
		if err := rows.Scan(&table, &key, &value); err != nil {
			return fmt.Errorf("scan changefeed row: %w", err)
		}
		ev, err := parseChangefeedValue(value)
		if err != nil {
			log.Printf("stream: skipping unparseable changefeed row: %v", err)
			continue
		}
		c.hub.Publish(ev)
	}
	return rows.Err()
}

// changefeedRow is the JSON envelope a core changefeed emits per row: {"after": {row fields}}. A
// deletion would carry a null "after", which decision_log never produces (it is append-only).
type changefeedRow struct {
	After *struct {
		Seq         int64  `json:"seq"`
		SubjectHash string `json:"subject_hash"`
		Action      string `json:"action"`
		LawfulBasis string `json:"lawful_basis"`
		OccurredAt  string `json:"occurred_at"`
		PrevHash    string `json:"prev_hash"`
		Hash        string `json:"hash"`
	} `json:"after"`
}

// parseChangefeedValue turns one changefeed value into a DecisionEvent. CockroachDB renders BYTES
// columns as \x-prefixed hex strings inside the JSON; normalize those to plain hex for the browser.
func parseChangefeedValue(value []byte) (DecisionEvent, error) {
	var row changefeedRow
	if err := json.Unmarshal(value, &row); err != nil {
		return DecisionEvent{}, fmt.Errorf("unmarshal changefeed value: %w", err)
	}
	if row.After == nil {
		return DecisionEvent{}, fmt.Errorf("changefeed row has no 'after' (unexpected for an append-only log)")
	}
	return DecisionEvent{
		Seq:         row.After.Seq,
		SubjectHash: normalizeHexBytes(row.After.SubjectHash),
		Action:      row.After.Action,
		LawfulBasis: row.After.LawfulBasis,
		OccurredAt:  row.After.OccurredAt,
		PrevHash:    normalizeHexBytes(row.After.PrevHash),
		Hash:        normalizeHexBytes(row.After.Hash),
	}, nil
}

// normalizeHexBytes converts CockroachDB's \x-prefixed BYTES rendering to plain lowercase hex. A
// value without the prefix is returned unchanged (defensive).
func normalizeHexBytes(s string) string {
	s = strings.TrimPrefix(s, `\x`)
	if _, err := hex.DecodeString(s); err != nil {
		return "" // not hex we can trust; render empty rather than garbage
	}
	return strings.ToLower(s)
}
