package stream

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// changefeedSQL is a CockroachDB CORE (sinkless) changefeed: it streams new decision_log rows over
// the SQL connection with no external sink, so it works on the free Basic tier (enterprise
// changefeeds do not). no_initial_scan means only rows appended AFTER the feed starts are streamed.
// The SSE handler subscribes BEFORE reading the snapshot, so any row appended during the snapshot is
// still delivered live; the client dedupes by seq, so the harmless snapshot/live overlap is merged
// rather than shown twice.
const changefeedSQL = "EXPERIMENTAL CHANGEFEED FOR decision_log WITH no_initial_scan"

// Consumer runs the changefeed on its OWN dedicated connection (never the shared operator pool, so
// the always-on feed cannot subtract a connection from the erasure/read paths) and publishes each
// row to the Hub, reconnecting with backoff if the feed drops. It requires kv.rangefeed.enabled
// (set by the deploy/local setup); if rangefeeds are off the feed errors and the consumer keeps
// retrying, and the SSE stream degrades to the snapshot-only view.
type Consumer struct {
	dsn string
	hub *Hub
}

// NewConsumer builds a changefeed consumer that opens its own connection to dsn.
func NewConsumer(dsn string, hub *Hub) *Consumer {
	return &Consumer{dsn: dsn, hub: hub}
}

// Run streams until ctx is cancelled, reconnecting with capped backoff. A minimum dwell is enforced
// on EVERY iteration (error or clean exit), so a changefeed that ends immediately cannot hot-loop
// the database. Intended to run in its own goroutine, cancelled on shutdown.
func (c *Consumer) Run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := c.stream(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Printf("stream: changefeed ended with error (%v); retrying in %s", err, backoff)
		} else {
			log.Printf("stream: changefeed closed cleanly after %s; retrying in %s", time.Since(start).Round(time.Second), backoff)
		}
		// Always wait before reconnecting; grow the delay unless the feed ran a healthy while.
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if time.Since(start) > time.Minute {
			backoff = time.Second // the feed was healthy for a while; reset the backoff
		} else if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// stream opens one changefeed on a fresh dedicated connection and publishes rows until it ends or
// ctx is cancelled.
func (c *Consumer) stream(ctx context.Context) error {
	conn, err := pgx.Connect(ctx, c.dsn)
	if err != nil {
		return fmt.Errorf("connect changefeed conn: %w", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()

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
// non-hex value (e.g. if a future CockroachDB version emits BYTES as base64) is blanked AND logged,
// so a changefeed format change surfaces as a warning rather than a silently empty hash chain.
func normalizeHexBytes(s string) string {
	trimmed := strings.TrimPrefix(s, `\x`)
	if _, err := hex.DecodeString(trimmed); err != nil {
		if s != "" {
			log.Printf("stream: changefeed bytes field is not \\x-hex (got %q); rendering empty", s)
		}
		return ""
	}
	return strings.ToLower(trimmed)
}
