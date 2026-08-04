// Package demo backs the browser-facing demo gateway: read-only views over the memory, proof, and
// decision-log state, a hash-chain verification, an inversion proxy, and a safe RBAC-denial probe.
// Nothing here returns plaintext or key material; the RBAC probe never mutates data (it always rolls
// back). It is the read side of the six-stage demo console.
package demo

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/StephenSook/erasure-proof/services/api/internal/agent"
	"github.com/StephenSook/erasure-proof/services/api/internal/chain"
	"github.com/StephenSook/erasure-proof/services/api/internal/ingest"
	"github.com/StephenSook/erasure-proof/services/api/internal/merkle"
	"github.com/StephenSook/erasure-proof/services/api/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	qMemoryPreview         = "memory_preview"
	qSubjectKeyFingerprint = "subject_key_fingerprint"
	qErasureRecordGet      = "erasure_record_get"
	qDecisionLogAll        = "decision_log_all"
	qDecisionLogVerify     = "decision_log_verify"
	qDecisionLogLeaves     = "decision_log_leaves"
	qDecisionLogIndexed    = "decision_log_indexed"
	qSearchPrefix          = "search_prefix"
	qTTInsert              = "tt_insert"
	qTTDelete              = "tt_delete"
	qTTCount               = "tt_count"
)

// RequiredQueries are the named statements the demo gateway looks up; require them at startup.
var RequiredQueries = []string{
	qMemoryPreview, qSubjectKeyFingerprint, qErasureRecordGet, qDecisionLogAll, qDecisionLogVerify,
	qDecisionLogLeaves, qDecisionLogIndexed, qSearchPrefix, qTTInsert, qTTDelete, qTTCount,
}

// ErrNotFound means the requested subject has no memory or erasure record.
var ErrNotFound = errors.New("not found")

// insufficientPrivilege is the SQLSTATE CockroachDB returns when a role lacks a privilege.
const insufficientPrivilege = "42501"

// Inverter is the narrow slice of the crypto client the demo needs: the recorded golden run, the
// live GPU inversion, the live GTR embedding (for the memory-writer), and the availability probes.
type Inverter interface {
	Invert(ctx context.Context) (map[string]any, error)
	InvertLive(ctx context.Context, embeddingB64 string) (map[string]any, error)
	InvertConfig(ctx context.Context) (map[string]any, error)
	EmbedLive(ctx context.Context, text string) (map[string]any, error)
	EmbedConfig(ctx context.Context) (map[string]any, error)
}

// liveInvertMaxPerHour caps how many live GPU inversions this process will start per rolling hour,
// so sustained demand or abuse cannot drain the GPU credit pool: at ~$0.02/run this bounds spend to
// roughly $1.20/hour even if a caller keeps clicking. It complements the concurrency semaphore
// (which bounds INSTANTANEOUS spend) and the worker's own max_containers cap.
const liveInvertMaxPerHour = 60

// Service holds the read pools and the inversion proxy.
type Service struct {
	operator *pgxpool.Pool
	agent    *pgxpool.Pool
	q        store.Queries
	inverter Inverter
	// liveInvertSem bounds CONCURRENT live GPU inversions so demand (or abuse) cannot fan out
	// unbounded GPU spend; excess callers get a busy signal rather than another billed container.
	liveInvertSem chan struct{}
	// liveInvertMu guards liveInvertHits, the timestamps of recent live inversions used for the
	// rolling-hour rate limit.
	liveInvertMu   sync.Mutex
	liveInvertHits []time.Time
	// now is injectable so the rate-limit test does not depend on wall-clock time.
	now func() time.Time
	// forensicsConverser is the Bedrock client for the on-screen forensics agent; nil when Bedrock
	// is not wired, so the UI shows the recorded/mock verdict instead. forensicsSem serializes live
	// audits (one at a time) since Bedrock's new-account token quota is low.
	forensicsConverser  agent.Converser
	forensicsSource     string
	forensicsDisclosure string
	warmingActive       bool
	forensicsSem        chan struct{}
	forensicsMu         sync.Mutex
	forensicsHits       []time.Time
	// titanEmbedder is the live AWS-native (Titan v2) embedding for the side-by-side panel; nil
	// when Bedrock is not wired. It shares the agent semaphore and rolling-hour budget: one
	// account-level Bedrock quota, one guard.
	titanEmbedder agent.TitanEmbedder
	// liveInvJob is the single background live-inversion job (see StartLiveInversion): the GPU run
	// outlasts CloudFront's 60s origin ceiling, so the browser starts it and polls, never holding
	// one long response open. liveInvJobInput binds the job to the exact embedding it inverts, so
	// a start for a DIFFERENT embedding is refused busy rather than silently served someone else's
	// result.
	liveInvJobMu    sync.Mutex
	liveInvJob      LiveInversionJob
	liveInvJobInput string
}

// New builds the demo Service.
func New(s *store.Store, inverter Inverter) *Service {
	return &Service{
		operator:      s.Operator,
		agent:         s.Agent,
		q:             s.Q,
		inverter:      inverter,
		liveInvertSem: make(chan struct{}, 2),
		now:           time.Now,
		forensicsSem:  make(chan struct{}, 1),
	}
}

// warmer is implemented by providers with a scale-to-zero cold start (the open-model fallback).
type warmer interface{ Warm(context.Context) bool }

// WarmForensics reports whether the live agent's model is ready to answer, and on a cold miss
// kicks ONE background warming poll (single-flight) so the container boots while the judge is
// still reading the page. Bedrock has no cold start and always reads warm.
func (s *Service) WarmForensics(ctx context.Context) bool {
	if s.forensicsConverser == nil {
		return false
	}
	w, ok := s.forensicsConverser.(warmer)
	if !ok {
		return true
	}
	if w.Warm(ctx) {
		return true
	}
	s.forensicsMu.Lock()
	starting := !s.warmingActive
	if starting {
		s.warmingActive = true
	}
	s.forensicsMu.Unlock()
	if starting {
		go func() {
			defer func() {
				s.forensicsMu.Lock()
				s.warmingActive = false
				s.forensicsMu.Unlock()
			}()
			deadline := time.Now().Add(4 * time.Minute)
			for time.Now().Before(deadline) {
				wctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				ready := w.Warm(wctx)
				cancel()
				if ready {
					return
				}
				time.Sleep(5 * time.Second)
			}
		}()
	}
	return false
}

// SetForensicsProvenance overrides the Source/Disclosure stamped on live agent results, so a
// non-Bedrock provider (the open-model fallback) is labeled honestly on screen. Unset keeps the
// Bedrock strings.
func (s *Service) SetForensicsProvenance(source, disclosure string) {
	s.forensicsSource, s.forensicsDisclosure = source, disclosure
}

// ForensicsProvider reports the provenance label for the config endpoint ("" when unwired).
func (s *Service) ForensicsProvider() string {
	if s.forensicsConverser == nil {
		return ""
	}
	if s.forensicsSource != "" {
		return s.forensicsSource
	}
	return "live_bedrock"
}

// SetForensicsConverser wires the live Bedrock forensics agent. Called at boot only when Bedrock is
// configured; leaving it unset keeps the live agent unavailable (the UI falls back honestly).
func (s *Service) SetForensicsConverser(c agent.Converser) { s.forensicsConverser = c }

// SetTitanEmbedder wires the live Titan v2 side-by-side embedding. Boot-time, AGENTS_LIVE only.
func (s *Service) SetTitanEmbedder(t agent.TitanEmbedder) { s.titanEmbedder = t }

// TitanAvailable reports whether the live Titan embedding can run (drives the UI panel).
func (s *Service) TitanAvailable() bool { return s.titanEmbedder != nil }

// ErrTitanUnavailable means no Bedrock Titan embedder is wired.
var ErrTitanUnavailable = errors.New("titan embedding unavailable")

// TitanEmbed embeds text with AWS-native Titan v2 for the side-by-side panel. Shares the agent
// semaphore (one live Bedrock call at a time) and the rolling-hour budget with the forensics
// agent and memory-writer, since all draw on the same low new-account Bedrock quota.
func (s *Service) TitanEmbed(ctx context.Context, text string) (agent.TitanEmbedding, error) {
	if s.titanEmbedder == nil {
		return agent.TitanEmbedding{}, ErrTitanUnavailable
	}
	select {
	case s.forensicsSem <- struct{}{}:
		defer func() { <-s.forensicsSem }()
	default:
		return agent.TitanEmbedding{}, ErrForensicsBusy
	}
	if !s.allowForensics() {
		return agent.TitanEmbedding{}, ErrForensicsBudget
	}
	// Same bound as the memory-writer: an oversized input should fail here, not opaquely at AWS.
	if len(text) > 1000 {
		text = text[:1000]
	}
	return s.titanEmbedder.EmbedText(ctx, text)
}

// ForensicsAvailable reports whether the live agent can run (drives the UI button).
func (s *Service) ForensicsAvailable() bool { return s.forensicsConverser != nil }

// ErrForensicsUnavailable means no Bedrock converser is wired.
var ErrForensicsUnavailable = errors.New("forensics agent unavailable")

// ErrForensicsBusy means a live audit is already running (quota guard).
var ErrForensicsBusy = errors.New("forensics agent busy")

// ErrForensicsBudget means the rolling-hour forensics-audit budget is exhausted (quota guard).
var ErrForensicsBudget = errors.New("forensics agent hourly budget exhausted")

// forensicsMaxPerHour bounds how many live audits this process runs per rolling hour, so back-to-back
// clicks cannot drain the low new-account Bedrock token quota. Each audit is up to five Converse
// calls; 30/hour keeps the sustained draw modest.
const forensicsMaxPerHour = 30

// ForensicsAudit runs the live Bedrock forensics agent over subjectID and returns the verdict and
// its full tool-call trace. One audit runs at a time (concurrency), bounded per rolling hour
// (sustained spend). Source and Disclosure mark the result as live; EvidenceProven is the server's
// own read of the trace so the UI never tones a PROVEN headline the tools did not support.
func (s *Service) ForensicsAudit(ctx context.Context, subjectID string) (agent.AuditResult, error) {
	if s.forensicsConverser == nil {
		return agent.AuditResult{}, ErrForensicsUnavailable
	}
	select {
	case s.forensicsSem <- struct{}{}:
		defer func() { <-s.forensicsSem }()
	default:
		return agent.AuditResult{}, ErrForensicsBusy
	}
	if !s.allowForensics() {
		return agent.AuditResult{}, ErrForensicsBudget
	}
	ag := agent.NewForensicsAgent(s.forensicsConverser, s.ForensicsToolset(), 4)
	res, err := ag.Audit(ctx, subjectID)
	if err != nil {
		return agent.AuditResult{}, err
	}
	res.Source = "live_bedrock"
	res.Disclosure = "Live Claude (Bedrock) tool-use audit. The verdict cites only what the " +
		"read-only tools returned; evidence_proven is our own check of the trace."
	if s.forensicsSource != "" {
		res.Source, res.Disclosure = s.forensicsSource, s.forensicsDisclosure
	}
	return res, nil
}

// distillSystem is the memory-writer prompt: Claude reads a conversation turn and returns the one
// durable fact worth remembering, which is then embedded and stored (the same behaviour as the
// tested Python MemoryWriter).
const distillSystem = "You are the memory-writing step of an AI agent. Read the user's message and " +
	"reply with ONE concise sentence stating the single durable fact about the person that is worth " +
	"remembering. Reply with only that sentence: no preamble, no quotes, no explanation."

// ErrMemoryWriterUnavailable means Bedrock or the embedding worker is not wired.
var ErrMemoryWriterUnavailable = errors.New("memory writer unavailable")

// EmbedAvailable reports whether cryptod has a live GTR embedding worker (network probe).
func (s *Service) EmbedAvailable(ctx context.Context) bool {
	cfg, err := s.inverter.EmbedConfig(ctx)
	if err != nil {
		// A probe failure (cryptod down, network) is not fatal to the page, but log it so an outage
		// is distinguishable from an intentionally unwired deploy rather than silently reading false.
		log.Printf("embed-availability probe failed: %v", err)
		return false
	}
	ok, _ := cfg["embed_available"].(bool)
	return ok
}

// DistillAndEmbed runs the live memory-writer's first two steps: Claude distils the durable fact
// from a conversation turn, then the fact is embedded on the GPU (canonical GTR pipeline). The
// caller stores the result through the normal ingest path. Returns the fact and its base64
// embedding. Guarded by the shared agent semaphore + hourly budget (Bedrock + GPU token quota).
func (s *Service) DistillAndEmbed(ctx context.Context, turn string) (string, string, error) {
	if s.forensicsConverser == nil {
		return "", "", ErrMemoryWriterUnavailable
	}
	// Check the embed worker is up BEFORE spending a Bedrock call: a doomed writer (embed down)
	// would otherwise burn one distil call and a budget slot per click for nothing.
	if !s.EmbedAvailable(ctx) {
		return "", "", ErrMemoryWriterUnavailable
	}
	select {
	case s.forensicsSem <- struct{}{}:
		defer func() { <-s.forensicsSem }()
	default:
		return "", "", ErrForensicsBusy
	}
	if !s.allowForensics() {
		return "", "", ErrForensicsBudget
	}
	res, err := s.forensicsConverser.Converse(ctx, distillSystem,
		[]agent.Message{{Role: agent.RoleUser, Blocks: []agent.Block{{Text: turn}}}}, nil)
	if err != nil {
		return "", "", fmt.Errorf("distil: %w", err)
	}
	fact := strings.TrimSpace(res.Text)
	if fact == "" {
		return "", "", errors.New("the model produced no memory to store")
	}
	// Bound the fact before embedding: the Modal embed caps text length, and a distil that ran long
	// (or was prompt-injected to be huge) should not fail opaquely at the GPU after we already paid.
	if len(fact) > 1000 {
		fact = fact[:1000]
	}
	emb, err := s.inverter.EmbedLive(ctx, fact)
	if err != nil {
		return "", "", fmt.Errorf("embed: %w", err)
	}
	b64, _ := emb["embedding_b64"].(string)
	if b64 == "" {
		return "", "", errors.New("embedding worker returned no vector")
	}
	return fact, b64, nil
}

// allowForensics records a live agent call (forensics or memory-writer) and reports whether it is
// within the rolling-hour budget, pruning stale timestamps on each call.
func (s *Service) allowForensics() bool {
	s.forensicsMu.Lock()
	defer s.forensicsMu.Unlock()
	nowFn := s.now
	if nowFn == nil {
		nowFn = time.Now
	}
	cutoff := nowFn().Add(-time.Hour)
	kept := s.forensicsHits[:0]
	for _, t := range s.forensicsHits {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	s.forensicsHits = kept
	if len(s.forensicsHits) >= forensicsMaxPerHour {
		return false
	}
	s.forensicsHits = append(s.forensicsHits, nowFn())
	return true
}

// allowLiveInvert records a live-inversion attempt and reports whether it is within the rolling
// hourly budget. It prunes timestamps older than an hour on each call.
func (s *Service) allowLiveInvert() bool {
	s.liveInvertMu.Lock()
	defer s.liveInvertMu.Unlock()
	nowFn := s.now
	if nowFn == nil {
		nowFn = time.Now
	}
	cutoff := nowFn().Add(-time.Hour)
	kept := s.liveInvertHits[:0]
	for _, t := range s.liveInvertHits {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	s.liveInvertHits = kept
	if len(s.liveInvertHits) >= liveInvertMaxPerHour {
		return false
	}
	s.liveInvertHits = append(s.liveInvertHits, nowFn())
	return true
}

// MemoryView is a non-sensitive preview of a subject's stored memory.
type MemoryView struct {
	SubjectID        string    `json:"subject_id"`
	MemoryID         string    `json:"memory_id"`
	ContentLen       int       `json:"content_len"`
	EmbeddingPresent bool      `json:"embedding_present"`
	EmbeddingLen     int       `json:"embedding_len"`
	KeyFingerprint   string    `json:"key_fingerprint"` // empty once the key row is erased
	CreatedAt        time.Time `json:"created_at"`
}

// Memory returns a preview of a subject's memory row plus the key fingerprint if it still exists.
func (s *Service) Memory(ctx context.Context, subjectID string) (MemoryView, error) {
	v := MemoryView{SubjectID: subjectID}
	err := s.operator.QueryRow(ctx, s.q.MustGet(qMemoryPreview), subjectID).Scan(
		&v.MemoryID, &v.ContentLen, &v.EmbeddingPresent, &v.EmbeddingLen, &v.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return MemoryView{}, ErrNotFound
	}
	if err != nil {
		return MemoryView{}, fmt.Errorf("memory preview: %w", err)
	}
	// The key fingerprint is present until erasure deletes the subject_keys row; absence is evidence.
	var fp string
	if e := s.operator.QueryRow(ctx, s.q.MustGet(qSubjectKeyFingerprint), subjectID).Scan(&fp); e == nil {
		v.KeyFingerprint = fp
	} else if !errors.Is(e, pgx.ErrNoRows) {
		return MemoryView{}, fmt.Errorf("key fingerprint: %w", e)
	}
	return v, nil
}

// TimeTravelView is the "deleted is not gone" beat: a throwaway row is inserted, DELETEd the way
// most systems "erase", and then read back from the recent past with AS OF SYSTEM TIME. Every
// field is from the live database; nothing is simulated.
type TimeTravelView struct {
	SubjectID string `json:"subject_id"`
	// AsOf is the cluster logical timestamp captured between the insert and the delete.
	AsOf string `json:"as_of"`
	// NormalReadRows is what a plain SELECT sees after the DELETE (0: the row is "gone").
	NormalReadRows int64 `json:"normal_read_rows"`
	// TimeTravelRows is what the same SELECT sees AS OF SYSTEM TIME (1: still fully readable).
	TimeTravelRows int64 `json:"time_travel_rows"`
	// GCNote states the honest window: time travel works within the garbage-collection TTL
	// (fixed at 4500s on the Basic tier), and backups extend the survival far past it.
	GCNote string `json:"gc_note"`
}

// ttTimestampRe pins the captured cluster_logical_timestamp to a plain decimal so the composed
// AS OF SYSTEM TIME clause (which cannot take a placeholder) can never carry anything else.
var ttTimestampRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)

// searchOverfetch is how many extra rows the similarity search reads beyond k so that NULL-distance
// (erased) rows, which CockroachDB sorts first, cannot push live results past the limit under the
// scan plan. Comfortably above any realistic per-subject memory count.
const searchOverfetch = 64

// TimeTravel runs the whole beat server-side: insert a throwaway row (fresh random subject, tiny
// ciphertext placeholders, no key), capture the cluster's logical timestamp, DELETE the row like
// an ordinary "erasure", then count what a normal read and an AS OF SYSTEM TIME read each see.
func (s *Service) TimeTravel(ctx context.Context) (TimeTravelView, error) {
	v := TimeTravelView{
		GCNote: "This is the wrapped-key row the erasure DELETEs. Read back AS OF SYSTEM TIME " +
			"within the garbage-collection window (fixed at 4500s on CockroachDB Basic), the " +
			"deleted row is still fully readable; backups keep it past GC too. Deleting the row " +
			"is not erasure, which is why the real erasure destroys the KEY in KMS.",
	}
	// Dummy wrapped-key row values (bytes + arn text + origin); nothing sensitive, deleted at once.
	err := s.operator.QueryRow(ctx, s.q.MustGet(qTTInsert),
		[]byte{0x01}, "arn:aws:kms:demo:time-travel", "GENERATE_DATA_KEY", []byte{0x02},
	).Scan(&v.SubjectID)
	if err != nil {
		return TimeTravelView{}, fmt.Errorf("time-travel insert: %w", err)
	}
	// Best-effort cleanup: if anything between the insert and the intended DELETE errors, the
	// throwaway row would otherwise leak permanently into subject_keys. The normal path DELETEs it
	// as step three; this deferred delete is idempotent (a no-op once that ran) and uses a fresh
	// context so it still fires if ctx was cancelled.
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, e := s.operator.Exec(cctx, s.q.MustGet(qTTDelete), v.SubjectID); e != nil {
			// Both the main-path delete and this deferred delete failing would leave a throwaway
			// row in subject_keys; log it so the hygiene debt is visible rather than silent.
			log.Printf("time-travel demo cleanup failed for subject %s: %v", v.SubjectID, e)
		}
	}()
	// The timestamp must postdate the insert's commit and predate the delete; a fresh statement
	// on the same pool satisfies both.
	var asOf string
	if err := s.operator.QueryRow(ctx, "SELECT cluster_logical_timestamp()::string").Scan(&asOf); err != nil {
		return TimeTravelView{}, fmt.Errorf("time-travel timestamp: %w", err)
	}
	if !ttTimestampRe.MatchString(asOf) {
		return TimeTravelView{}, fmt.Errorf("unexpected cluster timestamp format %q", asOf)
	}
	v.AsOf = asOf
	if _, err := s.operator.Exec(ctx, s.q.MustGet(qTTDelete), v.SubjectID); err != nil {
		return TimeTravelView{}, fmt.Errorf("time-travel delete: %w", err)
	}
	if err := s.operator.QueryRow(ctx, s.q.MustGet(qTTCount), v.SubjectID).Scan(&v.NormalReadRows); err != nil {
		return TimeTravelView{}, fmt.Errorf("time-travel normal read: %w", err)
	}
	// AS OF SYSTEM TIME requires a constant expression, not a placeholder, so the statement is
	// composed against the regexp-pinned timestamp above (digits and one dot only).
	asOfSQL := "SELECT count(*) FROM subject_keys AS OF SYSTEM TIME " + asOf + " WHERE subject_id = $1"
	if err := s.operator.QueryRow(ctx, asOfSQL, v.SubjectID).Scan(&v.TimeTravelRows); err != nil {
		return TimeTravelView{}, fmt.Errorf("time-travel past read: %w", err)
	}
	return v, nil
}

// SearchHit is one similarity result from the C-SPANN prefix search.
type SearchHit struct {
	MemoryID string  `json:"memory_id"`
	Distance float64 `json:"distance"`
}

// SearchView is the retrieval beat's result: the hits, plus whether the query plan actually used
// the C-SPANN vector index (read from a live EXPLAIN, not asserted).
type SearchView struct {
	Results   []SearchHit `json:"results"`
	IndexUsed bool        `json:"index_used"`
	// ExplainLine is the plan line naming the index (empty when the plan did not use it), so the
	// console shows the database's own words rather than our claim.
	ExplainLine string `json:"explain_line"`
}

// Search runs the prefix-filtered C-SPANN similarity search for a subject. The erasure sets the
// live vector to NULL, so the same search that finds a memory before erasure finds nothing after:
// the agent can no longer even locate what it can no longer decrypt. The query vector arrives as
// base64 little-endian float32 (the same wire format the ingest path stores).
func (s *Service) Search(ctx context.Context, subjectID, embeddingB64 string, k int) (SearchView, error) {
	vec, err := ingest.VectorLiteral(embeddingB64)
	if err != nil {
		return SearchView{}, err
	}
	if k < 1 || k > 10 {
		k = 3
	}
	// The primary query keeps LIMIT k so it stays C-SPANN-eligible (a larger LIMIT or a WHERE
	// embedding IS NOT NULL filter both make the planner drop the vector index, per issue #146145).
	// The C-SPANN index plan never emits NULL-distance rows, so under it LIMIT k is exactly correct.
	v, rawCount, err := s.searchOnce(ctx, subjectID, vec, k)
	if err != nil {
		return SearchView{}, err
	}
	// Only the scan fallback (tiny tables) can leak erased rows: CockroachDB sorts NULL distances
	// FIRST (a documented divergence from Postgres NULLS LAST), so a scan can return k rows of which
	// some are the erased subject's NULLs, displacing live results past the limit. Detect exactly
	// that (the raw row count hit k but live results came up short) and re-fetch wide once, trimming
	// to k after dropping NULLs. The common path (index plan, or a subject with <= k memories) never
	// takes this branch, so the on-screen mem_idx plan and the demo's one-memory-per-subject case
	// are untouched.
	if rawCount == k && len(v.Results) < k {
		wide, _, werr := s.searchOnce(ctx, subjectID, vec, k+searchOverfetch)
		if werr != nil {
			return SearchView{}, werr
		}
		if len(wide.Results) > k {
			wide.Results = wide.Results[:k]
		}
		wide.IndexUsed, wide.ExplainLine = v.IndexUsed, v.ExplainLine // keep the LIMIT-k plan line
		v = wide
	}
	return v, nil
}

// searchOnce runs the similarity search at a given SQL LIMIT and returns the live (non-NULL) hits
// (bounded by that limit), plus the raw row count the query returned (including NULL-distance
// erased rows, which it filters out). The EXPLAIN of the same limit fills IndexUsed / ExplainLine
// from the database's own plan. The caller trims the hits to the requested k.
func (s *Service) searchOnce(ctx context.Context, subjectID, vec string, limit int) (SearchView, int, error) {
	v := SearchView{Results: []SearchHit{}}
	raw := 0
	rows, err := s.operator.Query(ctx, s.q.MustGet(qSearchPrefix), subjectID, vec, limit)
	if err != nil {
		return SearchView{}, 0, fmt.Errorf("vector search: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		raw++
		var h SearchHit
		var dist *float64
		if err := rows.Scan(&h.MemoryID, &dist); err != nil {
			return SearchView{}, 0, fmt.Errorf("vector search scan: %w", err)
		}
		if dist == nil {
			continue // erased row (vector destroyed): not a retrievable memory
		}
		h.Distance = *dist
		v.Results = append(v.Results, h)
	}
	if err := rows.Err(); err != nil {
		return SearchView{}, 0, fmt.Errorf("vector search rows: %w", err)
	}

	// Ask the database how it planned the query and report ITS answer. EXPLAIN does not execute,
	// so this is cheap; a plan that stopped using mem_idx (index disabled, stats change) shows up
	// as index_used=false on the console instead of a silently false claim.
	ex, err := s.operator.Query(ctx, "EXPLAIN "+s.q.MustGet(qSearchPrefix), subjectID, vec, limit)
	if err != nil {
		// The search itself succeeded; a failed EXPLAIN degrades to "not proven", never an error.
		return v, raw, nil
	}
	defer ex.Close()
	for ex.Next() {
		var line string
		if err := ex.Scan(&line); err != nil {
			break
		}
		if strings.Contains(line, "mem_idx") {
			v.IndexUsed = true
			v.ExplainLine = strings.TrimSpace(line)
			break
		}
	}
	return v, raw, nil
}

// ProofView is a subject's recorded erasure-proof state, including the signed proof document the
// browser-side WebCrypto verifier consumes (ProofBody is the exact signed bytes).
type ProofView struct {
	SubjectID       string     `json:"subject_id"`
	RequestedAt     time.Time  `json:"requested_at"`
	CommittedAt     *time.Time `json:"committed_at"`
	DecisionLogSeq  *int64     `json:"decision_log_seq"`
	Fingerprint     *string    `json:"fingerprint"`
	KMSKeyARN       *string    `json:"kms_key_arn"`
	ProofRef        *string    `json:"proof_ref"`
	ProofBody       *string    `json:"proof_body"`
	ProofSignature  *string    `json:"proof_signature"`
	SignerPubkeyPEM *string    `json:"signer_pubkey_pem"`
}

// Proof returns a subject's erasure-proof record.
func (s *Service) Proof(ctx context.Context, subjectID string) (ProofView, error) {
	v := ProofView{SubjectID: subjectID}
	err := s.operator.QueryRow(ctx, s.q.MustGet(qErasureRecordGet), subjectID).Scan(
		&v.RequestedAt, &v.CommittedAt, &v.DecisionLogSeq, &v.Fingerprint, &v.KMSKeyARN, &v.ProofRef,
		&v.ProofBody, &v.ProofSignature, &v.SignerPubkeyPEM)
	if errors.Is(err, pgx.ErrNoRows) {
		return ProofView{}, ErrNotFound
	}
	if err != nil {
		return ProofView{}, fmt.Errorf("erasure record: %w", err)
	}
	return v, nil
}

// DecisionRow is one displayed decision-log entry (all fields already pseudonymized/hex).
type DecisionRow struct {
	Seq         int64     `json:"seq"`
	SubjectHash string    `json:"subject_hash"`
	Action      string    `json:"action"`
	LawfulBasis string    `json:"lawful_basis"`
	OccurredAt  time.Time `json:"occurred_at"`
	PrevHash    string    `json:"prev_hash"`
	Hash        string    `json:"hash"`
}

// DecisionLog returns the full hash-chained decision log, oldest first.
func (s *Service) DecisionLog(ctx context.Context) ([]DecisionRow, error) {
	rows, err := s.operator.Query(ctx, s.q.MustGet(qDecisionLogAll))
	if err != nil {
		return nil, fmt.Errorf("decision log: %w", err)
	}
	defer rows.Close()
	var out []DecisionRow
	for rows.Next() {
		var r DecisionRow
		if err := rows.Scan(&r.Seq, &r.SubjectHash, &r.Action, &r.LawfulBasis,
			&r.OccurredAt, &r.PrevHash, &r.Hash); err != nil {
			return nil, fmt.Errorf("scan decision row: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ChainResult is the outcome of recomputing the decision-log hash chain.
type ChainResult struct {
	Intact     bool   `json:"intact"`
	Checked    int    `json:"checked"`
	BreakAtSeq *int64 `json:"break_at_seq"`
}

// VerifyChain recomputes the hash chain in Go and reports the first break, if any. It walks the log
// in seq order and checks each stored hash against chain.Link(prev, seq, action, basis, subjectHash).
func (s *Service) VerifyChain(ctx context.Context) (ChainResult, error) {
	rows, err := s.operator.Query(ctx, s.q.MustGet(qDecisionLogVerify))
	if err != nil {
		return ChainResult{}, fmt.Errorf("decision log verify: %w", err)
	}
	defer rows.Close()

	prev := chain.GenesisPrevHash()
	result := ChainResult{Intact: true}
	for rows.Next() {
		var (
			seq                 int64
			subjectHash, hash   []byte
			action, lawfulBasis string
		)
		if err := rows.Scan(&seq, &subjectHash, &action, &lawfulBasis, &hash); err != nil {
			return ChainResult{}, fmt.Errorf("scan verify row: %w", err)
		}
		result.Checked++
		expected := chain.Link(prev, seq, action, lawfulBasis, subjectHash)
		if !bytes.Equal(expected, hash) {
			seqCopy := seq
			result.Intact = false
			result.BreakAtSeq = &seqCopy
			// Stop at the first break: everything after it is unverifiable anyway.
			return result, rows.Err()
		}
		prev = hash
	}
	return result, rows.Err()
}

// RbacResult reports whether the agent role was denied a forbidden write.
type RbacResult struct {
	Attempted string `json:"attempted"`
	Denied    bool   `json:"denied"`
	SQLState  string `json:"sqlstate"`
	Message   string `json:"message"`
}

// RbacDemo attempts a forbidden UPDATE on the append-only decision log as the agent pool's role and
// reports whether it was denied. It runs inside a transaction that is ALWAYS rolled back, so the log
// is never actually modified even where the role is unrestricted (e.g. a local root cluster).
func (s *Service) RbacDemo(ctx context.Context) (RbacResult, error) {
	const attempt = "UPDATE decision_log SET action = 'tamper' WHERE seq = (SELECT max(seq) FROM decision_log)"
	res := RbacResult{Attempted: attempt}

	tx, err := s.agent.Begin(ctx)
	if err != nil {
		return RbacResult{}, fmt.Errorf("begin rbac probe: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // always roll back: this probe must never mutate the log

	_, execErr := tx.Exec(ctx, attempt)
	if execErr == nil {
		res.Denied = false
		res.Message = "the agent role was NOT denied (this pool is not privilege-restricted; the write was rolled back)"
		return res, nil
	}
	var pgErr *pgconn.PgError
	if errors.As(execErr, &pgErr) {
		res.SQLState = pgErr.Code
		res.Message = pgErr.Message
		res.Denied = pgErr.Code == insufficientPrivilege
		return res, nil
	}
	return RbacResult{}, fmt.Errorf("rbac probe: %w", execErr)
}

// Inversion returns the recorded Vec2Text golden run from cryptod.
func (s *Service) Inversion(ctx context.Context) (map[string]any, error) {
	return s.inverter.Invert(ctx)
}

// ErrLiveInversionBusy signals that all live-inversion slots are in use (cost guard).
var ErrLiveInversionBusy = errors.New("live inversion busy")

// ErrLiveInversionBudget signals the rolling-hour live-inversion budget is exhausted (cost guard).
var ErrLiveInversionBudget = errors.New("live inversion hourly budget exhausted")

// InversionConfig reports whether live GPU inversion is available (drives the UI button).
func (s *Service) InversionConfig(ctx context.Context) (map[string]any, error) {
	return s.inverter.InvertConfig(ctx)
}

// InversionLive runs live GPU inversion of one 3072-byte (768 float32) embedding, behind a small
// concurrency semaphore so the GPU spend stays bounded. It validates the embedding length so a
// caller cannot push arbitrary-size payloads at the worker. cryptod falls back to the recorded run
// internally if the worker is down, so the source label in the result tells the viewer what ran.
func (s *Service) InversionLive(ctx context.Context, embeddingB64 string) (map[string]any, error) {
	raw, err := base64.StdEncoding.DecodeString(embeddingB64)
	if err != nil {
		return nil, fmt.Errorf("bad embedding base64: %w", err)
	}
	if len(raw) != 768*4 {
		return nil, fmt.Errorf("embedding must be 3072 bytes (768 float32), got %d", len(raw))
	}
	// Rolling-hour budget first (bounds sustained spend), then the concurrency slot (bounds
	// instantaneous spend). Only count a run against the budget once it also gets a slot, so a
	// burst of busy-rejections does not consume the hourly allowance.
	select {
	case s.liveInvertSem <- struct{}{}:
		defer func() { <-s.liveInvertSem }()
	default:
		return nil, ErrLiveInversionBusy
	}
	if !s.allowLiveInvert() {
		return nil, ErrLiveInversionBudget
	}
	return s.inverter.InvertLive(ctx, embeddingB64)
}

// LiveInversionJob is the poll-visible state of the background live inversion. A live GPU run is
// 1 to 2.5 minutes (cold start plus the inversion), longer than CloudFront's 60s origin read
// ceiling, so a synchronous response 504s at the edge before the origin answers. The browser
// starts the job and polls short status requests instead.
type LiveInversionJob struct {
	State  string         `json:"state"` // idle | running | done | error
	Result map[string]any `json:"result,omitempty"`
	Error  string         `json:"error,omitempty"`
}

// StartLiveInversion begins one background live inversion. Single-flight PER EMBEDDING: a second
// start for the same embedding coalesces onto the running job, while a start for a different
// embedding is refused with ErrLiveInversionBusy (the old sync path's semantics) so one subject's
// poll can never be answered with another subject's inversion. Payload validation happens here so
// the START request carries the error, not a later poll.
func (s *Service) StartLiveInversion(embeddingB64 string) (LiveInversionJob, error) {
	if raw, err := base64.StdEncoding.DecodeString(embeddingB64); err != nil || len(raw) != 768*4 {
		return LiveInversionJob{}, fmt.Errorf("embedding must be 3072 bytes (768 float32) of base64")
	}
	s.liveInvJobMu.Lock()
	defer s.liveInvJobMu.Unlock()
	if s.liveInvJob.State == "running" {
		if s.liveInvJobInput == embeddingB64 {
			return s.liveInvJob, nil
		}
		return LiveInversionJob{}, ErrLiveInversionBusy
	}
	s.liveInvJob = LiveInversionJob{State: "running"}
	s.liveInvJobInput = embeddingB64
	go func() {
		// Same deadline layering as the sync path: Modal worker 300s < cryptod 320s/330s < 340s.
		ctx, cancel := context.WithTimeout(context.Background(), 340*time.Second)
		defer cancel()
		v, err := s.InversionLive(ctx, embeddingB64)
		s.liveInvJobMu.Lock()
		defer s.liveInvJobMu.Unlock()
		switch {
		case errors.Is(err, ErrLiveInversionBusy):
			s.liveInvJob = LiveInversionJob{State: "error", Error: "the GPU is busy with another live inversion; try again in a moment"}
		case errors.Is(err, ErrLiveInversionBudget):
			s.liveInvJob = LiveInversionJob{State: "error", Error: "the live-inversion hourly budget is used up; the recorded run is always available"}
		case err != nil:
			log.Printf("demo: live inversion failed: %v", err)
			s.liveInvJob = LiveInversionJob{State: "error", Error: "live inversion unavailable"}
		default:
			s.liveInvJob = LiveInversionJob{State: "done", Result: v}
		}
	}()
	return s.liveInvJob, nil
}

// LiveInversionStatus reports the current job for the polling endpoint.
func (s *Service) LiveInversionStatus() LiveInversionJob {
	s.liveInvJobMu.Lock()
	defer s.liveInvJobMu.Unlock()
	return s.liveInvJob
}

// TreeHead is the RFC 6962 Merkle head over the decision log.
type TreeHead struct {
	TreeSize int    `json:"tree_size"`
	Root     string `json:"root"` // hex
}

// TreeHead computes the current Merkle root and tree size over the decision-log leaves.
func (s *Service) TreeHead(ctx context.Context) (TreeHead, error) {
	leaves, err := s.leaves(ctx)
	if err != nil {
		return TreeHead{}, err
	}
	return TreeHead{TreeSize: len(leaves), Root: hex.EncodeToString(merkle.Root(leaves))}, nil
}

// InclusionView is an RFC 6962 audit proof that a decision-log entry is in the tree.
//
// leaf_hash, tree_size, and root are convenience echoes, NOT authoritative: a sound verifier
// recomputes the leaf hash itself from the row's own chain hash (merkle.LeafHash / the browser
// merkleLeafHash) and checks against the (root, tree_size) signed into the erasure proof, never
// against values served by the same endpoint that supplied the audit path. This proof is against
// the CURRENT tree; a proof anchored earlier signed an earlier snapshot, and Consistency proves the
// current tree extends it append-only.
type InclusionView struct {
	Seq       int64    `json:"seq"`
	LeafIndex int      `json:"leaf_index"`
	TreeSize  int      `json:"tree_size"`
	LeafHash  string   `json:"leaf_hash"`  // hex, RFC 6962 leaf hash of the row's chain hash (convenience echo)
	AuditPath []string `json:"audit_path"` // hex, leaf-to-root
	Root      string   `json:"root"`       // hex (current head, not necessarily a signed one)
}

// Inclusion returns the audit path proving the decision-log row with the given seq is included in
// the current Merkle tree. ErrNotFound if no row has that seq.
// Inclusion returns the audit proof that the decision-log row with the given seq is included in the
// Merkle tree of size treeSize. treeSize <= 0 means the current tree; a positive treeSize computes
// the proof within the FIRST treeSize leaves, so a verifier can check inclusion in the exact tree a
// signed erasure proof committed to (not the current head, which has grown since).
func (s *Service) Inclusion(ctx context.Context, seq int64, treeSize int) (InclusionView, error) {
	rows, err := s.operator.Query(ctx, s.q.MustGet(qDecisionLogIndexed))
	if err != nil {
		return InclusionView{}, fmt.Errorf("decision log indexed: %w", err)
	}
	defer rows.Close()
	var leaves [][]byte
	index := -1
	for rows.Next() {
		var rowSeq int64
		var h []byte
		if err := rows.Scan(&rowSeq, &h); err != nil {
			return InclusionView{}, fmt.Errorf("scan indexed row: %w", err)
		}
		if rowSeq == seq {
			index = len(leaves)
		}
		leaves = append(leaves, h)
	}
	if err := rows.Err(); err != nil {
		return InclusionView{}, err
	}
	// Restrict to the requested (signed) tree size. The seq must fall within it.
	if treeSize > 0 {
		if treeSize > len(leaves) || index < 0 || index >= treeSize {
			return InclusionView{}, ErrNotFound
		}
		leaves = leaves[:treeSize]
	}
	if index < 0 {
		return InclusionView{}, ErrNotFound
	}
	path := merkle.InclusionProof(leaves, index)
	auditPath := make([]string, len(path))
	for i, p := range path {
		auditPath[i] = hex.EncodeToString(p)
	}
	return InclusionView{
		Seq:       seq,
		LeafIndex: index,
		TreeSize:  len(leaves),
		LeafHash:  hex.EncodeToString(merkle.LeafHash(leaves[index])),
		AuditPath: auditPath,
		Root:      hex.EncodeToString(merkle.Root(leaves)),
	}, nil
}

// ConsistencyView is an RFC 6962 consistency proof that the tree at SizeFrom is an append-only
// prefix of the tree at SizeTo (the log only grew, was never rewritten).
type ConsistencyView struct {
	SizeFrom int      `json:"size_from"`
	SizeTo   int      `json:"size_to"`
	Proof    []string `json:"proof"`     // hex
	RootFrom string   `json:"root_from"` // hex, the earlier root
	RootTo   string   `json:"root_to"`   // hex, the current root
}

// Consistency returns the RFC 6962 consistency proof between two tree sizes over the decision log,
// so a verifier can confirm the current log is an append-only extension of the tree an older signed
// proof committed to. sizeTo <= 0 means the current tree size.
func (s *Service) Consistency(ctx context.Context, sizeFrom, sizeTo int) (ConsistencyView, error) {
	all, err := s.leaves(ctx)
	if err != nil {
		return ConsistencyView{}, err
	}
	if sizeTo <= 0 || sizeTo > len(all) {
		sizeTo = len(all)
	}
	if sizeFrom <= 0 || sizeFrom > sizeTo {
		return ConsistencyView{}, ErrNotFound
	}
	upTo := all[:sizeTo]
	proof := merkle.ConsistencyProof(upTo, sizeFrom)
	hexProof := make([]string, len(proof))
	for i, p := range proof {
		hexProof[i] = hex.EncodeToString(p)
	}
	return ConsistencyView{
		SizeFrom: sizeFrom,
		SizeTo:   sizeTo,
		Proof:    hexProof,
		RootFrom: hex.EncodeToString(merkle.Root(all[:sizeFrom])),
		RootTo:   hex.EncodeToString(merkle.Root(upTo)),
	}, nil
}

func (s *Service) leaves(ctx context.Context) ([][]byte, error) {
	rows, err := s.operator.Query(ctx, s.q.MustGet(qDecisionLogLeaves))
	if err != nil {
		return nil, fmt.Errorf("decision log leaves: %w", err)
	}
	defer rows.Close()
	var leaves [][]byte
	for rows.Next() {
		var h []byte
		if err := rows.Scan(&h); err != nil {
			return nil, fmt.Errorf("scan leaf: %w", err)
		}
		leaves = append(leaves, h)
	}
	return leaves, rows.Err()
}
