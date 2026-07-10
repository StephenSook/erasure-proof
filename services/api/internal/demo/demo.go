// Package demo backs the browser-facing demo gateway: read-only views over the memory, proof, and
// decision-log state, a hash-chain verification, an inversion proxy, and a safe RBAC-denial probe.
// Nothing here returns plaintext or key material; the RBAC probe never mutates data (it always rolls
// back). It is the read side of the six-stage demo console.
package demo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/StephenSook/erasure-proof/services/api/internal/chain"
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
)

// RequiredQueries are the named statements the demo gateway looks up; require them at startup.
var RequiredQueries = []string{
	qMemoryPreview, qSubjectKeyFingerprint, qErasureRecordGet, qDecisionLogAll, qDecisionLogVerify,
}

// ErrNotFound means the requested subject has no memory or erasure record.
var ErrNotFound = errors.New("not found")

// insufficientPrivilege is the SQLSTATE CockroachDB returns when a role lacks a privilege.
const insufficientPrivilege = "42501"

// Inverter is the narrow slice of the crypto client the demo needs (the recorded golden run).
type Inverter interface {
	Invert(ctx context.Context) (map[string]any, error)
}

// Service holds the read pools and the inversion proxy.
type Service struct {
	operator *pgxpool.Pool
	agent    *pgxpool.Pool
	q        store.Queries
	inverter Inverter
}

// New builds the demo Service.
func New(s *store.Store, inverter Inverter) *Service {
	return &Service{operator: s.Operator, agent: s.Agent, q: s.Q, inverter: inverter}
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

// ProofView is a subject's recorded erasure-proof state.
type ProofView struct {
	SubjectID      string     `json:"subject_id"`
	RequestedAt    time.Time  `json:"requested_at"`
	CommittedAt    *time.Time `json:"committed_at"`
	DecisionLogSeq *int64     `json:"decision_log_seq"`
	Fingerprint    *string    `json:"fingerprint"`
	KMSKeyARN      *string    `json:"kms_key_arn"`
	ProofRef       *string    `json:"proof_ref"`
}

// Proof returns a subject's erasure-proof record.
func (s *Service) Proof(ctx context.Context, subjectID string) (ProofView, error) {
	v := ProofView{SubjectID: subjectID}
	err := s.operator.QueryRow(ctx, s.q.MustGet(qErasureRecordGet), subjectID).Scan(
		&v.RequestedAt, &v.CommittedAt, &v.DecisionLogSeq, &v.Fingerprint, &v.KMSKeyARN, &v.ProofRef)
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
