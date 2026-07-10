// Package erasure runs the destroy-and-retain erasure transaction. This is the core of the whole
// project: in one SERIALIZABLE transaction it retains the pseudonymized decision log and destroys
// the subject key, or does neither.
package erasure

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/StephenSook/erasure-proof/services/api/internal/chain"
	"github.com/StephenSook/erasure-proof/services/api/internal/store"
	crdbpgx "github.com/cockroachdb/cockroach-go/v2/crdb/crdbpgxv5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrAlreadyErased is returned when the subject has no key row (already erased, or never existed).
var ErrAlreadyErased = errors.New("subject key already destroyed")

// Action and LawfulBasis are the controlled vocabularies written into the permanent, hash-chained
// decision log. They are validated before anything is hashed so the retained compliance record
// only ever contains defensible values. Note: these Go consts do not bind the Python verifier;
// keep the string literals identical on both sides.
type (
	Action      string
	LawfulBasis string
)

const (
	ActionErasure Action = "erasure"
	ActionIngest  Action = "ingest"

	LawfulBasisGDPRArt17  LawfulBasis = "gdpr_art_17"
	LawfulBasisAIActArt19 LawfulBasis = "ai_act_art_19"
	LawfulBasisMiFIDII    LawfulBasis = "mifid_ii"
)

// Valid reports whether the action is in the controlled vocabulary.
func (a Action) Valid() bool {
	switch a {
	case ActionErasure, ActionIngest:
		return true
	}
	return false
}

// Valid reports whether the lawful basis is in the controlled vocabulary.
func (b LawfulBasis) Valid() bool {
	switch b {
	case LawfulBasisGDPRArt17, LawfulBasisAIActArt19, LawfulBasisMiFIDII:
		return true
	}
	return false
}

// Query names the erasure closure depends on. RequiredQueries lets main assert at startup that the
// loaded query set is complete, turning a would-be hot-path panic into a boot-time failure.
const (
	qLockSubjectKey      = "lock_subject_key"
	qChainHead           = "chain_head"
	qInsertDecision      = "insert_decision"
	qDeleteSubjectKey    = "delete_subject_key"
	qNullEmbeddings      = "null_embeddings"
	qInsertErasureRecord = "insert_erasure_record"
	qErasureRecordExists = "erasure_record_exists"
	qSetProofRef         = "set_proof_ref"
	qUnanchoredErasures  = "unanchored_erasures"
	qDecisionLogLeaves   = "decision_log_leaves"
)

// RequiredQueries is the set of named statements the erasure path and its post-commit anchoring and
// reconciler look up; pass it to store.Queries.Require at startup.
var RequiredQueries = []string{
	qLockSubjectKey, qChainHead, qInsertDecision, qDeleteSubjectKey,
	qNullEmbeddings, qInsertErasureRecord, qErasureRecordExists,
	qSetProofRef, qUnanchoredErasures, qDecisionLogLeaves,
}

// ErrSubjectNotFound is returned when neither a key row nor a prior erasure record exists for the
// subject (a mistyped or unknown id). It is distinct from ErrAlreadyErased so a caller cannot
// mistake "did nothing because the id was wrong" for "already handled".
var ErrSubjectNotFound = errors.New("unknown subject")

// Result reports what the committed transaction recorded, plus the key metadata the post-commit
// proof and kill switch need (captured before the key row was deleted).
type Result struct {
	Seq         int64  `json:"decision_log_seq"`
	SubjectHash []byte `json:"subject_hash"`
	Fingerprint []byte `json:"wrapped_key_fingerprint"`
	ChainHead   []byte `json:"decision_log_head"`
	KMSKeyARN   string `json:"kms_key_arn"`
	KeyOrigin   string `json:"key_origin"` // GENERATE_DATA_KEY | IMPORTED_MATERIAL
	// OccurredAt is the decision-log row's own timestamp. The signed proof states THIS time, not
	// anchor time: the reconcile path can anchor hours after the erasure actually happened.
	OccurredAt time.Time `json:"occurred_at"`
}

// Service runs erasures against the operator pool.
type Service struct {
	pool *pgxpool.Pool
	q    store.Queries
}

// New builds a Service from a store. It uses the operator pool (the least-privileged role that may
// execute the erasure procedure).
func New(s *store.Store) *Service {
	return &Service{pool: s.Operator, q: s.Q}
}

// Erase destroys the subject's key and atomically retains a hash-chained decision-log row.
//
// Everything below runs inside crdbpgx.ExecuteTx, which retries on a 40001 serialization failure.
// The closure is PURE database work plus in-memory hashing: it makes NO network call (KMS, S3,
// cryptod), so re-running it on a retry is always safe. Cryptographic signing and S3 anchoring
// happen after this returns, outside the transaction.
func (svc *Service) Erase(ctx context.Context, subjectID string, action Action, lawfulBasis LawfulBasis) (Result, error) {
	if !action.Valid() {
		return Result{}, fmt.Errorf("invalid action %q", action)
	}
	if !lawfulBasis.Valid() {
		return Result{}, fmt.Errorf("invalid lawful basis %q", lawfulBasis)
	}

	var res Result
	err := crdbpgx.ExecuteTx(ctx, svc.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		// 1. Lock the subject key row and capture the fields the post-commit proof needs.
		var fingerprint []byte
		var kmsKeyARN, keyOrigin string
		err := tx.QueryRow(ctx, svc.q.MustGet(qLockSubjectKey), subjectID).
			Scan(&fingerprint, &kmsKeyARN, &keyOrigin)
		if errors.Is(err, pgx.ErrNoRows) {
			// No key row: distinguish an already-erased subject from an unknown id.
			var erased bool
			if e := tx.QueryRow(ctx, svc.q.MustGet(qErasureRecordExists), subjectID).Scan(&erased); e != nil {
				return fmt.Errorf("check erasure record: %w", e)
			}
			if erased {
				return ErrAlreadyErased
			}
			return ErrSubjectNotFound
		}
		if err != nil {
			return fmt.Errorf("lock subject key: %w", err)
		}

		// 2. Read the decision-log chain head (no rows = genesis).
		var seq int64
		var prevHash []byte
		err = tx.QueryRow(ctx, svc.q.MustGet(qChainHead)).Scan(&seq, &prevHash)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			seq, prevHash = 0, chain.GenesisPrevHash()
		case err != nil:
			return fmt.Errorf("read chain head: %w", err)
		}
		newSeq := seq + 1
		subjectHash := chain.SubjectHash(subjectID)
		rowHash := chain.Link(prevHash, newSeq, string(action), string(lawfulBasis), subjectHash)

		// 3. Append the pseudonymized, hash-chained decision-log row, capturing its occurred_at so
		// the signed proof can state the erasure's actual time (not anchor time). Scanned into a
		// local so the Result literal below cannot drop it (the 2026-07-10 rehearsal caught a
		// signed proof carrying the zero time exactly that way).
		var occurredAt time.Time
		if err := tx.QueryRow(ctx, svc.q.MustGet(qInsertDecision),
			newSeq, subjectHash, string(action), string(lawfulBasis), prevHash, rowHash).Scan(&occurredAt); err != nil {
			return fmt.Errorf("insert decision: %w", err)
		}

		// 4. The crypto-shred: delete the only wrapped copy of the subject key.
		if _, err := tx.Exec(ctx, svc.q.MustGet(qDeleteSubjectKey), subjectID); err != nil {
			return fmt.Errorf("delete subject key: %w", err)
		}

		// 5. Purge the live plaintext vector (the durable ciphertext copy stays as provable noise).
		if _, err := tx.Exec(ctx, svc.q.MustGet(qNullEmbeddings), subjectID); err != nil {
			return fmt.Errorf("null embeddings: %w", err)
		}

		// 6. Record the erasure (retaining the KMS ARN so the reconciler can anchor the proof).
		if _, err := tx.Exec(ctx, svc.q.MustGet(qInsertErasureRecord),
			subjectID, newSeq, fingerprint, kmsKeyARN); err != nil {
			return fmt.Errorf("insert erasure record: %w", err)
		}

		res = Result{
			Seq: newSeq, SubjectHash: subjectHash, Fingerprint: fingerprint, ChainHead: rowHash,
			KMSKeyARN: kmsKeyARN, KeyOrigin: keyOrigin, OccurredAt: occurredAt,
		}
		return nil
	})
	return res, err
}
