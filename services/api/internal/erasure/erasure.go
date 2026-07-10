// Package erasure runs the destroy-and-retain erasure transaction. This is the core of the whole
// project: in one SERIALIZABLE transaction it retains the pseudonymized decision log and destroys
// the subject key, or does neither.
package erasure

import (
	"context"
	"errors"
	"fmt"

	"github.com/StephenSook/erasure-proof/services/api/internal/chain"
	"github.com/StephenSook/erasure-proof/services/api/internal/store"
	crdbpgx "github.com/cockroachdb/cockroach-go/v2/crdb/crdbpgxv5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrAlreadyErased is returned when the subject has no key row (already erased, or never existed).
var ErrAlreadyErased = errors.New("subject key already destroyed")

// Result reports what the committed transaction recorded.
type Result struct {
	Seq         int64  `json:"decision_log_seq"`
	SubjectHash []byte `json:"subject_hash"`
	Fingerprint []byte `json:"wrapped_key_fingerprint"`
	ChainHead   []byte `json:"decision_log_head"`
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
func (svc *Service) Erase(ctx context.Context, subjectID, action, lawfulBasis string) (Result, error) {
	var res Result
	err := crdbpgx.ExecuteTx(ctx, svc.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		// 1. Lock the subject key row and capture the fingerprint retained in the proof.
		var fingerprint []byte
		err := tx.QueryRow(ctx, svc.q.MustGet("lock_subject_key"), subjectID).Scan(&fingerprint)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrAlreadyErased
		}
		if err != nil {
			return fmt.Errorf("lock subject key: %w", err)
		}

		// 2. Read the decision-log chain head (no rows = genesis).
		var seq int64
		var prevHash []byte
		err = tx.QueryRow(ctx, svc.q.MustGet("chain_head")).Scan(&seq, &prevHash)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			seq, prevHash = 0, chain.GenesisPrevHash
		case err != nil:
			return fmt.Errorf("read chain head: %w", err)
		}
		newSeq := seq + 1
		subjectHash := chain.SubjectHash(subjectID)
		rowHash := chain.Link(prevHash, newSeq, action, lawfulBasis, subjectHash)

		// 3. Append the pseudonymized, hash-chained decision-log row.
		if _, err := tx.Exec(ctx, svc.q.MustGet("insert_decision"),
			newSeq, subjectHash, action, lawfulBasis, prevHash, rowHash); err != nil {
			return fmt.Errorf("insert decision: %w", err)
		}

		// 4. The crypto-shred: delete the only wrapped copy of the subject key.
		if _, err := tx.Exec(ctx, svc.q.MustGet("delete_subject_key"), subjectID); err != nil {
			return fmt.Errorf("delete subject key: %w", err)
		}

		// 5. Purge the live plaintext vector (the durable ciphertext copy stays as provable noise).
		if _, err := tx.Exec(ctx, svc.q.MustGet("null_embeddings"), subjectID); err != nil {
			return fmt.Errorf("null embeddings: %w", err)
		}

		// 6. Record the erasure.
		if _, err := tx.Exec(ctx, svc.q.MustGet("insert_erasure_record"),
			subjectID, newSeq, fingerprint); err != nil {
			return fmt.Errorf("insert erasure record: %w", err)
		}

		res = Result{Seq: newSeq, SubjectHash: subjectHash, Fingerprint: fingerprint, ChainHead: rowHash}
		return nil
	})
	return res, err
}
