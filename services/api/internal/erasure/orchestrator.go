package erasure

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/StephenSook/erasure-proof/services/api/internal/cryptoclient"
	"github.com/StephenSook/erasure-proof/services/api/internal/store"
)

// Orchestrator runs an erasure and its post-commit anchoring, and reconciles erasures whose proof
// was never anchored. The proof_ref is recorded ONLY after cryptod confirms the anchor, so an
// anchor failure leaves the row for the reconciler rather than falsely recording a proof.
type Orchestrator struct {
	svc    *Service
	crypto cryptoclient.Client
	store  *store.Store
	now    func() time.Time
}

// NewOrchestrator builds an Orchestrator over the store and a cryptod client.
func NewOrchestrator(s *store.Store, crypto cryptoclient.Client) *Orchestrator {
	return &Orchestrator{svc: New(s), crypto: crypto, store: s, now: time.Now}
}

// EraseAndAnchor commits the erasure, then anchors a signed proof post-commit. It returns the
// Result, the proof reference (empty if anchoring did not complete), and any anchor error. A
// non-nil anchor error does NOT mean the erasure failed: the data is durably erased and the
// reconciler will anchor the proof later.
func (o *Orchestrator) EraseAndAnchor(
	ctx context.Context, subjectID string, basis LawfulBasis,
) (Result, string, error) {
	res, err := o.svc.Erase(ctx, subjectID, ActionErasure, basis)
	if err != nil {
		return res, "", err
	}

	keyState := "wrapped_key_destroyed"
	if res.KeyOrigin == "IMPORTED_MATERIAL" && res.KMSKeyARN != "" {
		sh, serr := o.crypto.Shred(ctx, res.KMSKeyARN)
		if serr != nil {
			// The wrapped key row is already deleted (the primary erasure). The imported-material
			// second kill switch did not confirm; leave the proof for the reconciler.
			return res, "", fmt.Errorf("shred: %w", serr)
		}
		keyState = sh.KeyState
	}

	proofRef, aerr := o.anchorProof(ctx, subjectID, res.Seq,
		hex.EncodeToString(res.SubjectHash), hex.EncodeToString(res.ChainHead),
		hex.EncodeToString(res.Fingerprint), res.KMSKeyARN, keyState)
	return res, proofRef, aerr
}

// anchorProof signs and anchors the proof via cryptod, then records proof_ref only on success.
func (o *Orchestrator) anchorProof(
	ctx context.Context, subjectID string, seq int64,
	subjectHashHex, chainHeadHex, fingerprintHex, kmsKeyARN, keyState string,
) (string, error) {
	ar, err := o.crypto.Anchor(ctx, cryptoclient.AnchorRequest{
		SubjectHash:           subjectHashHex,
		OccurredAt:            o.now().UTC().Format(time.RFC3339),
		DecisionLogSeq:        seq,
		ChainHead:             chainHeadHex,
		WrappedKeyFingerprint: fingerprintHex,
		KMSKeyARN:             kmsKeyARN,
		KeyState:              keyState,
	})
	if err != nil {
		return "", fmt.Errorf("anchor: %w", err)
	}
	if _, err := o.store.Operator.Exec(ctx, o.store.Q.MustGet(qSetProofRef), subjectID, ar.ProofRef); err != nil {
		return ar.ProofRef, fmt.Errorf("record proof_ref: %w", err)
	}
	return ar.ProofRef, nil
}

// Reconcile anchors every erasure whose proof was never recorded (a crash or a failed post-commit
// anchor). It anchors the proof only; it does not re-run the imported-material kill switch, since
// the wrapped key is already destroyed. Returns how many proofs it anchored. One bad row does not
// abort the sweep.
func (o *Orchestrator) Reconcile(ctx context.Context) (int, error) {
	rows, err := o.store.Operator.Query(ctx, o.store.Q.MustGet(qUnanchoredErasures))
	if err != nil {
		return 0, err
	}
	type pending struct {
		subjectID, subjectHashHex, chainHeadHex, fingerprintHex, kmsKeyARN string
		seq                                                                int64
	}
	var todo []pending
	for rows.Next() {
		var subjectID string
		var seq int64
		var fingerprint, subjectHash, chainHead []byte
		var kmsKeyARN *string
		if err := rows.Scan(&subjectID, &seq, &fingerprint, &kmsKeyARN, &subjectHash, &chainHead); err != nil {
			rows.Close()
			return 0, err
		}
		arn := ""
		if kmsKeyARN != nil {
			arn = *kmsKeyARN
		}
		todo = append(todo, pending{
			subjectID:      subjectID,
			subjectHashHex: hex.EncodeToString(subjectHash),
			chainHeadHex:   hex.EncodeToString(chainHead),
			fingerprintHex: hex.EncodeToString(fingerprint),
			kmsKeyARN:      arn,
			seq:            seq,
		})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	anchored := 0
	for _, p := range todo {
		if _, err := o.anchorProof(ctx, p.subjectID, p.seq, p.subjectHashHex, p.chainHeadHex,
			p.fingerprintHex, p.kmsKeyARN, "wrapped_key_destroyed"); err != nil {
			continue // leave it for the next run
		}
		anchored++
	}
	return anchored, nil
}
