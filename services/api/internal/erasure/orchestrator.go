package erasure

import (
	"context"
	"encoding/base64"
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
}

// NewOrchestrator builds an Orchestrator over the store and a cryptod client.
func NewOrchestrator(s *store.Store, crypto cryptoclient.Client) *Orchestrator {
	return &Orchestrator{svc: New(s), crypto: crypto, store: s}
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
		hex.EncodeToString(res.Fingerprint), res.KMSKeyARN, keyState,
		res.OccurredAt.UTC().Format(time.RFC3339))
	return res, proofRef, aerr
}

// anchorProof signs and anchors the proof via cryptod, then records the proof only on success.
// occurredAt is the decision log's own timestamp, NOT anchor time: the reconcile path can run
// hours after the erasure, and a signed compliance artifact must state when the erasure actually
// happened.
func (o *Orchestrator) anchorProof(
	ctx context.Context, subjectID string, seq int64,
	subjectHashHex, chainHeadHex, fingerprintHex, kmsKeyARN, keyState, occurredAt string,
) (string, error) {
	ar, err := o.crypto.Anchor(ctx, cryptoclient.AnchorRequest{
		SubjectHash:           subjectHashHex,
		OccurredAt:            occurredAt,
		DecisionLogSeq:        seq,
		ChainHead:             chainHeadHex,
		WrappedKeyFingerprint: fingerprintHex,
		KMSKeyARN:             kmsKeyARN,
		KeyState:              keyState,
	})
	if err != nil {
		return "", fmt.Errorf("anchor: %w", err)
	}
	// Fail closed on an incomplete response: storing an empty body/signature/key would satisfy the
	// NOT NULL-free columns, mark the row anchored (proof_ref set), and strand it in a permanent
	// "pending" that the reconciler never revisits.
	if ar.ProofCanonical == "" || ar.Signature == "" || ar.SignerPublicKeyPEM == "" {
		return "", fmt.Errorf("anchor response incomplete (canonical/signature/key); leaving row for the reconciler")
	}
	// proof_body is the EXACT canonical bytes the signature covers; the browser verifier checks
	// them verbatim, so decode and store exactly what cryptod returned.
	proofBody, err := base64.StdEncoding.DecodeString(ar.ProofCanonical)
	if err != nil {
		return "", fmt.Errorf("decode proof_canonical: %w", err)
	}
	tag, err := o.store.Operator.Exec(ctx, o.store.Q.MustGet(qSetProofRef),
		subjectID, ar.ProofRef, string(proofBody), ar.Signature, ar.SignerPublicKeyPEM)
	if err != nil {
		return ar.ProofRef, fmt.Errorf("record proof: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ar.ProofRef, fmt.Errorf("record proof: erasure_record row missing for subject")
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
		occurredAt                                                         time.Time
	}
	var todo []pending
	for rows.Next() {
		var subjectID string
		var seq int64
		var fingerprint, subjectHash, chainHead []byte
		var kmsKeyARN *string
		var occurredAt time.Time
		if err := rows.Scan(&subjectID, &seq, &fingerprint, &kmsKeyARN, &subjectHash, &chainHead, &occurredAt); err != nil {
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
			occurredAt:     occurredAt,
		})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	anchored := 0
	for _, p := range todo {
		// key_state: the primary erasure (wrapped key row deleted) always happened, so this is true
		// for every reconciled row. For imported-material subjects whose second kill switch failed
		// on the live path it UNDER-reports (the shred outcome is not persisted on erasure_record
		// yet); it never overclaims. occurred_at is the decision log's own timestamp.
		if _, err := o.anchorProof(ctx, p.subjectID, p.seq, p.subjectHashHex, p.chainHeadHex,
			p.fingerprintHex, p.kmsKeyARN, "wrapped_key_destroyed",
			p.occurredAt.UTC().Format(time.RFC3339)); err != nil {
			continue // leave it for the next run
		}
		anchored++
	}
	return anchored, nil
}
