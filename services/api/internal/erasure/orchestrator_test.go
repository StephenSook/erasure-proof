package erasure_test

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/StephenSook/erasure-proof/services/api/internal/cryptoclient"
	"github.com/StephenSook/erasure-proof/services/api/internal/erasure"
)

// stubCrypto is an in-memory cryptoclient.Client for testing the post-commit anchoring without a
// running cryptod.
type stubCrypto struct {
	anchorErr error
	shredErr  error
}

func (s *stubCrypto) Prepare(context.Context, cryptoclient.PrepareRequest) (cryptoclient.PrepareResponse, error) {
	return cryptoclient.PrepareResponse{}, nil
}

func (s *stubCrypto) Shred(context.Context, string) (cryptoclient.ShredResponse, error) {
	if s.shredErr != nil {
		return cryptoclient.ShredResponse{}, s.shredErr
	}
	return cryptoclient.ShredResponse{Destroyed: true, KeyState: "PendingImport"}, nil
}

func (s *stubCrypto) Anchor(_ context.Context, req cryptoclient.AnchorRequest) (cryptoclient.AnchorResponse, error) {
	if s.anchorErr != nil {
		return cryptoclient.AnchorResponse{}, s.anchorErr
	}
	return cryptoclient.AnchorResponse{
		ProofRef:           "s3://proofs/" + req.SubjectHash + ".json",
		ProofCanonical:     base64.StdEncoding.EncodeToString([]byte(`{"canonical":true}`)),
		Signature:          "c2lnbmF0dXJl",
		SignerPublicKeyPEM: "-----BEGIN PUBLIC KEY-----\nstub\n-----END PUBLIC KEY-----",
	}, nil
}

func TestEraseAndAnchor_RecordsProofRefOnSuccess(t *testing.T) {
	st, subjectID := setup(t)
	orch := erasure.NewOrchestrator(st, &stubCrypto{})

	res, proofRef, err := orch.EraseAndAnchor(context.Background(), subjectID, "gdpr_art_17")
	if err != nil {
		t.Fatalf("EraseAndAnchor: %v", err)
	}
	if res.Seq < 1 || proofRef == "" {
		t.Fatalf("seq=%d proofRef=%q, want seq>=1 and a proof ref", res.Seq, proofRef)
	}
	var stored *string
	if err := st.Operator.QueryRow(context.Background(),
		"SELECT proof_ref FROM erasure_record WHERE subject_id = $1", subjectID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == nil || *stored != proofRef {
		t.Errorf("stored proof_ref = %v, want %q", stored, proofRef)
	}

	// The signed proof document is stored with the record: the exact canonical bytes, the signature,
	// and the signer key, so the browser verifier can be served without an S3 round trip.
	var body, sig, pem *string
	if err := st.Operator.QueryRow(context.Background(),
		"SELECT proof_body, proof_signature, signer_pubkey_pem FROM erasure_record WHERE subject_id = $1",
		subjectID).Scan(&body, &sig, &pem); err != nil {
		t.Fatal(err)
	}
	if body == nil || *body != `{"canonical":true}` {
		t.Errorf("proof_body = %v, want the exact canonical bytes", body)
	}
	if sig == nil || *sig != "c2lnbmF0dXJl" {
		t.Errorf("proof_signature = %v, want the stub signature", sig)
	}
	if pem == nil || *pem == "" {
		t.Error("signer_pubkey_pem not stored")
	}
}

func TestEraseAndAnchor_AnchorFailureLeavesProofForReconciler(t *testing.T) {
	st, subjectID := setup(t)
	failing := erasure.NewOrchestrator(st, &stubCrypto{anchorErr: errors.New("s3 unavailable")})

	res, proofRef, err := failing.EraseAndAnchor(context.Background(), subjectID, "gdpr_art_17")
	if err == nil {
		t.Fatal("expected an anchor error")
	}
	if res.Seq < 1 {
		t.Fatalf("erasure should still have committed, got seq=%d", res.Seq)
	}
	if proofRef != "" {
		t.Errorf("proofRef = %q, want empty on anchor failure", proofRef)
	}
	// proof_ref must NOT be recorded when anchoring failed.
	var stored *string
	if err := st.Operator.QueryRow(context.Background(),
		"SELECT proof_ref FROM erasure_record WHERE subject_id = $1", subjectID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != nil {
		t.Errorf("proof_ref = %q, want NULL after a failed anchor", *stored)
	}

	// The reconciler anchors it on the next run.
	reconciling := erasure.NewOrchestrator(st, &stubCrypto{})
	n, err := reconciling.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if n < 1 {
		t.Errorf("reconciled %d, want >= 1", n)
	}
	if err := st.Operator.QueryRow(context.Background(),
		"SELECT proof_ref FROM erasure_record WHERE subject_id = $1", subjectID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == nil {
		t.Error("proof_ref still NULL after reconcile")
	}
}
