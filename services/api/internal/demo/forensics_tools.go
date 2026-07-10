package demo

import (
	"context"
	"errors"

	"github.com/StephenSook/erasure-proof/services/api/internal/agent"
)

// ForensicsToolset exposes the demo gateway's read-only evidence methods as the agent.Tools the
// forensics agent calls. Every method returns a JSON-able map that becomes the model's evidence;
// errors are returned as {"error": ...} so the agent records them in its trace instead of crashing.
func (s *Service) ForensicsToolset() agent.Tools {
	return forensicsToolset{s}
}

type forensicsToolset struct{ s *Service }

func (t forensicsToolset) VerifyHashChain(ctx context.Context) map[string]any {
	r, err := t.s.VerifyChain(ctx)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	out := map[string]any{"intact": r.Intact, "checked": r.Checked}
	if r.BreakAtSeq != nil {
		out["break_at_seq"] = *r.BreakAtSeq
	}
	return out
}

func (t forensicsToolset) CheckErasureProof(ctx context.Context, subjectID string) map[string]any {
	p, err := t.s.Proof(ctx, subjectID)
	if errors.Is(err, ErrNotFound) {
		return map[string]any{"erasure_recorded": false}
	}
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	out := map[string]any{"erasure_recorded": true, "requested_at": p.RequestedAt}
	if p.DecisionLogSeq != nil {
		out["decision_log_seq"] = *p.DecisionLogSeq
	}
	if p.Fingerprint != nil {
		out["wrapped_key_fingerprint"] = *p.Fingerprint
	}
	if p.ProofRef != nil {
		out["proof_ref"] = *p.ProofRef
	}
	out["proof_signed"] = p.ProofBody != nil && p.ProofSignature != nil
	return out
}

func (t forensicsToolset) ConfirmKeyDestroyed(ctx context.Context, subjectID string) map[string]any {
	// The subject key row is gone iff Memory reports an empty key fingerprint; the erasure is
	// recorded iff a proof exists. Both must hold for the ciphertext to be provably unrecoverable.
	mem, memErr := t.s.Memory(ctx, subjectID)
	keyPresent := memErr == nil && mem.KeyFingerprint != ""
	if memErr != nil && !errors.Is(memErr, ErrNotFound) {
		return map[string]any{"error": memErr.Error()}
	}
	_, proofErr := t.s.Proof(ctx, subjectID)
	erasureRecorded := proofErr == nil
	if proofErr != nil && !errors.Is(proofErr, ErrNotFound) {
		return map[string]any{"error": proofErr.Error()}
	}
	return map[string]any{
		"key_row_present":  keyPresent,
		"erasure_recorded": erasureRecorded,
		"destroyed":        !keyPresent && erasureRecorded,
	}
}
