// Package chain computes the decision-log hash chain. The Python forensics verifier recomputes the
// identical bytes, so the canonical form defined here is a cross-language contract: keep it and the
// verifier in lockstep.
package chain

import (
	"crypto/sha256"
	"fmt"
)

// GenesisPrevHash returns the prev_hash of the first decision-log row (32 zero bytes). It returns
// a fresh slice each call so no caller can mutate a shared package-global.
func GenesisPrevHash() []byte { return make([]byte, 32) }

// SubjectHash pseudonymizes a subject id for the decision log: SHA-256 over the id's string form.
// No raw personal identifier ever reaches the retained log.
func SubjectHash(subjectID string) []byte {
	h := sha256.Sum256([]byte(subjectID))
	return h[:]
}

// canonicalRow is the deterministic byte encoding of a decision-log row's content that is hashed
// into the chain: "seq|action|lawful_basis" followed by the raw subject-hash bytes.
func canonicalRow(seq int64, action, lawfulBasis string, subjectHash []byte) []byte {
	prefix := []byte(fmt.Sprintf("%d|%s|%s", seq, action, lawfulBasis))
	return append(prefix, subjectHash...)
}

// Link computes hash = SHA-256(prevHash || canonicalRow) for a new decision-log row.
func Link(prevHash []byte, seq int64, action, lawfulBasis string, subjectHash []byte) []byte {
	h := sha256.New()
	h.Write(prevHash)
	h.Write(canonicalRow(seq, action, lawfulBasis, subjectHash))
	return h.Sum(nil)
}
