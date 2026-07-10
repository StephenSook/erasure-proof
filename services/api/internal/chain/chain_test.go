package chain

import (
	"bytes"
	"testing"
)

func TestSubjectHashIs32Bytes(t *testing.T) {
	if got := len(SubjectHash("some-subject")); got != 32 {
		t.Errorf("subject hash length = %d, want 32", got)
	}
}

func TestLinkIsDeterministic(t *testing.T) {
	sh := SubjectHash("subject-a")
	a := Link(GenesisPrevHash(), 1, "erasure", "gdpr_art_17", sh)
	b := Link(GenesisPrevHash(), 1, "erasure", "gdpr_art_17", sh)
	if !bytes.Equal(a, b) {
		t.Error("Link is not deterministic for identical inputs")
	}
	if len(a) != 32 {
		t.Errorf("hash length = %d, want 32", len(a))
	}
}

func TestLinkChangesWithEveryField(t *testing.T) {
	sh := SubjectHash("subject-a")
	base := Link(GenesisPrevHash(), 1, "erasure", "gdpr_art_17", sh)

	cases := map[string][]byte{
		"different seq":    Link(GenesisPrevHash(), 2, "erasure", "gdpr_art_17", sh),
		"different action": Link(GenesisPrevHash(), 1, "ingest", "gdpr_art_17", sh),
		"different basis":  Link(GenesisPrevHash(), 1, "erasure", "ai_act_art_19", sh),
		"different subject": Link(GenesisPrevHash(), 1, "erasure", "gdpr_art_17",
			SubjectHash("subject-b")),
		"different prev": Link(base, 1, "erasure", "gdpr_art_17", sh),
	}
	for name, h := range cases {
		if bytes.Equal(h, base) {
			t.Errorf("%s: hash did not change", name)
		}
	}
}

func TestChainLinksTogether(t *testing.T) {
	sh := SubjectHash("s")
	h1 := Link(GenesisPrevHash(), 1, "ingest", "consent", sh)
	// The second row's prev_hash is the first row's hash.
	h2 := Link(h1, 2, "erasure", "gdpr_art_17", sh)
	if bytes.Equal(h1, h2) {
		t.Error("chained hashes collided")
	}
}
