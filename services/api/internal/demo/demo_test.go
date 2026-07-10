package demo_test

import (
	"context"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/StephenSook/erasure-proof/services/api/internal/chain"
	"github.com/StephenSook/erasure-proof/services/api/internal/demo"
	"github.com/StephenSook/erasure-proof/services/api/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests need a CockroachDB reachable at CRDB_DSN_TEST; they skip otherwise. CI provides it.

func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..")
}

func vectorLiteral() string {
	return "[" + strings.Repeat("0.01,", 767) + "0.01]"
}

type stubInverter struct{ resp map[string]any }

func (s stubInverter) Invert(context.Context) (map[string]any, error) { return s.resp, nil }

// setup runs the demo tests in their OWN database (erasure_demo_test) so the global decision-log
// chain and the TRUNCATE here never collide with the erasure/ingest tests that share CRDB_DSN_TEST.
// It applies the schema, truncates the four tables, and returns a store plus an admin pool.
func setup(t *testing.T) (*store.Store, *pgxpool.Pool) {
	t.Helper()
	base := os.Getenv("CRDB_DSN_TEST")
	if base == "" {
		t.Skip("set CRDB_DSN_TEST to run the demo gateway test")
	}
	ctx := context.Background()
	root := repoRoot(t)

	const demoDB = "erasure_demo_test"
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse CRDB_DSN_TEST: %v", err)
	}
	// Create the isolated database from a connection to the base DSN.
	bootstrap, err := pgxpool.New(ctx, base)
	if err != nil {
		t.Fatalf("connect base: %v", err)
	}
	if _, err := bootstrap.Exec(ctx, "CREATE DATABASE IF NOT EXISTS "+demoDB); err != nil {
		bootstrap.Close()
		t.Fatalf("create demo db: %v", err)
	}
	bootstrap.Close()

	u.Path = "/" + demoDB
	dsn := u.String()

	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect demo db: %v", err)
	}
	t.Cleanup(admin.Close)

	schema, err := os.ReadFile(filepath.Join(root, "db", "migrations", "0001_schema.sql"))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	if _, err := admin.Exec(ctx, string(schema)); err != nil {
		t.Fatalf("apply schema: %v", err)
	}
	if _, err := admin.Exec(ctx,
		"TRUNCATE agent_memory, subject_keys, decision_log, erasure_record"); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	st, err := store.Open(ctx, dsn, dsn, filepath.Join(root, "db", "queries"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(st.Close)
	return st, admin
}

// seedSubject inserts one subject with a key and a memory row, returning its id.
func seedSubject(t *testing.T, admin *pgxpool.Pool) string {
	t.Helper()
	ctx := context.Background()
	var id string
	if err := admin.QueryRow(ctx, "SELECT gen_random_uuid()::string").Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx,
		`INSERT INTO subject_keys (subject_id, wrapped_key, kms_key_arn, key_origin, wrapped_key_fingerprint)
		 VALUES ($1, b'\x01\x02', 'arn:test', 'GENERATE_DATA_KEY', b'\xaa\xbb')`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx,
		`INSERT INTO agent_memory (subject_id, content_ciphertext, embedding, embedding_ciphertext,
			nonce_content, nonce_embedding, wrapped_key)
		 VALUES ($1, b'\x01\x02\x03', $2, b'\x04\x05', b'\x06', b'\x07', b'\x08')`,
		id, vectorLiteral()); err != nil {
		t.Fatal(err)
	}
	return id
}

// appendDecision inserts a hash-chained decision-log row using the same chain.Link the app uses.
func appendDecision(t *testing.T, admin *pgxpool.Pool, seq int64, subjectID, action, basis string, prev []byte) []byte {
	t.Helper()
	sh := chain.SubjectHash(subjectID)
	h := chain.Link(prev, seq, action, basis, sh)
	if _, err := admin.Exec(context.Background(),
		`INSERT INTO decision_log (seq, subject_hash, action, lawful_basis, prev_hash, hash)
		 VALUES ($1, $2, $3, $4, $5, $6)`, seq, sh, action, basis, prev, h); err != nil {
		t.Fatalf("append decision seq %d: %v", seq, err)
	}
	return h
}

func TestMemory_ShowsPreviewAndFingerprint(t *testing.T) {
	st, admin := setup(t)
	id := seedSubject(t, admin)
	svc := demo.New(st, stubInverter{})

	v, err := svc.Memory(context.Background(), id)
	if err != nil {
		t.Fatalf("Memory: %v", err)
	}
	if v.ContentLen != 3 || v.EmbeddingLen != 2 {
		t.Errorf("lengths = content %d / embedding %d, want 3 / 2", v.ContentLen, v.EmbeddingLen)
	}
	if !v.EmbeddingPresent {
		t.Error("embedding_present = false, want true (live vector seeded)")
	}
	if v.KeyFingerprint != hex.EncodeToString([]byte{0xaa, 0xbb}) {
		t.Errorf("fingerprint = %q, want aabb", v.KeyFingerprint)
	}
}

func TestMemory_UnknownSubjectNotFound(t *testing.T) {
	st, _ := setup(t)
	svc := demo.New(st, stubInverter{})
	_, err := svc.Memory(context.Background(), "00000000-0000-0000-0000-000000000000")
	if err != demo.ErrNotFound {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestProof_ReturnsRecord(t *testing.T) {
	st, admin := setup(t)
	id := seedSubject(t, admin)
	if _, err := admin.Exec(context.Background(),
		`INSERT INTO erasure_record (subject_id, decision_log_seq, wrapped_key_fingerprint, kms_key_arn, proof_ref)
		 VALUES ($1, 1, b'\xaa\xbb', 'arn:test', 's3://proofs/x.json')`, id); err != nil {
		t.Fatal(err)
	}
	svc := demo.New(st, stubInverter{})

	v, err := svc.Proof(context.Background(), id)
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}
	if v.ProofRef == nil || *v.ProofRef != "s3://proofs/x.json" {
		t.Errorf("proof_ref = %v, want the seeded uri", v.ProofRef)
	}
	if v.DecisionLogSeq == nil || *v.DecisionLogSeq != 1 {
		t.Errorf("decision_log_seq = %v, want 1", v.DecisionLogSeq)
	}
}

func TestVerifyChain_IntactThenBroken(t *testing.T) {
	st, admin := setup(t)
	id := seedSubject(t, admin)
	svc := demo.New(st, stubInverter{})

	prev := chain.GenesisPrevHash()
	prev = appendDecision(t, admin, 1, id, "ingest", "gdpr_art_17", prev)
	appendDecision(t, admin, 2, id, "erasure", "gdpr_art_17", prev)

	res, err := svc.VerifyChain(context.Background())
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !res.Intact || res.Checked != 2 || res.BreakAtSeq != nil {
		t.Fatalf("intact chain check = %+v, want intact/checked 2/no break", res)
	}

	// Tamper a row's action: the recomputed hash no longer matches the stored hash.
	if _, err := admin.Exec(context.Background(),
		"UPDATE decision_log SET action = 'tamper' WHERE seq = 2"); err != nil {
		t.Fatal(err)
	}
	res, err = svc.VerifyChain(context.Background())
	if err != nil {
		t.Fatalf("VerifyChain after tamper: %v", err)
	}
	if res.Intact {
		t.Error("intact = true after tamper, want false")
	}
	if res.BreakAtSeq == nil || *res.BreakAtSeq != 2 {
		t.Errorf("break_at_seq = %v, want 2", res.BreakAtSeq)
	}
}

func TestDecisionLog_ReturnsRowsInOrder(t *testing.T) {
	st, admin := setup(t)
	id := seedSubject(t, admin)
	svc := demo.New(st, stubInverter{})
	prev := chain.GenesisPrevHash()
	prev = appendDecision(t, admin, 1, id, "ingest", "gdpr_art_17", prev)
	appendDecision(t, admin, 2, id, "erasure", "gdpr_art_17", prev)

	rows, err := svc.DecisionLog(context.Background())
	if err != nil {
		t.Fatalf("DecisionLog: %v", err)
	}
	if len(rows) != 2 || rows[0].Seq != 1 || rows[1].Seq != 2 {
		t.Fatalf("rows = %d in wrong order: %+v", len(rows), rows)
	}
	if rows[1].Action != "erasure" {
		t.Errorf("row 2 action = %q, want erasure", rows[1].Action)
	}
}

// TestRbacDemo_RollsBackAndReportsHonestly proves the probe never mutates the log and reports the
// real result. On a root pool the role is unrestricted, so it reports denied=false, and the log is
// unchanged because the probe always rolls back.
func TestRbacDemo_RollsBackAndReportsHonestly(t *testing.T) {
	st, admin := setup(t)
	id := seedSubject(t, admin)
	appendDecision(t, admin, 1, id, "ingest", "gdpr_art_17", chain.GenesisPrevHash())
	svc := demo.New(st, stubInverter{})

	res, err := svc.RbacDemo(context.Background())
	if err != nil {
		t.Fatalf("RbacDemo: %v", err)
	}
	if res.Denied {
		t.Error("denied = true on a root pool; expected not-restricted honesty")
	}

	// The log must be untouched: the probe rolled back.
	var action string
	if err := admin.QueryRow(context.Background(),
		"SELECT action FROM decision_log WHERE seq = 1").Scan(&action); err != nil {
		t.Fatal(err)
	}
	if action != "ingest" {
		t.Errorf("decision_log seq 1 action = %q, want ingest (probe must not mutate)", action)
	}
}

func TestInversion_ProxiesGoldenRun(t *testing.T) {
	svc := demo.New(&store.Store{}, stubInverter{resp: map[string]any{"recovered_text": "a name"}})
	got, err := svc.Inversion(context.Background())
	if err != nil {
		t.Fatalf("Inversion: %v", err)
	}
	if got["recovered_text"] != "a name" {
		t.Errorf("got %v, want the stubbed golden run", got)
	}
}
