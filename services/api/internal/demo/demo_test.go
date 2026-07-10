package demo_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/StephenSook/erasure-proof/services/api/internal/chain"
	"github.com/StephenSook/erasure-proof/services/api/internal/demo"
	"github.com/StephenSook/erasure-proof/services/api/internal/merkle"
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

type stubInverter struct {
	resp     map[string]any
	liveWait chan struct{} // if set, InvertLive blocks on it (to exercise the concurrency guard)
}

func (s stubInverter) Invert(context.Context) (map[string]any, error) { return s.resp, nil }

func (s stubInverter) InvertLive(_ context.Context, embeddingB64 string) (map[string]any, error) {
	if s.liveWait != nil {
		<-s.liveWait
	}
	// Echo the received bytes back so a test can assert the pass-through.
	return map[string]any{"source": "live_gpu", "recovered_text": "name", "echo_b64": embeddingB64}, nil
}

func (s stubInverter) InvertConfig(context.Context) (map[string]any, error) {
	return map[string]any{"live_available": true}, nil
}

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

	for _, m := range []string{"0001_schema.sql", "0005_proof_document.sql"} {
		schema, err := os.ReadFile(filepath.Join(root, "db", "migrations", m))
		if err != nil {
			t.Fatalf("read %s: %v", m, err)
		}
		if _, err := admin.Exec(ctx, string(schema)); err != nil {
			t.Fatalf("apply %s: %v", m, err)
		}
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

func TestTreeHeadAndInclusion(t *testing.T) {
	st, admin := setup(t)
	id := seedSubject(t, admin)
	svc := demo.New(st, stubInverter{})
	ctx := context.Background()

	prev := chain.GenesisPrevHash()
	prev = appendDecision(t, admin, 1, id, "ingest", "gdpr_art_17", prev)
	prev = appendDecision(t, admin, 2, id, "erasure", "gdpr_art_17", prev)
	appendDecision(t, admin, 3, id, "ingest", "gdpr_art_17", prev)

	th, err := svc.TreeHead(ctx)
	if err != nil {
		t.Fatalf("TreeHead: %v", err)
	}
	if th.TreeSize != 3 || len(th.Root) != 64 {
		t.Fatalf("tree head = %+v, want size 3 and a 64-hex root", th)
	}

	inc, err := svc.Inclusion(ctx, 2)
	if err != nil {
		t.Fatalf("Inclusion: %v", err)
	}
	if inc.LeafIndex != 1 || inc.TreeSize != 3 {
		t.Fatalf("inclusion = %+v, want leaf index 1 in a tree of 3", inc)
	}
	if inc.Root != th.Root {
		t.Error("inclusion root must equal the tree-head root")
	}

	// Verify the audit proof exactly as a client would, with the merkle package.
	leafHash, _ := hex.DecodeString(inc.LeafHash)
	root, _ := hex.DecodeString(inc.Root)
	path := make([][]byte, len(inc.AuditPath))
	for i, p := range inc.AuditPath {
		path[i], _ = hex.DecodeString(p)
	}
	if !merkle.VerifyInclusion(leafHash, inc.LeafIndex, inc.TreeSize, path, root) {
		t.Error("the returned inclusion proof did not verify")
	}
	// A tampered leaf must not verify against the same path and root.
	if merkle.VerifyInclusion(bytesRepeat(0xff, 32), inc.LeafIndex, inc.TreeSize, path, root) {
		t.Error("a tampered leaf verified against the proof")
	}

	if _, err := svc.Inclusion(ctx, 99); !errors.Is(err, demo.ErrNotFound) {
		t.Errorf("Inclusion(unknown seq) = %v, want ErrNotFound", err)
	}
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
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

func TestInversionLive_ValidatesLengthAndProxies(t *testing.T) {
	svc := demo.New(&store.Store{}, stubInverter{})
	// Wrong length is rejected before any GPU call.
	if _, err := svc.InversionLive(context.Background(), base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Error("expected a length error for a non-3072-byte embedding")
	}
	// A correct 3072-byte embedding proxies through and the exact bytes reach the worker.
	emb := base64.StdEncoding.EncodeToString(bytesRepeat(0x22, 3072))
	got, err := svc.InversionLive(context.Background(), emb)
	if err != nil {
		t.Fatalf("InversionLive: %v", err)
	}
	if got["source"] != "live_gpu" || got["echo_b64"] != emb {
		t.Errorf("got %v, want live_gpu source echoing the exact embedding", got)
	}
}

func TestInversionLive_ConcurrencyGuard(t *testing.T) {
	// Two slots. Fill both with blocked calls, then a third must get ErrLiveInversionBusy.
	gate := make(chan struct{})
	svc := demo.New(&store.Store{}, stubInverter{liveWait: gate})
	emb := base64.StdEncoding.EncodeToString(bytesRepeat(0x01, 3072))

	started := make(chan struct{}, 2)
	for i := 0; i < 2; i++ {
		go func() {
			started <- struct{}{}
			_, _ = svc.InversionLive(context.Background(), emb)
		}()
	}
	<-started
	<-started
	// Give the two goroutines a moment to acquire both semaphore slots before probing the third.
	for i := 0; i < 100; i++ {
		if _, err := svc.InversionLive(context.Background(), emb); errors.Is(err, demo.ErrLiveInversionBusy) {
			close(gate)
			return
		}
		time.Sleep(time.Millisecond)
	}
	close(gate)
	t.Error("expected ErrLiveInversionBusy while both slots were held")
}
