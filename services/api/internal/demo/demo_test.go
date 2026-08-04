package demo_test

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/StephenSook/erasure-proof/services/api/internal/agent"
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
	entered  chan struct{} // if set, InvertLive signals here AFTER the caller acquired its slot
	liveWait chan struct{} // if set, InvertLive blocks on it (to exercise the concurrency guard)
}

func (s stubInverter) Invert(context.Context) (map[string]any, error) { return s.resp, nil }

func (s stubInverter) InvertLive(_ context.Context, embeddingB64 string) (map[string]any, error) {
	// Signaling here (not in the goroutine before the call) means the caller has already passed the
	// semaphore + budget guards and is truly holding a slot, so the test can wait for exactly N
	// slots to be held before probing for the busy signal.
	if s.entered != nil {
		s.entered <- struct{}{}
	}
	if s.liveWait != nil {
		<-s.liveWait
	}
	// Echo the received bytes back so a test can assert the pass-through.
	return map[string]any{"source": "live_gpu", "recovered_text": "name", "echo_b64": embeddingB64}, nil
}

func (s stubInverter) InvertConfig(context.Context) (map[string]any, error) {
	return map[string]any{"live_available": true}, nil
}

func (s stubInverter) EmbedLive(_ context.Context, text string) (map[string]any, error) {
	// A deterministic 3072-byte vector derived from the text length, so tests can assert a store.
	emb := bytesRepeat(byte(len(text)%256), 3072)
	return map[string]any{"embedding_b64": base64.StdEncoding.EncodeToString(emb), "echo_text": text}, nil
}

func (s stubInverter) EmbedConfig(context.Context) (map[string]any, error) {
	return map[string]any{"embed_available": true}, nil
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
	// The C-SPANN index (migration 0003), so the search test can assert index_used from a live
	// EXPLAIN: the wired-or-cut proof that "Distributed Vector Indexing" is real, not claimed.
	// SET CLUSTER SETTING cannot run inside a multi-statement batch, so apply the pieces
	// separately rather than the raw migration file.
	if _, err := admin.Exec(ctx, "SET CLUSTER SETTING feature.vector_index.enabled = true"); err != nil {
		t.Fatalf("enable vector index feature: %v", err)
	}
	if _, err := admin.Exec(ctx,
		"SET sql_safe_updates = false; CREATE VECTOR INDEX IF NOT EXISTS mem_idx ON agent_memory (subject_id, embedding); SET sql_safe_updates = true"); err != nil {
		t.Fatalf("create vector index: %v", err)
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

func TestSearch_FindsBeforeErasureAndNothingAfter(t *testing.T) {
	st, admin := setup(t)
	id := seedSubject(t, admin)
	svc := demo.New(st, stubInverter{})
	ctx := context.Background()

	// The query vector is the exact stored one (0.01 x 768) in the ingest wire format, so the
	// nearest neighbour is the seeded memory itself at distance ~0.
	raw := make([]byte, 768*4)
	bits := math.Float32bits(0.01)
	for i := 0; i < 768; i++ {
		binary.LittleEndian.PutUint32(raw[i*4:], bits)
	}
	q := base64.StdEncoding.EncodeToString(raw)

	before, err := svc.Search(ctx, id, q, 3)
	if err != nil {
		t.Fatalf("search before erasure: %v", err)
	}
	if len(before.Results) != 1 {
		t.Fatalf("results before erasure = %d, want 1", len(before.Results))
	}
	if before.Results[0].Distance > 1e-6 {
		t.Errorf("distance = %v, want ~0 (query is the stored vector)", before.Results[0].Distance)
	}
	// setup applies migration 0003, so the plan MUST use the C-SPANN index; this is the
	// wired-or-cut proof for the "Distributed Vector Indexing" claim, read from a live EXPLAIN.
	if !before.IndexUsed {
		t.Errorf("index_used = false, want the C-SPANN plan (explain line %q)", before.ExplainLine)
	}
	if !strings.Contains(before.ExplainLine, "mem_idx") {
		t.Errorf("explain line %q does not name mem_idx", before.ExplainLine)
	}

	// The erasure transaction sets the live vector to NULL; simulate that destruction directly.
	if _, err := admin.Exec(ctx, `UPDATE agent_memory SET embedding = NULL WHERE subject_id = $1`, id); err != nil {
		t.Fatal(err)
	}
	after, err := svc.Search(ctx, id, q, 3)
	if err != nil {
		t.Fatalf("search after erasure: %v", err)
	}
	if len(after.Results) != 0 {
		t.Fatalf("results after erasure = %d, want 0 (the vector no longer exists)", len(after.Results))
	}
}

func TestTimeTravel_DeletedRowStillReadableInThePast(t *testing.T) {
	st, _ := setup(t)
	svc := demo.New(st, stubInverter{})

	v, err := svc.TimeTravel(context.Background())
	if err != nil {
		t.Fatalf("TimeTravel: %v", err)
	}
	if v.NormalReadRows != 0 {
		t.Errorf("normal read rows = %d, want 0 (the row was deleted)", v.NormalReadRows)
	}
	if v.TimeTravelRows != 1 {
		t.Errorf("time-travel rows = %d, want 1 (MVCC history within the GC window)", v.TimeTravelRows)
	}
	if v.AsOf == "" || v.SubjectID == "" {
		t.Errorf("view missing fields: %+v", v)
	}
}

func TestSearch_ErasedRowDoesNotDropLiveResults(t *testing.T) {
	// Regression for the NULLS-FIRST + LIMIT footgun: CockroachDB sorts NULL distances first, so an
	// erased row (embedding NULL) under the scan plan must not consume a top-k slot and hide a live
	// memory. Seed k+1 memories for one subject, NULL one, and require all k live rows to come back.
	st, admin := setup(t)
	id := seedSubject(t, admin) // memory #1 (vector 0.01 x 768)
	svc := demo.New(st, stubInverter{})
	ctx := context.Background()

	// Add three more memories with distinct vectors so distances differ.
	for _, val := range []string{"0.02", "0.03", "0.04"} {
		lit := "[" + strings.Repeat(val+",", 767) + val + "]"
		if _, err := admin.Exec(ctx,
			`INSERT INTO agent_memory (subject_id, content_ciphertext, embedding, embedding_ciphertext,
				nonce_content, nonce_embedding, wrapped_key)
			 VALUES ($1, b'\x01', $2, b'\x02', b'\x03', b'\x04', b'\x05')`, id, lit); err != nil {
			t.Fatal(err)
		}
	}
	// Erase exactly one of the four (NULL its vector), simulating a partial-subject erasure.
	if _, err := admin.Exec(ctx,
		`UPDATE agent_memory SET embedding = NULL WHERE subject_id = $1 AND ctid IN
		 (SELECT ctid FROM agent_memory WHERE subject_id = $1 LIMIT 1)`, id); err != nil {
		// ctid is not a CockroachDB column; fall back to NULLing by the lowest id.
		if _, e2 := admin.Exec(ctx,
			`UPDATE agent_memory SET embedding = NULL WHERE id = (SELECT id FROM agent_memory WHERE subject_id = $1 ORDER BY id LIMIT 1)`, id); e2 != nil {
			t.Fatal(e2)
		}
	}

	raw := make([]byte, 768*4)
	binary.LittleEndian.PutUint32(raw, math.Float32bits(0.02))
	for i := 1; i < 768; i++ {
		binary.LittleEndian.PutUint32(raw[i*4:], math.Float32bits(0.02))
	}
	q := base64.StdEncoding.EncodeToString(raw)

	res, err := svc.Search(ctx, id, q, 3)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	// Three live memories remain; k=3 must return all three, none dropped by the NULL row.
	if len(res.Results) != 3 {
		t.Fatalf("results = %d, want 3 live memories (the erased NULL row must not steal a slot)", len(res.Results))
	}
}

func TestSearch_RejectsBadEmbedding(t *testing.T) {
	st, _ := setup(t)
	svc := demo.New(st, stubInverter{})
	if _, err := svc.Search(context.Background(), "00000000-0000-0000-0000-000000000000", "not-base64!!", 3); err == nil {
		t.Fatal("want an error for a malformed query vector")
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

	inc, err := svc.Inclusion(ctx, 2, 0)
	if err != nil {
		t.Fatalf("Inclusion: %v", err)
	}
	if inc.LeafIndex != 1 || inc.TreeSize != 3 {
		t.Fatalf("inclusion = %+v, want leaf index 1 in a tree of 3", inc)
	}
	if inc.Root != th.Root {
		t.Error("inclusion root must equal the tree-head root")
	}

	// Inclusion within the SIGNED tree size 2 (before the third row): leaf still present, but the
	// root is the size-2 root, which a signed proof of that era would have committed to.
	inc2, err := svc.Inclusion(ctx, 2, 2)
	if err != nil {
		t.Fatalf("Inclusion(size=2): %v", err)
	}
	if inc2.TreeSize != 2 || inc2.Root == th.Root {
		t.Errorf("size-restricted inclusion = %+v, want tree size 2 and a different (earlier) root", inc2)
	}

	// Consistency: the size-2 tree must be an append-only prefix of the current size-3 tree.
	cons, err := svc.Consistency(ctx, 2, 0)
	if err != nil {
		t.Fatalf("Consistency: %v", err)
	}
	cp := make([][]byte, len(cons.Proof))
	for i, p := range cons.Proof {
		cp[i], _ = hex.DecodeString(p)
	}
	rf, _ := hex.DecodeString(cons.RootFrom)
	rt, _ := hex.DecodeString(cons.RootTo)
	if !merkle.VerifyConsistency(cons.SizeFrom, cons.SizeTo, cp, rf, rt) {
		t.Error("the returned consistency proof did not verify")
	}
	if r2, _ := hex.DecodeString(inc2.Root); !bytesEqual(rf, r2) {
		t.Error("consistency RootFrom must equal the size-2 inclusion root")
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

	if _, err := svc.Inclusion(ctx, 99, 0); !errors.Is(err, demo.ErrNotFound) {
		t.Errorf("Inclusion(unknown seq) = %v, want ErrNotFound", err)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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

func TestForensicsAgent_UnavailableWithoutConverser(t *testing.T) {
	svc := demo.New(&store.Store{}, stubInverter{})
	if svc.ForensicsAvailable() {
		t.Error("forensics agent should be unavailable until a converser is wired")
	}
	if _, err := svc.ForensicsAudit(context.Background(), "s1"); !errors.Is(err, demo.ErrForensicsUnavailable) {
		t.Errorf("want ErrForensicsUnavailable, got %v", err)
	}
}

// stubTitan records the text it was asked to embed and returns a fixed embedding.
type stubTitan struct{ lastText string }

func (s *stubTitan) EmbedText(_ context.Context, text string) (agent.TitanEmbedding, error) {
	s.lastText = text
	return agent.TitanEmbedding{
		ModelID: "amazon.titan-embed-text-v2:0", Dimensions: 1024,
		EmbeddingB64: "AAAA", Sha256: "ab" + "cd", TokenCount: 7,
	}, nil
}

func TestTitanEmbed_UnavailableWithoutEmbedder(t *testing.T) {
	svc := demo.New(&store.Store{}, stubInverter{})
	if svc.TitanAvailable() {
		t.Error("titan should be unavailable until an embedder is wired")
	}
	if _, err := svc.TitanEmbed(context.Background(), "hello"); !errors.Is(err, demo.ErrTitanUnavailable) {
		t.Errorf("want ErrTitanUnavailable, got %v", err)
	}
}

func TestTitanEmbed_SharesAgentBudgetAndTruncates(t *testing.T) {
	svc := demo.New(&store.Store{}, stubInverter{})
	stub := &stubTitan{}
	svc.SetTitanEmbedder(stub)
	base := time.Unix(1_700_000_000, 0)
	svc.SetNowForTest(func() time.Time { return base })

	// An oversized input is bounded before it reaches Bedrock.
	long := strings.Repeat("x", 2000)
	if _, err := svc.TitanEmbed(context.Background(), long); err != nil {
		t.Fatalf("titan embed: %v", err)
	}
	if len(stub.lastText) != 1000 {
		t.Errorf("embedded text length = %d, want truncated to 1000", len(stub.lastText))
	}

	// Titan draws on the SAME rolling-hour agent budget as forensics/memory-writer (one Bedrock
	// quota, one guard); exhausting it via Titan refuses the next call.
	for i := 1; i < demo.ForensicsMaxPerHourForTest; i++ {
		if _, err := svc.TitanEmbed(context.Background(), "hi"); err != nil {
			t.Fatalf("run %d within budget failed: %v", i, err)
		}
	}
	if _, err := svc.TitanEmbed(context.Background(), "hi"); !errors.Is(err, demo.ErrForensicsBudget) {
		t.Fatalf("want ErrForensicsBudget after exhausting the shared budget, got %v", err)
	}
	// The window rolls: allowed again an hour later.
	svc.SetNowForTest(func() time.Time { return base.Add(61 * time.Minute) })
	if _, err := svc.TitanEmbed(context.Background(), "hi"); err != nil {
		t.Fatalf("want a fresh allowance after the window rolled, got %v", err)
	}
}

func TestInversionLive_HourlyBudgetGuard(t *testing.T) {
	svc := demo.New(&store.Store{}, stubInverter{})
	// Freeze the clock so the rolling window is deterministic.
	base := time.Unix(1_700_000_000, 0)
	svc.SetNowForTest(func() time.Time { return base })
	emb := base64.StdEncoding.EncodeToString(bytesRepeat(0x01, 3072))

	// Exhaust the hourly budget, then the next call is refused with ErrLiveInversionBudget.
	for i := 0; i < demo.LiveInvertMaxPerHourForTest; i++ {
		if _, err := svc.InversionLive(context.Background(), emb); err != nil {
			t.Fatalf("run %d within budget failed: %v", i, err)
		}
	}
	if _, err := svc.InversionLive(context.Background(), emb); !errors.Is(err, demo.ErrLiveInversionBudget) {
		t.Fatalf("want ErrLiveInversionBudget after exhausting the budget, got %v", err)
	}
	// An hour and a bit later, the window has rolled and calls are allowed again.
	svc.SetNowForTest(func() time.Time { return base.Add(61 * time.Minute) })
	if _, err := svc.InversionLive(context.Background(), emb); err != nil {
		t.Fatalf("want a fresh allowance after the window rolled, got %v", err)
	}
}

func TestInversionLive_ConcurrencyGuard(t *testing.T) {
	// Two slots. Fill both with blocked calls, then a third must get ErrLiveInversionBusy.
	// entered fires only after a call has actually acquired its slot, so we wait for both slots to
	// be held before probing. (The probe must not itself acquire a slot and block on the gate.)
	gate := make(chan struct{})
	entered := make(chan struct{}, 2)
	svc := demo.New(&store.Store{}, stubInverter{liveWait: gate, entered: entered})
	emb := base64.StdEncoding.EncodeToString(bytesRepeat(0x01, 3072))

	for i := 0; i < 2; i++ {
		go func() { _, _ = svc.InversionLive(context.Background(), emb) }()
	}
	<-entered // both goroutines have acquired their slots and are blocked in the stub
	<-entered

	// Both slots are held, so a third call is deterministically refused (never reaches the stub).
	if _, err := svc.InversionLive(context.Background(), emb); !errors.Is(err, demo.ErrLiveInversionBusy) {
		close(gate)
		t.Fatalf("expected ErrLiveInversionBusy while both slots were held, got %v", err)
	}
	close(gate) // release the two goroutines
}

func TestLiveInversionJob_StartPollsToDone_SingleFlight(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 2)
	svc := demo.New(&store.Store{}, stubInverter{entered: entered, liveWait: release})

	// A bad payload errors at start time (the START request carries it, never a poll).
	if job := svc.StartLiveInversion("not-base64!"); job.State != "error" {
		t.Fatalf("bad payload: want error state, got %+v", job)
	}

	emb := base64.StdEncoding.EncodeToString(bytesRepeat(0x33, 3072))
	if job := svc.StartLiveInversion(emb); job.State != "running" {
		t.Fatalf("start: want running, got %+v", job)
	}
	<-entered // the background run is now holding its GPU slot
	// A second start while one runs is single-flight: it reports the running job and does not
	// bill a second GPU container.
	if job := svc.StartLiveInversion(emb); job.State != "running" {
		t.Fatalf("second start: want running, got %+v", job)
	}
	if job := svc.LiveInversionStatus(); job.State != "running" {
		t.Fatalf("status mid-run: want running, got %+v", job)
	}
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		job := svc.LiveInversionStatus()
		if job.State == "done" {
			if job.Result["recovered_text"] != "name" {
				t.Fatalf("done result: %+v", job.Result)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("job never reached done; last %+v", job)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if extra := len(entered); extra != 0 {
		t.Fatalf("expected exactly one GPU call, found %d extra", extra)
	}
}
