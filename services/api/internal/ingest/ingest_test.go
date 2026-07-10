package ingest_test

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
	"testing"

	"github.com/StephenSook/erasure-proof/services/api/internal/cryptoclient"
	"github.com/StephenSook/erasure-proof/services/api/internal/ingest"
	"github.com/StephenSook/erasure-proof/services/api/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests need a CockroachDB reachable at CRDB_DSN_TEST. They skip otherwise so a plain
// `go test ./...` without a database still passes; CI provides the DSN.

func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// .../services/api/internal/ingest -> up four to the repo root.
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..")
}

// validEmbeddingB64 builds a base64 of 768 little-endian float32 values, the wire format Ingest
// decodes into a pgvector literal.
func validEmbeddingB64() string {
	buf := make([]byte, 768*4)
	for i := 0; i < 768; i++ {
		binary.LittleEndian.PutUint32(buf[i*4:], math.Float32bits(0.01))
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// b64 encodes n bytes of value v as base64 (helper for well-formed fixed-length fields).
func b64(v byte, n int) string {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = v
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// validPrepareResponse mirrors the exact field lengths a real cryptod /prepare returns, so the
// ingest length validation passes. Individual tests mutate a copy to exercise the failure paths.
func validPrepareResponse() cryptoclient.PrepareResponse {
	return cryptoclient.PrepareResponse{
		ContentCiphertext:     b64(0x11, 21),   // >= 16 (GCM tag), content length is caller-chosen
		NonceContent:          b64(0x01, 12),   // 96-bit nonce
		EmbeddingCiphertext:   b64(0x21, 3088), // 3072 embedding + 16 GCM tag
		NonceEmbedding:        b64(0x02, 12),
		SubjectWrappedKey:     b64(0xaa, 128), // KMS CiphertextBlob, variable but non-empty
		SubjectKeyFingerprint: hex.EncodeToString(make([]byte, 32)),
		RowWrappedKey:         b64(0xbb, 40), // RFC 3394 wrap of a 32-byte key
		KMSKeyARN:             "arn:aws:kms:us-east-1:000000000000:key/test",
		KeyOrigin:             "GENERATE_DATA_KEY",
	}
}

// stubCrypto returns deterministic, well-formed two-level envelope material without a running
// cryptod. mutate, when set, adjusts the response to exercise a validation failure path. The AAD is
// computed from the request exactly as cryptod does (subject_id || chain_head), so the ingest-side
// exact-match validation passes.
type stubCrypto struct {
	prepareErr error
	mutate     func(*cryptoclient.PrepareResponse)
	lastReq    cryptoclient.PrepareRequest
}

func (s *stubCrypto) Prepare(_ context.Context, req cryptoclient.PrepareRequest) (cryptoclient.PrepareResponse, error) {
	if s.prepareErr != nil {
		return cryptoclient.PrepareResponse{}, s.prepareErr
	}
	s.lastReq = req
	resp := validPrepareResponse()
	head, err := hex.DecodeString(req.ChainHead)
	if err != nil {
		return cryptoclient.PrepareResponse{}, err
	}
	resp.AAD = base64.StdEncoding.EncodeToString(append([]byte(req.SubjectID), head...))
	if s.mutate != nil {
		s.mutate(&resp)
	}
	return resp, nil
}

func (s *stubCrypto) Shred(context.Context, string) (cryptoclient.ShredResponse, error) {
	return cryptoclient.ShredResponse{}, nil
}

func (s *stubCrypto) Anchor(context.Context, cryptoclient.AnchorRequest) (cryptoclient.AnchorResponse, error) {
	return cryptoclient.AnchorResponse{}, nil
}

func setup(t *testing.T) (*store.Store, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("CRDB_DSN_TEST")
	if dsn == "" {
		t.Skip("set CRDB_DSN_TEST to run the ingest integration test")
	}
	ctx := context.Background()
	root := repoRoot(t)

	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
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

	st, err := store.Open(ctx, dsn, dsn, filepath.Join(root, "db", "queries"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(st.Close)
	return st, admin
}

func TestIngest_ProvisionsSubjectAndMemory(t *testing.T) {
	st, admin := setup(t)
	stub := &stubCrypto{}
	in := ingest.New(st, stub)

	res, err := in.Ingest(context.Background(), "", "aGVsbG8=", validEmbeddingB64())
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if res.SubjectID == "" || res.MemoryID == "" {
		t.Fatalf("got subject=%q memory=%q, want both set", res.SubjectID, res.MemoryID)
	}

	ctx := context.Background()
	var keys int
	if err := admin.QueryRow(ctx,
		"SELECT count(*) FROM subject_keys WHERE subject_id = $1", res.SubjectID).Scan(&keys); err != nil {
		t.Fatal(err)
	}
	if keys != 1 {
		t.Errorf("subject_keys rows = %d, want 1", keys)
	}

	var mems int
	var embeddingPresent bool
	if err := admin.QueryRow(ctx,
		"SELECT count(*), bool_and(embedding IS NOT NULL) FROM agent_memory WHERE subject_id = $1",
		res.SubjectID).Scan(&mems, &embeddingPresent); err != nil {
		t.Fatal(err)
	}
	if mems != 1 {
		t.Errorf("agent_memory rows = %d, want 1", mems)
	}
	if !embeddingPresent {
		t.Error("live plaintext embedding was not stored for C-SPANN search")
	}

	// AAD chain binding: the stored aad_context must be exactly subject_id || the chain head ingest
	// observed and sent (the stub records the request; other tests may be appending to the shared
	// decision_log concurrently, so the head is taken from the recorded request, not re-queried).
	sentHead, err := hex.DecodeString(stub.lastReq.ChainHead)
	if err != nil {
		t.Fatalf("stub recorded non-hex chain head: %v", err)
	}
	var storedAAD []byte
	if err := admin.QueryRow(ctx,
		"SELECT aad_context FROM agent_memory WHERE subject_id = $1", res.SubjectID).Scan(&storedAAD); err != nil {
		t.Fatal(err)
	}
	want := append([]byte(res.SubjectID), sentHead...)
	if string(storedAAD) != string(want) {
		t.Errorf("aad_context = %x, want subject||sent-head %x", storedAAD, want)
	}
}

// TestIngest_BindsAADToChainHead is the non-genesis cross-check: with a real decision_log row in
// place, the Go side must scan the head, hex-encode it to cryptod, and store subject||head exactly.
// Runs in its OWN database so concurrent packages sharing CRDB_DSN_TEST cannot move the head.
func TestIngest_BindsAADToChainHead(t *testing.T) {
	base := os.Getenv("CRDB_DSN_TEST")
	if base == "" {
		t.Skip("set CRDB_DSN_TEST")
	}
	ctx := context.Background()
	root := repoRoot(t)

	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := pgxpool.New(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrap.Exec(ctx, "CREATE DATABASE IF NOT EXISTS ingest_aad_test"); err != nil {
		bootstrap.Close()
		t.Fatal(err)
	}
	bootstrap.Close()
	u.Path = "/ingest_aad_test"
	dsn := u.String()

	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	for _, m := range []string{"0001_schema.sql", "0005_proof_document.sql"} {
		schema, err := os.ReadFile(filepath.Join(root, "db", "migrations", m))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, string(schema)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := admin.Exec(ctx,
		"TRUNCATE agent_memory, subject_keys, decision_log, erasure_record"); err != nil {
		t.Fatal(err)
	}

	// Seed a known head: a decision row whose hash is 32 known bytes.
	head := make([]byte, 32)
	for i := range head {
		head[i] = byte(i + 1)
	}
	if _, err := admin.Exec(ctx,
		`INSERT INTO decision_log (seq, subject_hash, action, lawful_basis, prev_hash, hash)
		 VALUES (1, x'aa', 'ingest', 'gdpr_art_17', x'00', $1)`, head); err != nil {
		t.Fatal(err)
	}

	st, err := store.Open(ctx, dsn, dsn, filepath.Join(root, "db", "queries"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	stub := &stubCrypto{}
	in := ingest.New(st, stub)

	// Uppercase spelling in, canonical lowercase out (M1: canonicalization before encryption).
	upper := "F47AC10B-58CC-4372-A567-0E02B2C3D479"
	res, err := in.Ingest(ctx, upper, "aGVsbG8=", validEmbeddingB64())
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if res.SubjectID != "f47ac10b-58cc-4372-a567-0e02b2c3d479" {
		t.Errorf("subject_id not canonicalized: %q", res.SubjectID)
	}
	if stub.lastReq.ChainHead != hex.EncodeToString(head) {
		t.Errorf("chain head sent = %q, want %q", stub.lastReq.ChainHead, hex.EncodeToString(head))
	}

	var storedAAD []byte
	if err := admin.QueryRow(ctx,
		"SELECT aad_context FROM agent_memory WHERE subject_id = $1", res.SubjectID).Scan(&storedAAD); err != nil {
		t.Fatal(err)
	}
	want := append([]byte(res.SubjectID), head...)
	if string(storedAAD) != string(want) {
		t.Errorf("aad_context = %x, want %x", storedAAD, want)
	}
}

// TestIngest_RejectsNonCanonicalSubjectID proves malformed subject ids are refused before any pool
// or crypto use (braced/hyphenless spellings are deliberately rejected: the AAD's no-ambiguity
// argument rests on a fixed 36-byte subject prefix).
func TestIngest_RejectsNonCanonicalSubjectID(t *testing.T) {
	in := ingest.New(&store.Store{}, &stubCrypto{})
	for _, bad := range []string{
		"not-a-uuid",
		"{f47ac10b-58cc-4372-a567-0e02b2c3d479}",
		"f47ac10b58cc4372a5670e02b2c3d479",
		"f47ac10b-58cc-4372-a567-0e02b2c3d47g",
	} {
		_, err := in.Ingest(context.Background(), bad, "aGVsbG8=", validEmbeddingB64())
		if !errors.Is(err, ingest.ErrBadSubjectID) {
			t.Errorf("subject %q: error = %v, want ErrBadSubjectID", bad, err)
		}
	}
}

// TestIngest_RefusesResurrection is the load-bearing guarantee: once a subject has an erasure
// record, ingest must refuse to re-add memory, or an erased person could be silently resurrected.
func TestIngest_RefusesResurrection(t *testing.T) {
	st, admin := setup(t)
	in := ingest.New(st, &stubCrypto{})

	ctx := context.Background()
	var subjectID string
	if err := admin.QueryRow(ctx, "SELECT gen_random_uuid()::string").Scan(&subjectID); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx,
		"INSERT INTO erasure_record (subject_id) VALUES ($1)", subjectID); err != nil {
		t.Fatalf("seed erasure record: %v", err)
	}

	_, err := in.Ingest(ctx, subjectID, "aGVsbG8=", validEmbeddingB64())
	if !errors.Is(err, ingest.ErrSubjectErased) {
		t.Fatalf("error = %v, want ErrSubjectErased", err)
	}

	// The refused request must not have written a key or a memory row.
	var keys, mems int
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM subject_keys WHERE subject_id = $1", subjectID).Scan(&keys); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM agent_memory WHERE subject_id = $1", subjectID).Scan(&mems); err != nil {
		t.Fatal(err)
	}
	if keys != 0 || mems != 0 {
		t.Errorf("refused ingest still wrote: keys=%d mems=%d, want 0/0", keys, mems)
	}
}

// TestIngest_RefusesDoubleProvision proves a subject cannot be provisioned twice.
func TestIngest_RefusesDoubleProvision(t *testing.T) {
	st, _ := setup(t)
	in := ingest.New(st, &stubCrypto{})

	res, err := in.Ingest(context.Background(), "", "aGVsbG8=", validEmbeddingB64())
	if err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	_, err = in.Ingest(context.Background(), res.SubjectID, "d29ybGQ=", validEmbeddingB64())
	if !errors.Is(err, ingest.ErrAlreadyProvisioned) {
		t.Errorf("second ingest error = %v, want ErrAlreadyProvisioned", err)
	}
}

// TestIngest_RejectsBadEmbedding proves a malformed embedding is a client error, distinct from an
// internal failure, and never touches the database.
func TestIngest_RejectsBadEmbedding(t *testing.T) {
	// No DB needed: the embedding is validated before any connection is used.
	in := ingest.New(&store.Store{}, &stubCrypto{})
	_, err := in.Ingest(context.Background(), "", "aGVsbG8=", "not-base64!!")
	if !errors.Is(err, ingest.ErrBadEmbedding) {
		t.Errorf("error = %v, want ErrBadEmbedding", err)
	}
	_, err = in.Ingest(context.Background(), "", "aGVsbG8=", base64.StdEncoding.EncodeToString([]byte{0x01, 0x02}))
	if !errors.Is(err, ingest.ErrBadEmbedding) {
		t.Errorf("short embedding error = %v, want ErrBadEmbedding", err)
	}
}

// TestIngest_RejectsNonFiniteEmbedding proves a NaN/Inf dimension is rejected at the boundary as a
// client error, not passed through to fail at insert time as a 500.
func TestIngest_RejectsNonFiniteEmbedding(t *testing.T) {
	buf := make([]byte, 768*4)
	for i := 0; i < 768; i++ {
		binary.LittleEndian.PutUint32(buf[i*4:], math.Float32bits(0.01))
	}
	binary.LittleEndian.PutUint32(buf[10*4:], math.Float32bits(float32(math.NaN())))
	in := ingest.New(&store.Store{}, &stubCrypto{})
	_, err := in.Ingest(context.Background(), "", "aGVsbG8=", base64.StdEncoding.EncodeToString(buf))
	if !errors.Is(err, ingest.ErrBadEmbedding) {
		t.Errorf("error = %v, want ErrBadEmbedding for NaN dimension", err)
	}
}

// TestIngest_RejectsBadContent proves non-base64 content is a 400-class client error caught before
// cryptod is even called.
func TestIngest_RejectsBadContent(t *testing.T) {
	in := ingest.New(&store.Store{}, &stubCrypto{})
	_, err := in.Ingest(context.Background(), "", "not base64!!", validEmbeddingB64())
	if !errors.Is(err, ingest.ErrBadContent) {
		t.Errorf("error = %v, want ErrBadContent", err)
	}
}

// TestIngest_RejectsHollowCryptoMaterial is the HIGH-severity guard from the adversarial review: a
// missing/empty cryptod field decodes to empty-but-non-null bytes that would pass BYTES NOT NULL and
// silently store an undecryptable row. Ingest must refuse before opening the transaction.
func TestIngest_RejectsHollowCryptoMaterial(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*cryptoclient.PrepareResponse)
	}{
		{"empty row_wrapped_key", func(r *cryptoclient.PrepareResponse) { r.RowWrappedKey = "" }},
		{"empty subject_wrapped_key", func(r *cryptoclient.PrepareResponse) { r.SubjectWrappedKey = "" }},
		{"empty fingerprint", func(r *cryptoclient.PrepareResponse) { r.SubjectKeyFingerprint = "" }},
		{"short nonce", func(r *cryptoclient.PrepareResponse) { r.NonceContent = b64(0x01, 8) }},
		{"wrong embedding ct length", func(r *cryptoclient.PrepareResponse) { r.EmbeddingCiphertext = b64(0x21, 100) }},
		{"empty kms arn", func(r *cryptoclient.PrepareResponse) { r.KMSKeyARN = "" }},
		{"unknown key origin", func(r *cryptoclient.PrepareResponse) { r.KeyOrigin = "" }},
		{"empty aad", func(r *cryptoclient.PrepareResponse) { r.AAD = "" }},
		{"wrong aad", func(r *cryptoclient.PrepareResponse) { r.AAD = b64(0x99, 20) }},
	}
	// DB-backed: the chain-head read precedes /prepare, so these paths need a real pool.
	st, _ := setup(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := ingest.New(st, &stubCrypto{mutate: tc.mutate})
			_, err := in.Ingest(context.Background(), "", "aGVsbG8=", validEmbeddingB64())
			if !errors.Is(err, ingest.ErrBadCryptoMaterial) {
				t.Errorf("error = %v, want ErrBadCryptoMaterial", err)
			}
		})
	}
}
