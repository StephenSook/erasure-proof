package erasure_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/StephenSook/erasure-proof/services/api/internal/chain"
	"github.com/StephenSook/erasure-proof/services/api/internal/erasure"
	"github.com/StephenSook/erasure-proof/services/api/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests need a CockroachDB reachable at CRDB_DSN_TEST. They are skipped otherwise so that a
// plain `go test ./...` without a database still passes; CI provides the DSN.

func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// .../services/api/internal/erasure -> up four to the repo root.
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..")
}

func vectorLiteral() string {
	return "[" + strings.Repeat("0.01,", 767) + "0.01]"
}

// setup applies the base schema, opens a store, and seeds one subject with a key and a memory row.
func setup(t *testing.T) (*store.Store, string) {
	t.Helper()
	dsn := os.Getenv("CRDB_DSN_TEST")
	if dsn == "" {
		t.Skip("set CRDB_DSN_TEST to run the erasure integration test")
	}
	ctx := context.Background()
	root := repoRoot(t)

	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(admin.Close)

	schema, err := os.ReadFile(filepath.Join(root, "db", "migrations", "0001_schema.sql"))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	if _, err := admin.Exec(ctx, string(schema)); err != nil {
		t.Fatalf("apply schema: %v", err)
	}

	st, err := store.Open(ctx, dsn, dsn, filepath.Join(root, "db", "queries"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(st.Close)

	var subjectID string
	if err := admin.QueryRow(ctx, "SELECT gen_random_uuid()::string").Scan(&subjectID); err != nil {
		t.Fatalf("gen uuid: %v", err)
	}
	if _, err := admin.Exec(ctx,
		`INSERT INTO subject_keys (subject_id, wrapped_key, kms_key_arn, key_origin, wrapped_key_fingerprint)
		 VALUES ($1, b'\x01\x02', 'arn:test', 'GENERATE_DATA_KEY', b'\xaa\xbb')`, subjectID); err != nil {
		t.Fatalf("seed key: %v", err)
	}
	if _, err := admin.Exec(ctx,
		`INSERT INTO agent_memory (subject_id, content_ciphertext, embedding, embedding_ciphertext,
			nonce_content, nonce_embedding, wrapped_key)
		 VALUES ($1, b'\x01', $2, b'\x02', b'\x03', b'\x04', b'\x05')`, subjectID, vectorLiteral()); err != nil {
		t.Fatalf("seed memory: %v", err)
	}
	return st, subjectID
}

func assertErased(t *testing.T, st *store.Store, subjectID string) {
	t.Helper()
	ctx := context.Background()
	var keys int
	if err := st.Operator.QueryRow(ctx,
		"SELECT count(*) FROM subject_keys WHERE subject_id = $1", subjectID).Scan(&keys); err != nil {
		t.Fatal(err)
	}
	if keys != 0 {
		t.Errorf("subject key not destroyed: %d rows remain", keys)
	}

	var logs int
	if err := st.Operator.QueryRow(ctx,
		"SELECT count(*) FROM decision_log WHERE subject_hash = $1", chain.SubjectHash(subjectID)).Scan(&logs); err != nil {
		t.Fatal(err)
	}
	if logs != 1 {
		t.Errorf("decision log rows = %d, want 1", logs)
	}

	var records int
	if err := st.Operator.QueryRow(ctx,
		"SELECT count(*) FROM erasure_record WHERE subject_id = $1", subjectID).Scan(&records); err != nil {
		t.Fatal(err)
	}
	if records != 1 {
		t.Errorf("erasure records = %d, want 1", records)
	}

	var embeddingNull bool
	if err := st.Operator.QueryRow(ctx,
		"SELECT bool_and(embedding IS NULL) FROM agent_memory WHERE subject_id = $1", subjectID).Scan(&embeddingNull); err != nil {
		t.Fatal(err)
	}
	if !embeddingNull {
		t.Error("live embedding was not purged to NULL")
	}
}

func TestErase_DestroysAndRetains(t *testing.T) {
	st, subjectID := setup(t)
	svc := erasure.New(st)

	res, err := svc.Erase(context.Background(), subjectID, "erasure", "gdpr_art_17")
	if err != nil {
		t.Fatalf("erase: %v", err)
	}
	if res.Seq < 1 {
		t.Errorf("seq = %d, want >= 1", res.Seq)
	}
	assertErased(t, st, subjectID)
}

func TestErase_AlreadyErasedIsIdempotentError(t *testing.T) {
	st, subjectID := setup(t)
	svc := erasure.New(st)

	if _, err := svc.Erase(context.Background(), subjectID, "erasure", "gdpr_art_17"); err != nil {
		t.Fatalf("first erase: %v", err)
	}
	_, err := svc.Erase(context.Background(), subjectID, "erasure", "gdpr_art_17")
	if err != erasure.ErrAlreadyErased {
		t.Errorf("second erase error = %v, want ErrAlreadyErased", err)
	}
}

// TestErase_SurvivesInjectedRetries proves the transaction is atomic under serialization failures:
// with inject_retry_errors_enabled every connection injects retryable 40001 errors, so the crdbpgx
// wrapper must retry the whole closure and still commit both the decision-log insert and the key
// deletion (or neither). Seeding and verification use the clean pool; only the erasure runs on the
// injecting pool.
func TestErase_SurvivesInjectedRetries(t *testing.T) {
	st, subjectID := setup(t)
	dsn := os.Getenv("CRDB_DSN_TEST")

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET inject_retry_errors_enabled = true")
		return err
	}
	injectPool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer injectPool.Close()

	// Run the erasure on a store backed by the injecting pool, reusing the loaded queries.
	svc := erasure.New(&store.Store{Operator: injectPool, Agent: injectPool, Q: st.Q})
	if _, err := svc.Erase(context.Background(), subjectID, "erasure", "gdpr_art_17"); err != nil {
		t.Fatalf("erase under injected retries: %v", err)
	}

	// Verify atomic completion using the clean pool.
	assertErased(t, st, subjectID)
}
