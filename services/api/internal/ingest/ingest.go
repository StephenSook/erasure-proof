// Package ingest provisions a subject and stores its first encrypted memory. It is the privileged
// setup path (it writes keys), deliberately separate from the agent's runtime memory writes: it
// runs on the operator pool, so the agent_worker role never touches keys.
package ingest

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/StephenSook/erasure-proof/services/api/internal/cryptoclient"
	"github.com/StephenSook/erasure-proof/services/api/internal/store"
	crdbpgx "github.com/cockroachdb/cockroach-go/v2/crdb/crdbpgxv5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const embeddingDims = 768

// Expected byte lengths of the material cryptod returns. base64/hex decoding of an empty or missing
// field yields empty-but-non-nil bytes that would silently satisfy the BYTES NOT NULL columns, so we
// assert these before storing. A wrong length means a boundary drift or partial cryptod response,
// which must fail loudly rather than commit an undecryptable row or a hollow proof.
const (
	gcmTagBytes          = 16                           // AES-GCM tag appended to every ciphertext
	nonceBytes           = 12                           // 96-bit nonce (aead.py NONCE_BYTES)
	fingerprintBytes     = 32                           // SHA-256 of the wrapped subject key (app.py)
	rowWrappedBytes      = 40                           // RFC 3394 key wrap of a 32-byte key (envelope.py)
	embeddingBytes       = embeddingDims * 4            // 768 little-endian float32
	embeddingCipherBytes = embeddingBytes + gcmTagBytes // deterministic GCM ciphertext length
	expectedGenerateKey  = "GENERATE_DATA_KEY"
	expectedImportedKey  = "IMPORTED_MATERIAL"
)

const (
	qErasureRecordExists = "erasure_record_exists"
	qSubjectKeyExists    = "subject_key_exists"
	qInsertSubjectKey    = "insert_subject_key"
	qInsertMemory        = "insert_memory"
)

// RequiredQueries is the set of named statements Ingest looks up; require it at startup.
var RequiredQueries = []string{qErasureRecordExists, qSubjectKeyExists, qInsertSubjectKey, qInsertMemory}

var (
	// ErrSubjectErased means the subject has an erasure record; re-adding memory would resurrect it.
	ErrSubjectErased = errors.New("subject was erased; refusing to re-add memory")
	// ErrAlreadyProvisioned means the subject already has a key row.
	ErrAlreadyProvisioned = errors.New("subject already provisioned")
	// ErrBadEmbedding means the caller-supplied embedding is not valid base64 float32 of the right
	// length, or contains non-finite values. It is a client error, distinct from an internal failure.
	ErrBadEmbedding = errors.New("invalid embedding")
	// ErrBadContent means the caller-supplied content is not valid base64. Client error.
	ErrBadContent = errors.New("invalid content")
	// ErrBadCryptoMaterial means cryptod returned material of an unexpected shape (wrong length,
	// empty field, or unknown key origin). It is an internal failure: storing it would silently
	// corrupt the row or hollow out the proof, so ingest refuses before opening the transaction.
	ErrBadCryptoMaterial = errors.New("invalid crypto material from cryptod")
)

// Ingester provisions subjects and stores their memories.
type Ingester struct {
	pool   *pgxpool.Pool
	crypto cryptoclient.Client
	q      store.Queries
}

// New builds an Ingester on the operator pool (provisioning is privileged; it writes keys).
func New(s *store.Store, crypto cryptoclient.Client) *Ingester {
	return &Ingester{pool: s.Operator, crypto: crypto, q: s.Q}
}

// Result reports the provisioned subject and stored memory.
type Result struct {
	SubjectID string `json:"subject_id"`
	MemoryID  string `json:"memory_id"`
}

// prepared holds the decoded, validated cryptod output, ready to store.
type prepared struct {
	subjectWrapped []byte
	fingerprint    []byte
	rowWrapped     []byte
	contentCT      []byte
	embeddingCT    []byte
	nonceContent   []byte
	nonceEmbedding []byte
	keyOrigin      string
	kmsKeyARN      string
}

// Ingest provisions a subject key and stores one encrypted memory. content and embeddingB64 are
// base64; embeddingB64 is the raw little-endian float32 bytes of the 768-dim GTR vector. If
// subjectID is empty a new UUID is generated.
func (in *Ingester) Ingest(ctx context.Context, subjectID, content, embeddingB64 string) (Result, error) {
	if subjectID == "" {
		id, err := newUUIDv4()
		if err != nil {
			return Result{}, err
		}
		subjectID = id
	}
	vec, err := vectorLiteral(embeddingB64)
	if err != nil {
		return Result{}, err
	}
	// Validate content is base64 at the boundary so malformed input is a 400, not a cryptod 500.
	if _, err := base64.StdEncoding.DecodeString(content); err != nil {
		return Result{}, fmt.Errorf("%w: not base64: %v", ErrBadContent, err)
	}

	// Encrypt via cryptod. This network call happens BEFORE the transaction, so nothing impure runs
	// inside the retried closure.
	resp, err := in.crypto.Prepare(ctx, cryptoclient.PrepareRequest{
		SubjectID: subjectID, Content: content, Embedding: embeddingB64,
	})
	if err != nil {
		return Result{}, fmt.Errorf("prepare: %w", err)
	}
	p, err := decodePrepared(resp)
	if err != nil {
		return Result{}, err
	}

	res := Result{SubjectID: subjectID}
	err = crdbpgx.ExecuteTx(ctx, in.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		// Resurrection guard: never re-add memory for an erased subject.
		var erased bool
		if e := tx.QueryRow(ctx, in.q.MustGet(qErasureRecordExists), subjectID).Scan(&erased); e != nil {
			return fmt.Errorf("check erasure record: %w", e)
		}
		if erased {
			return ErrSubjectErased
		}
		var provisioned bool
		if e := tx.QueryRow(ctx, in.q.MustGet(qSubjectKeyExists), subjectID).Scan(&provisioned); e != nil {
			return fmt.Errorf("check subject key: %w", e)
		}
		if provisioned {
			return ErrAlreadyProvisioned
		}
		// key_origin is stored as cryptod reports it (validated in decodePrepared), not assumed here,
		// because the erasure path branches on it to decide whether to fire the imported-material KMS
		// kill switch. A wrong origin would silently skip destroying imported material.
		if _, e := tx.Exec(ctx, in.q.MustGet(qInsertSubjectKey),
			subjectID, p.subjectWrapped, p.kmsKeyARN, p.keyOrigin, p.fingerprint); e != nil {
			return fmt.Errorf("insert subject key: %w", e)
		}
		var memID string
		// aad_context is a should-build binding not yet populated on the ingest path; store NULL.
		if e := tx.QueryRow(ctx, in.q.MustGet(qInsertMemory),
			subjectID, p.contentCT, vec, p.embeddingCT, p.nonceContent, p.nonceEmbedding,
			p.rowWrapped, []byte(nil)).Scan(&memID); e != nil {
			return fmt.Errorf("insert memory: %w", e)
		}
		res.MemoryID = memID
		return nil
	})
	return res, err
}

func decodePrepared(resp cryptoclient.PrepareResponse) (prepared, error) {
	var p prepared
	var err error
	if p.subjectWrapped, err = base64.StdEncoding.DecodeString(resp.SubjectWrappedKey); err != nil {
		return p, fmt.Errorf("decode subject_wrapped_key: %w", err)
	}
	if p.fingerprint, err = hex.DecodeString(resp.SubjectKeyFingerprint); err != nil {
		return p, fmt.Errorf("decode subject_key_fingerprint: %w", err)
	}
	if p.rowWrapped, err = base64.StdEncoding.DecodeString(resp.RowWrappedKey); err != nil {
		return p, fmt.Errorf("decode row_wrapped_key: %w", err)
	}
	if p.contentCT, err = base64.StdEncoding.DecodeString(resp.ContentCiphertext); err != nil {
		return p, fmt.Errorf("decode content_ciphertext: %w", err)
	}
	if p.embeddingCT, err = base64.StdEncoding.DecodeString(resp.EmbeddingCiphertext); err != nil {
		return p, fmt.Errorf("decode embedding_ciphertext: %w", err)
	}
	if p.nonceContent, err = base64.StdEncoding.DecodeString(resp.NonceContent); err != nil {
		return p, fmt.Errorf("decode nonce_content: %w", err)
	}
	if p.nonceEmbedding, err = base64.StdEncoding.DecodeString(resp.NonceEmbedding); err != nil {
		return p, fmt.Errorf("decode nonce_embedding: %w", err)
	}
	p.kmsKeyARN = resp.KMSKeyARN
	p.keyOrigin = resp.KeyOrigin
	if err := validatePrepared(p); err != nil {
		return prepared{}, err
	}
	return p, nil
}

// validatePrepared rejects cryptod output that would silently corrupt a row or hollow a proof:
// empty/missing fields (which decode to zero-length non-null bytes and pass BYTES NOT NULL) and
// wrong-length key material. Lengths are exact where the format fixes them, non-empty otherwise.
func validatePrepared(p prepared) error {
	checkLen := func(name string, got, want int) error {
		if got != want {
			return fmt.Errorf("%w: %s length %d, want %d", ErrBadCryptoMaterial, name, got, want)
		}
		return nil
	}
	checkNonEmpty := func(name string, got int) error {
		if got == 0 {
			return fmt.Errorf("%w: %s is empty", ErrBadCryptoMaterial, name)
		}
		return nil
	}
	for _, e := range []error{
		checkNonEmpty("subject_wrapped_key", len(p.subjectWrapped)),
		checkLen("subject_key_fingerprint", len(p.fingerprint), fingerprintBytes),
		checkLen("row_wrapped_key", len(p.rowWrapped), rowWrappedBytes),
		checkLen("nonce_content", len(p.nonceContent), nonceBytes),
		checkLen("nonce_embedding", len(p.nonceEmbedding), nonceBytes),
		checkLen("embedding_ciphertext", len(p.embeddingCT), embeddingCipherBytes),
	} {
		if e != nil {
			return e
		}
	}
	// content plaintext length is caller-chosen, so its ciphertext length varies; it must still carry
	// the GCM tag.
	if len(p.contentCT) < gcmTagBytes {
		return fmt.Errorf("%w: content_ciphertext length %d < tag %d",
			ErrBadCryptoMaterial, len(p.contentCT), gcmTagBytes)
	}
	if p.kmsKeyARN == "" {
		return fmt.Errorf("%w: kms_key_arn is empty", ErrBadCryptoMaterial)
	}
	if p.keyOrigin != expectedGenerateKey && p.keyOrigin != expectedImportedKey {
		return fmt.Errorf("%w: unknown key_origin %q", ErrBadCryptoMaterial, p.keyOrigin)
	}
	return nil
}

// vectorLiteral decodes base64 little-endian float32 bytes into a pgvector literal "[f1,f2,...]".
func vectorLiteral(embeddingB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(embeddingB64)
	if err != nil {
		return "", fmt.Errorf("%w: not base64: %v", ErrBadEmbedding, err)
	}
	if len(raw) != embeddingDims*4 {
		return "", fmt.Errorf("%w: must be %d float32 (%d bytes), got %d",
			ErrBadEmbedding, embeddingDims, embeddingDims*4, len(raw))
	}
	var sb strings.Builder
	sb.WriteByte('[')
	for i := 0; i < embeddingDims; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		f := math.Float32frombits(binary.LittleEndian.Uint32(raw[i*4:]))
		// A non-finite value would format as "NaN"/"+Inf" and be rejected by CockroachDB at insert
		// time (a 500). Reject it here as a client error instead.
		if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
			return "", fmt.Errorf("%w: dimension %d is not finite", ErrBadEmbedding, i)
		}
		sb.WriteString(strconv.FormatFloat(float64(f), 'f', -1, 32))
	}
	sb.WriteByte(']')
	return sb.String(), nil
}

func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
