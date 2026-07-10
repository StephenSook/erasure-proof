// Package cryptoclient is the Go orchestrator's client for the Python cryptod service. It is an
// interface so the orchestrator and reconciler can be tested against a stub without a running
// cryptod.
package cryptoclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// PrepareRequest asks cryptod to generate a data key and encrypt content + embedding.
type PrepareRequest struct {
	SubjectID string `json:"subject_id"`
	Content   string `json:"content"`   // base64
	Embedding string `json:"embedding"` // base64
}

// PrepareResponse carries the ciphertexts and the two-level wrapped keys to store: the KMS-wrapped
// subject key (subject_keys.wrapped_key) and the per-row key wrapped under the subject key
// (agent_memory.wrapped_key).
type PrepareResponse struct {
	ContentCiphertext     string `json:"content_ciphertext"`
	NonceContent          string `json:"nonce_content"`
	EmbeddingCiphertext   string `json:"embedding_ciphertext"`
	NonceEmbedding        string `json:"nonce_embedding"`
	SubjectWrappedKey     string `json:"subject_wrapped_key"`
	SubjectKeyFingerprint string `json:"subject_key_fingerprint"`
	RowWrappedKey         string `json:"row_wrapped_key"`
	KMSKeyARN             string `json:"kms_key_arn"`
	// KeyOrigin is how cryptod made the subject key ('GENERATE_DATA_KEY' | 'IMPORTED_MATERIAL'). It
	// is stored verbatim because the erasure path branches on it for the imported-material kill
	// switch; the ingest layer must not assume it.
	KeyOrigin string `json:"key_origin"`
}

// ShredResponse reports the imported-material kill switch outcome.
type ShredResponse struct {
	Destroyed bool   `json:"destroyed"`
	KeyState  string `json:"key_state"`
	Status    string `json:"status"`
}

// AnchorRequest is the proof material to sign and anchor.
type AnchorRequest struct {
	SubjectHash           string `json:"subject_hash"`
	OccurredAt            string `json:"occurred_at"`
	DecisionLogSeq        int64  `json:"decision_log_seq"`
	ChainHead             string `json:"chain_head"`
	WrappedKeyFingerprint string `json:"wrapped_key_fingerprint"`
	KMSKeyARN             string `json:"kms_key_arn"`
	KeyState              string `json:"key_state"`
}

// AnchorResponse carries the anchored, signed proof.
type AnchorResponse struct {
	Signature      string `json:"signature"`
	ProofRef       string `json:"proof_ref"`
	ObjectLockMode string `json:"object_lock_mode"`
	RetainUntil    string `json:"retain_until"`
	SHA256         string `json:"sha256"`
}

// Client is the cryptod surface the orchestrator depends on.
type Client interface {
	Prepare(ctx context.Context, req PrepareRequest) (PrepareResponse, error)
	Shred(ctx context.Context, keyARN string) (ShredResponse, error)
	Anchor(ctx context.Context, req AnchorRequest) (AnchorResponse, error)
}

// HTTP is the real HTTP-backed client.
type HTTP struct {
	base string
	http *http.Client
}

// NewHTTP builds an HTTP client for the cryptod base URL.
func NewHTTP(baseURL string) *HTTP {
	return &HTTP{base: baseURL, http: &http.Client{Timeout: 30 * time.Second}}
}

func (c *HTTP) post(ctx context.Context, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("cryptod %s: %w", path, err)
	}
	defer resp.Body.Close()
	// 2xx is success (includes 202 pending_confirmation from /shred). Anything else is an error so
	// the caller never treats a failed anchor or shred as done.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("cryptod %s: status %d: %s", path, resp.StatusCode, snippet)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *HTTP) Prepare(ctx context.Context, req PrepareRequest) (PrepareResponse, error) {
	var out PrepareResponse
	err := c.post(ctx, "/prepare", req, &out)
	return out, err
}

func (c *HTTP) Shred(ctx context.Context, keyARN string) (ShredResponse, error) {
	var out ShredResponse
	err := c.post(ctx, "/shred", map[string]string{"key_arn": keyARN}, &out)
	return out, err
}

func (c *HTTP) Anchor(ctx context.Context, req AnchorRequest) (AnchorResponse, error) {
	var out AnchorResponse
	err := c.post(ctx, "/anchor", req, &out)
	return out, err
}

// Invert fetches the recorded Vec2Text golden run (GET /invert) for the demo gateway. It is not part
// of the core Client interface (the orchestrator and reconciler do not need it); the demo package
// depends on a narrow Inverter interface that *HTTP satisfies.
func (c *HTTP) Invert(ctx context.Context) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/invert", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cryptod /invert: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("cryptod /invert: status %d: %s", resp.StatusCode, snippet)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}
