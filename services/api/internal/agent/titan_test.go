package agent

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"math"
	"testing"
)

// The Titan wire shape must match the GTR /embed convention exactly (little-endian float32 bytes,
// SHA-256 of those bytes) or the console's side-by-side digests stop being comparable.
func TestFinishTitanEmbedding_WireShapeMatchesGTRConvention(t *testing.T) {
	vec := []float64{1.5, -2.0, 0.0}
	emb := finishTitanEmbedding("amazon.titan-embed-text-v2:0", vec, 7)

	raw, err := base64.StdEncoding.DecodeString(emb.EmbeddingB64)
	if err != nil {
		t.Fatalf("embedding_b64 not base64: %v", err)
	}
	if len(raw) != 4*len(vec) {
		t.Fatalf("raw length = %d, want %d (float32 per component)", len(raw), 4*len(vec))
	}
	for i, want := range vec {
		got := math.Float32frombits(binary.LittleEndian.Uint32(raw[4*i:]))
		if got != float32(want) {
			t.Errorf("component %d = %v, want %v (little-endian float32)", i, got, want)
		}
	}
	sum := sha256.Sum256(raw)
	if emb.Sha256 != hex.EncodeToString(sum[:]) {
		t.Errorf("sha256 = %s, want the digest of the exact serialized bytes", emb.Sha256)
	}
	if emb.Dimensions != 3 || emb.TokenCount != 7 {
		t.Errorf("dims/tokens = %d/%d, want 3/7", emb.Dimensions, emb.TokenCount)
	}
}
