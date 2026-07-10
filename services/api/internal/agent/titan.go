package agent

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
)

// defaultTitanModelID is Amazon's own embedding model, invoked with its bare id (Titan supports
// on-demand throughput directly; the us. inference-profile prefix is an Anthropic-models need).
const defaultTitanModelID = "amazon.titan-embed-text-v2:0"

// titanDimensions is fixed at Titan v2's maximum. The side-by-side point is the contrast with the
// GTR 768-dim vector, so the dimensionality is part of the display, not a tunable.
const titanDimensions = 1024

// TitanEmbedding is one live Titan v2 embedding, in the same wire shape as the GTR path
// (little-endian float32 base64 + its SHA-256) so the two vectors are directly comparable.
type TitanEmbedding struct {
	ModelID      string `json:"model_id"`
	Dimensions   int    `json:"dimensions"`
	EmbeddingB64 string `json:"embedding_b64"`
	Sha256       string `json:"sha256"`
	TokenCount   int    `json:"input_token_count"`
}

// TitanEmbedder is the live AWS-native embedding step (interface so demo tests stub it).
type TitanEmbedder interface {
	EmbedText(ctx context.Context, text string) (TitanEmbedding, error)
}

// BedrockTitan embeds via Bedrock InvokeModel. Unlike the Converse-based agents this is a raw
// model invocation: Titan's embedding API has no Converse shape.
type BedrockTitan struct {
	client  *bedrockruntime.Client
	modelID string
}

// NewBedrockTitan builds the client from the default AWS credential chain. No network call is
// made; a missing model entitlement surfaces on the first EmbedText.
func NewBedrockTitan(ctx context.Context) (*BedrockTitan, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	model := os.Getenv("BEDROCK_TITAN_EMBED_MODEL_ID")
	if model == "" {
		model = defaultTitanModelID
	}
	return &BedrockTitan{client: bedrockruntime.NewFromConfig(cfg), modelID: model}, nil
}

// EmbedText runs one live Titan v2 embedding and returns it in the GTR-comparable wire shape.
func (b *BedrockTitan) EmbedText(ctx context.Context, text string) (TitanEmbedding, error) {
	body, err := json.Marshal(map[string]any{
		"inputText":  text,
		"dimensions": titanDimensions,
		"normalize":  true,
	})
	if err != nil {
		return TitanEmbedding{}, err
	}
	out, err := b.client.InvokeModel(ctx, &bedrockruntime.InvokeModelInput{
		ModelId:     aws.String(b.modelID),
		ContentType: aws.String("application/json"),
		Body:        body,
	})
	if err != nil {
		return TitanEmbedding{}, fmt.Errorf("titan invoke: %w", err)
	}
	var resp struct {
		Embedding           []float64 `json:"embedding"`
		InputTextTokenCount int       `json:"inputTextTokenCount"`
	}
	if err := json.Unmarshal(out.Body, &resp); err != nil {
		return TitanEmbedding{}, fmt.Errorf("titan response: %w", err)
	}
	if len(resp.Embedding) != titanDimensions {
		return TitanEmbedding{}, fmt.Errorf(
			"titan returned %d dimensions, expected %d", len(resp.Embedding), titanDimensions)
	}
	return finishTitanEmbedding(b.modelID, resp.Embedding, resp.InputTextTokenCount), nil
}

// finishTitanEmbedding serializes the vector as little-endian float32 (the GTR /embed convention)
// and hashes those exact bytes, so the console can show both vectors' digests side by side.
func finishTitanEmbedding(modelID string, vec []float64, tokens int) TitanEmbedding {
	raw := make([]byte, 4*len(vec))
	for i, v := range vec {
		binary.LittleEndian.PutUint32(raw[4*i:], math.Float32bits(float32(v)))
	}
	sum := sha256.Sum256(raw)
	return TitanEmbedding{
		ModelID:      modelID,
		Dimensions:   len(vec),
		EmbeddingB64: base64.StdEncoding.EncodeToString(raw),
		Sha256:       hex.EncodeToString(sum[:]),
		TokenCount:   tokens,
	}
}
