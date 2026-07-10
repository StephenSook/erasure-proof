package agent

import (
	"context"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/document"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
)

// defaultModelID is the granted entitlement on this account (Claude Haiku 4.5), also the cheapest,
// which matters under the low daily-token quota. Override with AGENTS_MODEL_ID. The cross-region
// inference-profile id (us.anthropic. prefix) is required; the bare anthropic.claude-* id raises
// ValidationException (on-demand throughput is not supported for these models).
const defaultModelID = "us.anthropic.claude-haiku-4-5-20251001-v1:0"

// BedrockConverse is the real Converser over the Bedrock Converse API.
type BedrockConverse struct {
	client    *bedrockruntime.Client
	modelID   string
	maxTokens int32
}

// NewBedrockConverse builds the client from the default AWS credential chain (the Fargate task role
// assumes the Bedrock-invoke principal). It does not make a network call, so a missing quota surfaces
// only when Audit runs.
func NewBedrockConverse(ctx context.Context) (*BedrockConverse, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	model := os.Getenv("AGENTS_MODEL_ID")
	if model == "" {
		model = defaultModelID
	}
	return &BedrockConverse{client: bedrockruntime.NewFromConfig(cfg), modelID: model, maxTokens: 512}, nil
}

// Converse runs one Converse turn, translating the agent's transcript types to and from the SDK.
func (b *BedrockConverse) Converse(
	ctx context.Context, system string, messages []Message, tools []ToolSpec,
) (Result, error) {
	in := &bedrockruntime.ConverseInput{
		ModelId:         aws.String(b.modelID),
		System:          []types.SystemContentBlock{&types.SystemContentBlockMemberText{Value: system}},
		Messages:        toSDKMessages(messages),
		InferenceConfig: &types.InferenceConfiguration{MaxTokens: aws.Int32(b.maxTokens), Temperature: aws.Float32(0)},
	}
	if len(tools) > 0 {
		in.ToolConfig = toSDKToolConfig(tools)
	}
	out, err := b.client.Converse(ctx, in)
	if err != nil {
		return Result{}, err
	}
	return parseSDKOutput(out), nil
}

func toSDKMessages(messages []Message) []types.Message {
	out := make([]types.Message, 0, len(messages))
	for _, m := range messages {
		role := types.ConversationRoleUser
		if m.Role == RoleAssistant {
			role = types.ConversationRoleAssistant
		}
		content := make([]types.ContentBlock, 0, len(m.Blocks))
		for _, blk := range m.Blocks {
			switch {
			case blk.ToolUse != nil:
				content = append(content, &types.ContentBlockMemberToolUse{Value: types.ToolUseBlock{
					ToolUseId: aws.String(blk.ToolUse.ID),
					Name:      aws.String(blk.ToolUse.Name),
					Input:     document.NewLazyDocument(blk.ToolUse.Input),
				}})
			case blk.ToolResult != nil:
				content = append(content, &types.ContentBlockMemberToolResult{Value: types.ToolResultBlock{
					ToolUseId: aws.String(blk.ToolResult.ToolUseID),
					Content: []types.ToolResultContentBlock{
						&types.ToolResultContentBlockMemberJson{Value: document.NewLazyDocument(blk.ToolResult.JSON)},
					},
				}})
			default:
				content = append(content, &types.ContentBlockMemberText{Value: blk.Text})
			}
		}
		out = append(out, types.Message{Role: role, Content: content})
	}
	return out
}

func toSDKToolConfig(tools []ToolSpec) *types.ToolConfiguration {
	specs := make([]types.Tool, 0, len(tools))
	for _, t := range tools {
		specs = append(specs, &types.ToolMemberToolSpec{Value: types.ToolSpecification{
			Name:        aws.String(t.Name),
			Description: aws.String(t.Description),
			InputSchema: &types.ToolInputSchemaMemberJson{Value: document.NewLazyDocument(t.InputSchema)},
		}})
	}
	return &types.ToolConfiguration{Tools: specs}
}

func parseSDKOutput(out *bedrockruntime.ConverseOutput) Result {
	res := Result{StopReason: string(out.StopReason)}
	msgOut, ok := out.Output.(*types.ConverseOutputMemberMessage)
	if !ok {
		return res
	}
	assistant := Message{Role: RoleAssistant}
	for _, block := range msgOut.Value.Content {
		switch v := block.(type) {
		case *types.ContentBlockMemberText:
			res.Text += v.Value
			assistant.Blocks = append(assistant.Blocks, Block{Text: v.Value})
		case *types.ContentBlockMemberToolUse:
			var input map[string]any
			if v.Value.Input != nil {
				_ = v.Value.Input.UnmarshalSmithyDocument(&input)
			}
			tu := ToolUse{ID: aws.ToString(v.Value.ToolUseId), Name: aws.ToString(v.Value.Name), Input: input}
			res.ToolUses = append(res.ToolUses, tu)
			assistant.Blocks = append(assistant.Blocks, Block{ToolUse: &tu})
		}
	}
	res.Assistant = assistant
	return res
}
