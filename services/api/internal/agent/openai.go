package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// OpenAIConverse is a Converser over an OpenAI-compatible chat-completions endpoint. It exists so
// the live agent beats keep working when Bedrock is unavailable (a new AWS account ships with a
// zero Bedrock quota): the deployed fallback is llama.cpp serving an open model on a Modal
// serverless GPU, which speaks this dialect natively, and the UI labels which provider answered.
// The translation is Converse-shaped on the agent side, so the tool-use loop cannot tell the
// difference between providers.
type OpenAIConverse struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
	model      string
	maxTokens  int
}

// NewOpenAIConverse builds the client from AGENTS_LLM_URL / AGENTS_LLM_SECRET / AGENTS_LLM_MODEL.
// It makes no network call; an unreachable endpoint surfaces when Audit runs, exactly like the
// Bedrock twin.
func NewOpenAIConverse() (*OpenAIConverse, error) {
	base := strings.TrimRight(os.Getenv("AGENTS_LLM_URL"), "/")
	if base == "" {
		return nil, fmt.Errorf("AGENTS_LLM_URL is not set")
	}
	// The bearer secret rides on every request, so refuse to send it anywhere unencrypted;
	// loopback is exempt for local development and tests.
	if !strings.HasPrefix(base, "https://") &&
		!strings.HasPrefix(base, "http://127.0.0.1") && !strings.HasPrefix(base, "http://localhost") {
		return nil, fmt.Errorf("AGENTS_LLM_URL must be https (loopback excepted)")
	}
	model := os.Getenv("AGENTS_LLM_MODEL")
	if model == "" {
		model = "qwen2.5-3b-instruct"
	}
	return &OpenAIConverse{
		httpClient: &http.Client{},
		baseURL:    base,
		apiKey:     os.Getenv("AGENTS_LLM_SECRET"),
		model:      model,
		maxTokens:  512,
	}, nil
}

// Model reports the configured model label for honest on-screen provenance.
func (o *OpenAIConverse) Model() string { return o.model }

// The wire shapes of the OpenAI chat-completions dialect, reduced to the fields the loop uses.
type oaTool struct {
	Type     string     `json:"type"`
	Function oaFunction `json:"function"`
}

type oaFunction struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Parameters  map[string]any `json:"parameters,omitempty"`
}

type oaToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type oaMessage struct {
	Role       string       `json:"role"`
	Content    string       `json:"content,omitempty"`
	ToolCalls  []oaToolCall `json:"tool_calls,omitempty"`
	ToolCallID string       `json:"tool_call_id,omitempty"`
}

type oaRequest struct {
	Model       string      `json:"model"`
	Messages    []oaMessage `json:"messages"`
	Tools       []oaTool    `json:"tools,omitempty"`
	MaxTokens   int         `json:"max_tokens"`
	Temperature float64     `json:"temperature"`
}

type oaResponse struct {
	Choices []struct {
		FinishReason string    `json:"finish_reason"`
		Message      oaMessage `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Converse runs one turn, translating the agent transcript to and from the OpenAI dialect.
func (o *OpenAIConverse) Converse(
	ctx context.Context, system string, messages []Message, tools []ToolSpec,
) (Result, error) {
	req := oaRequest{
		Model:       o.model,
		Messages:    append([]oaMessage{{Role: "system", Content: system}}, toOAMessages(messages)...),
		MaxTokens:   o.maxTokens,
		Temperature: 0,
	}
	for _, t := range tools {
		req.Tools = append(req.Tools, oaTool{
			Type:     "function",
			Function: oaFunction{Name: t.Name, Description: t.Description, Parameters: t.InputSchema},
		})
	}

	body, err := json.Marshal(req)
	if err != nil {
		return Result{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, o.baseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return Result{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if o.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+o.apiKey)
	}
	// A scale-to-zero endpoint answers 503 while the container boots and the model loads
	// (observed live: {"message":"Loading model"}). That is a warming signal, not a failure, so
	// retry within the caller's deadline; the first judge click pays the cold start and every
	// later call is warm.
	var respBody []byte
	for {
		resp, err := o.httpClient.Do(httpReq)
		if err != nil {
			return Result{}, fmt.Errorf("open-model endpoint: %w", err)
		}
		respBody, err = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if err != nil {
			return Result{}, err
		}
		if resp.StatusCode == http.StatusServiceUnavailable {
			select {
			case <-ctx.Done():
				return Result{}, fmt.Errorf("open-model endpoint: still warming at deadline: %s", truncate(respBody, 120))
			case <-time.After(5 * time.Second):
			}
			httpReq, err = http.NewRequestWithContext(ctx, http.MethodPost, o.baseURL+"/v1/chat/completions", bytes.NewReader(body))
			if err != nil {
				return Result{}, err
			}
			httpReq.Header.Set("Content-Type", "application/json")
			if o.apiKey != "" {
				httpReq.Header.Set("Authorization", "Bearer "+o.apiKey)
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return Result{}, fmt.Errorf("open-model endpoint: status %d: %s", resp.StatusCode, truncate(respBody, 300))
		}
		break
	}
	var parsed oaResponse
	if err := json.Unmarshal(sanitizeJSONControlChars(respBody), &parsed); err != nil {
		return Result{}, fmt.Errorf("open-model endpoint: bad JSON: %w", err)
	}
	if parsed.Error != nil {
		return Result{}, fmt.Errorf("open-model endpoint: %s", parsed.Error.Message)
	}
	if len(parsed.Choices) == 0 {
		return Result{}, fmt.Errorf("open-model endpoint: no choices in response")
	}
	return fromOAChoice(parsed.Choices[0].FinishReason, parsed.Choices[0].Message), nil
}

// toOAMessages flattens the Converse-shaped transcript into the OpenAI dialect: assistant tool
// calls ride on the assistant message, and each tool result becomes its own role:"tool" message.
func toOAMessages(messages []Message) []oaMessage {
	out := make([]oaMessage, 0, len(messages))
	for _, m := range messages {
		if m.Role == RoleAssistant {
			msg := oaMessage{Role: "assistant"}
			for _, blk := range m.Blocks {
				switch {
				case blk.ToolUse != nil:
					args, _ := json.Marshal(blk.ToolUse.Input)
					tc := oaToolCall{ID: blk.ToolUse.ID, Type: "function"}
					tc.Function.Name = blk.ToolUse.Name
					tc.Function.Arguments = string(args)
					msg.ToolCalls = append(msg.ToolCalls, tc)
				default:
					msg.Content += blk.Text
				}
			}
			out = append(out, msg)
			continue
		}
		var text string
		for _, blk := range m.Blocks {
			switch {
			case blk.ToolResult != nil:
				payload, _ := json.Marshal(blk.ToolResult.JSON)
				out = append(out, oaMessage{Role: "tool", ToolCallID: blk.ToolResult.ToolUseID, Content: string(payload)})
			default:
				text += blk.Text
			}
		}
		if text != "" {
			out = append(out, oaMessage{Role: "user", Content: text})
		}
	}
	return out
}

// fromOAChoice maps one completion back onto the Converse-shaped Result. finish_reason
// "tool_calls" maps to the loop's "tool_use" sentinel; anything else ends the loop, same as
// Bedrock's end_turn.
func fromOAChoice(finishReason string, msg oaMessage) Result {
	res := Result{StopReason: "end_turn", Text: strings.TrimSpace(msg.Content)}
	assistant := Message{Role: RoleAssistant}
	if msg.Content != "" {
		assistant.Blocks = append(assistant.Blocks, Block{Text: msg.Content})
	}
	for i, tc := range msg.ToolCalls {
		var input map[string]any
		if err := json.Unmarshal([]byte(tc.Function.Arguments), &input); err != nil {
			input = map[string]any{}
		}
		id := tc.ID
		if id == "" {
			// Some llama.cpp chat templates omit call ids; the loop only needs them to pair
			// results with calls within one turn, so a deterministic local id is sufficient.
			id = fmt.Sprintf("call_%d", i)
		}
		tu := ToolUse{ID: id, Name: tc.Function.Name, Input: input}
		res.ToolUses = append(res.ToolUses, tu)
		assistant.Blocks = append(assistant.Blocks, Block{ToolUse: &tu})
	}
	if finishReason == "tool_calls" || len(res.ToolUses) > 0 {
		res.StopReason = "tool_use"
	}
	res.Assistant = assistant
	return res
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}

// sanitizeJSONControlChars escapes raw control characters that appear INSIDE string literals.
// llama.cpp has been observed emitting unescaped newlines in message content, which Python's
// tolerant parser accepts but Go's strict decoder rejects; outside strings, control characters are
// legal JSON whitespace and are left alone.
func sanitizeJSONControlChars(b []byte) []byte {
	var out bytes.Buffer
	out.Grow(len(b))
	inString, escaped := false, false
	for _, c := range b {
		if inString {
			switch {
			case escaped:
				// A raw control byte right after a backslash is still invalid JSON; emitting its
				// escape sequence after the already-written backslash yields a valid literal
				// backslash + escape (the only lossless-ish repair available).
				escaped = false
				if c < 0x20 {
					switch c {
					case '\n':
						out.WriteString(`\n`)
					case '\r':
						out.WriteString(`\r`)
					case '\t':
						out.WriteString(`\t`)
					default:
						fmt.Fprintf(&out, `\u%04x`, c)
					}
					continue
				}
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			case c < 0x20:
				switch c {
				case '\n':
					out.WriteString(`\n`)
				case '\r':
					out.WriteString(`\r`)
				case '\t':
					out.WriteString(`\t`)
				default:
					fmt.Fprintf(&out, `\u%04x`, c)
				}
				continue
			}
		} else if c == '"' {
			inString = true
		}
		out.WriteByte(c)
	}
	return out.Bytes()
}
