package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// The scripted endpoint returns a tool call first, then a final text verdict, asserting the exact
// OpenAI-dialect shapes the translation must produce (system first, tool results as role:"tool",
// assistant tool_calls echoed with arguments as a JSON string).
func TestOpenAIConverseToolLoopTranslation(t *testing.T) {
	var gotRequests []oaRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer sekrit" {
			t.Errorf("Authorization = %q, want Bearer sekrit", got)
		}
		var req oaRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		gotRequests = append(gotRequests, req)

		w.Header().Set("Content-Type", "application/json")
		if len(gotRequests) == 1 {
			_, _ = w.Write([]byte(`{"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant",
				"tool_calls":[{"id":"call_abc","type":"function","function":{"name":"confirm_key_destroyed","arguments":"{\"subject_id\":\"s1\"}"}}]}}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"VERDICT: PROVEN because the key row is gone."}}]}`))
	}))
	defer srv.Close()

	t.Setenv("AGENTS_LLM_URL", srv.URL)
	t.Setenv("AGENTS_LLM_SECRET", "sekrit")
	c, err := NewOpenAIConverse()
	if err != nil {
		t.Fatalf("NewOpenAIConverse: %v", err)
	}

	messages := []Message{{Role: RoleUser, Blocks: []Block{{Text: "Audit subject s1."}}}}
	res, err := c.Converse(context.Background(), "system prompt", messages, ForensicsToolSpecs)
	if err != nil {
		t.Fatalf("first converse: %v", err)
	}
	if res.StopReason != "tool_use" || len(res.ToolUses) != 1 {
		t.Fatalf("first turn: stop=%q tools=%d, want tool_use/1", res.StopReason, len(res.ToolUses))
	}
	if res.ToolUses[0].Name != "confirm_key_destroyed" || res.ToolUses[0].Input["subject_id"] != "s1" {
		t.Fatalf("tool use = %+v", res.ToolUses[0])
	}

	// Feed the tool result back, as the loop does, and check the final text turn.
	messages = append(messages, res.Assistant, Message{Role: RoleUser, Blocks: []Block{{
		ToolResult: &ToolResult{ToolUseID: res.ToolUses[0].ID, JSON: map[string]any{"destroyed": true}},
	}}})
	final, err := c.Converse(context.Background(), "system prompt", messages, ForensicsToolSpecs)
	if err != nil {
		t.Fatalf("second converse: %v", err)
	}
	if final.StopReason != "end_turn" || final.Text == "" {
		t.Fatalf("final turn: stop=%q text=%q", final.StopReason, final.Text)
	}

	// The second request must carry: system first, then user text, assistant tool_calls with JSON
	// string arguments, then the tool result as role:"tool" bound by tool_call_id.
	second := gotRequests[1]
	if second.Messages[0].Role != "system" || second.Messages[1].Role != "user" {
		t.Fatalf("message order: %+v", second.Messages)
	}
	asst := second.Messages[2]
	if asst.Role != "assistant" || len(asst.ToolCalls) != 1 || asst.ToolCalls[0].Function.Name != "confirm_key_destroyed" {
		t.Fatalf("assistant message: %+v", asst)
	}
	var args map[string]any
	if err := json.Unmarshal([]byte(asst.ToolCalls[0].Function.Arguments), &args); err != nil || args["subject_id"] != "s1" {
		t.Fatalf("arguments round-trip: %q err=%v", asst.ToolCalls[0].Function.Arguments, err)
	}
	tool := second.Messages[3]
	if tool.Role != "tool" || tool.ToolCallID != "call_abc" {
		t.Fatalf("tool message: %+v", tool)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(tool.Content), &payload); err != nil || payload["destroyed"] != true {
		t.Fatalf("tool payload: %q err=%v", tool.Content, err)
	}
	if len(second.Tools) != len(ForensicsToolSpecs) {
		t.Fatalf("tools advertised = %d, want %d", len(second.Tools), len(ForensicsToolSpecs))
	}
}

// A 503 "Loading model" during a scale-to-zero cold start is a warming signal: the client retries
// within the context deadline instead of failing the audit on the first judge click.
func TestOpenAIConverseRetriesWhileWarming(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":{"message":"Loading model","type":"unavailable_error","code":503}}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"warm now"}}]}`))
	}))
	defer srv.Close()
	t.Setenv("AGENTS_LLM_URL", srv.URL)
	t.Setenv("AGENTS_LLM_SECRET", "")
	c, err := NewOpenAIConverse()
	if err != nil {
		t.Fatalf("NewOpenAIConverse: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := c.Converse(ctx, "s", []Message{{Role: RoleUser, Blocks: []Block{{Text: "go"}}}}, nil)
	if err != nil {
		t.Fatalf("converse: %v", err)
	}
	if res.Text != "warm now" || calls != 2 {
		t.Fatalf("text=%q calls=%d, want warm retry", res.Text, calls)
	}
}

// llama.cpp has been observed emitting raw control characters inside JSON strings, which Go's
// strict decoder rejects; the sanitizer escapes them in-string and leaves structural whitespace
// alone.
func TestSanitizeJSONControlChars(t *testing.T) {
	in := []byte("{\n  \"content\": \"line one\nline two\ttabbed\",\n  \"ok\": true\n}")
	var parsed map[string]any
	if err := json.Unmarshal(sanitizeJSONControlChars(in), &parsed); err != nil {
		t.Fatalf("sanitized JSON still rejected: %v", err)
	}
	if parsed["content"] != "line one\nline two\ttabbed" {
		t.Fatalf("content round-trip = %q", parsed["content"])
	}
	if escaped := `{"a": "back\\slash\nend"}`; func() error {
		var m map[string]any
		return json.Unmarshal(sanitizeJSONControlChars([]byte("{\"a\": \"back\\\\slash\nend\"}")), &m)
	}() != nil {
		t.Fatalf("escape-aware pass mangled %s", escaped)
	}
}

// A template that omits tool-call ids still pairs results locally, and an error body surfaces as an
// error rather than a zero Result.
func TestOpenAIConverseEdgeCases(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant",
			"tool_calls":[{"id":"","type":"function","function":{"name":"verify_hash_chain","arguments":"{}"}}]}}]}`))
	}))
	defer srv.Close()
	t.Setenv("AGENTS_LLM_URL", srv.URL)
	t.Setenv("AGENTS_LLM_SECRET", "")
	c, err := NewOpenAIConverse()
	if err != nil {
		t.Fatalf("NewOpenAIConverse: %v", err)
	}
	res, err := c.Converse(context.Background(), "s", []Message{{Role: RoleUser, Blocks: []Block{{Text: "go"}}}}, ForensicsToolSpecs)
	if err != nil {
		t.Fatalf("converse: %v", err)
	}
	if res.ToolUses[0].ID == "" {
		t.Fatal("empty tool-call id was not replaced with a local id")
	}

	// A permanently-503 endpoint must surface as an error once the caller's deadline expires,
	// not spin forever (warming retries are deadline-bounded).
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`loading model`))
	}))
	defer bad.Close()
	t.Setenv("AGENTS_LLM_URL", bad.URL)
	c2, _ := NewOpenAIConverse()
	shortCtx, shortCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer shortCancel()
	if _, err := c2.Converse(shortCtx, "s", nil, nil); err == nil {
		t.Fatal("expected an error from a permanently-503 endpoint at deadline")
	}
	_ = os.Unsetenv("AGENTS_LLM_URL")
}
