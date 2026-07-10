package agent_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/StephenSook/erasure-proof/services/api/internal/agent"
)

// fakeConverser scripts a sequence of Converse results so the loop is exercised with no AWS calls.
type fakeConverser struct {
	steps []agent.Result
	i     int
	calls int
	err   error
}

func (f *fakeConverser) Converse(_ context.Context, _ string, _ []agent.Message, _ []agent.ToolSpec) (agent.Result, error) {
	f.calls++
	if f.err != nil {
		return agent.Result{}, f.err
	}
	r := f.steps[f.i]
	if f.i < len(f.steps)-1 {
		f.i++
	}
	return r, nil
}

// fakeTools records which tools ran and returns canned evidence.
type fakeTools struct{ called []string }

func (t *fakeTools) VerifyHashChain(context.Context) map[string]any {
	t.called = append(t.called, "verify_hash_chain")
	return map[string]any{"intact": true, "checked": 3}
}

func (t *fakeTools) CheckErasureProof(_ context.Context, subjectID string) map[string]any {
	t.called = append(t.called, "check_erasure_proof")
	return map[string]any{"erasure_recorded": true, "subject": subjectID}
}

func (t *fakeTools) ConfirmKeyDestroyed(_ context.Context, _ string) map[string]any {
	t.called = append(t.called, "confirm_key_destroyed")
	return map[string]any{"destroyed": true}
}

func toolUseStep(name string, input map[string]any) agent.Result {
	tu := agent.ToolUse{ID: "tu-" + name, Name: name, Input: input}
	return agent.Result{
		StopReason: "tool_use",
		ToolUses:   []agent.ToolUse{tu},
		Assistant:  agent.Message{Role: agent.RoleAssistant, Blocks: []agent.Block{{ToolUse: &tu}}},
	}
}

func TestAudit_GathersEvidenceThenVerdict(t *testing.T) {
	conv := &fakeConverser{steps: []agent.Result{
		toolUseStep("confirm_key_destroyed", map[string]any{"subject_id": "s1"}),
		toolUseStep("verify_hash_chain", map[string]any{}),
		{StopReason: "end_turn", Text: "VERDICT: PROVEN the key row is gone, the erasure is recorded, and the chain is intact."},
	}}
	tools := &fakeTools{}
	res, err := agent.NewForensicsAgent(conv, tools, 4).Audit(context.Background(), "s1")
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if !strings.HasPrefix(res.Verdict, "VERDICT: PROVEN") {
		t.Errorf("verdict = %q, want a PROVEN verdict", res.Verdict)
	}
	if len(res.ToolCalls) != 2 {
		t.Fatalf("recorded %d tool calls, want 2", len(res.ToolCalls))
	}
	if res.ToolCalls[0].Name != "confirm_key_destroyed" || res.ToolCalls[1].Name != "verify_hash_chain" {
		t.Errorf("trace = %v, want the two tools in order", res.ToolCalls)
	}
	// The trace carries the real tool outputs, not model claims.
	if res.ToolCalls[0].Output["destroyed"] != true {
		t.Errorf("first tool output = %v, want the real evidence", res.ToolCalls[0].Output)
	}
}

func TestAudit_ForcesVerdictWhenToolRoundsExhausted(t *testing.T) {
	// Every step asks for a tool: the loop must run out of rounds and force a final tool-less verdict.
	loop := toolUseStep("verify_hash_chain", map[string]any{})
	conv := &fakeConverser{steps: []agent.Result{loop, loop, {StopReason: "end_turn", Text: "VERDICT: NOT PROVEN, ran out of evidence-gathering rounds."}}}
	res, err := agent.NewForensicsAgent(conv, &fakeTools{}, 2).Audit(context.Background(), "s1")
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if res.Rounds != 2 {
		t.Errorf("rounds = %d, want the max (2)", res.Rounds)
	}
	// 2 tool rounds + 1 forced final call.
	if conv.calls != 3 {
		t.Errorf("converse calls = %d, want 3 (2 rounds + forced final)", conv.calls)
	}
	if !strings.HasPrefix(res.Verdict, "VERDICT: NOT PROVEN") {
		t.Errorf("verdict = %q", res.Verdict)
	}
}

func TestAudit_UnknownToolIsRecordedNotFatal(t *testing.T) {
	conv := &fakeConverser{steps: []agent.Result{
		toolUseStep("nonexistent_tool", map[string]any{}),
		{StopReason: "end_turn", Text: "VERDICT: NOT PROVEN unknown tool."},
	}}
	res, err := agent.NewForensicsAgent(conv, &fakeTools{}, 4).Audit(context.Background(), "s1")
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if res.ToolCalls[0].Output["error"] == nil {
		t.Error("an unknown tool should be recorded with an error in the trace, not crash")
	}
}

func TestAudit_ConverseErrorPropagates(t *testing.T) {
	conv := &fakeConverser{err: errors.New("throttled")}
	_, err := agent.NewForensicsAgent(conv, &fakeTools{}, 4).Audit(context.Background(), "s1")
	if err == nil || !strings.Contains(err.Error(), "throttled") {
		t.Errorf("want the converse error to propagate, got %v", err)
	}
}
