// Package agent runs the forensics agent that proves an erasure on the live console: a Bedrock
// Claude tool-use loop over the read-only forensics tools. Claude decides which tools to call,
// gathers evidence, and returns a PROVEN / NOT PROVEN verdict with the full tool-call trace shown
// on screen. The agent never asserts anything the tools did not return.
//
// This is the Go, console-serving twin of the tested Python ForensicsAgent in services/agents; it
// lives here because the Go api is the deployed surface and already holds the read-only tool
// implementations. The Converser is an interface so the loop is tested against a scripted fake with
// no AWS calls.
package agent

import (
	"context"
	"fmt"
)

// Role is a Converse message role.
type Role string

const (
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
)

// ToolSpec advertises a tool to the model.
type ToolSpec struct {
	Name        string
	Description string
	InputSchema map[string]any
}

// ToolUse is a tool the model asked to call.
type ToolUse struct {
	ID    string
	Name  string
	Input map[string]any
}

// Block is one content block of a message: exactly one of Text, ToolUse, or ToolResult is set.
type Block struct {
	Text       string
	ToolUse    *ToolUse
	ToolResult *ToolResult
}

// ToolResult carries a tool's JSON output back to the model.
type ToolResult struct {
	ToolUseID string
	JSON      map[string]any
}

// Message is one turn in the running transcript.
type Message struct {
	Role   Role
	Blocks []Block
}

// Result is the parsed outcome of one Converse turn.
type Result struct {
	StopReason string
	Text       string
	ToolUses   []ToolUse
	// Assistant is the assistant message to append to the transcript verbatim before the next turn.
	Assistant Message
}

// Converser is the Bedrock Converse boundary (real impl in bedrock.go; a fake drives the tests).
type Converser interface {
	Converse(ctx context.Context, system string, messages []Message, tools []ToolSpec) (Result, error)
}

// Tools is the read-only forensic evidence the agent can gather. Implemented over the demo gateway's
// read methods. Every method returns a JSON-able map that becomes the model's evidence.
type Tools interface {
	VerifyHashChain(ctx context.Context) map[string]any
	CheckErasureProof(ctx context.Context, subjectID string) map[string]any
	ConfirmKeyDestroyed(ctx context.Context, subjectID string) map[string]any
}

// ToolCall is one recorded tool invocation for the on-screen trace.
type ToolCall struct {
	Name   string         `json:"name"`
	Input  map[string]any `json:"input"`
	Output map[string]any `json:"output"`
}

// AuditResult is the agent's verdict plus its full evidence trace.
type AuditResult struct {
	Verdict   string     `json:"verdict"`
	ToolCalls []ToolCall `json:"tool_calls"`
	Rounds    int        `json:"rounds"`
}

const auditSystem = "You are a forensic auditor for an erasure-proof system. Decide whether a data " +
	"subject's personal data has been provably and irreversibly erased. Use the read-only tools to " +
	"gather evidence: confirm the per-subject key row is gone (so the ciphertext can never be " +
	"decrypted), confirm the erasure is recorded, and verify the decision-log hash chain is intact. " +
	"Then give a final line that begins with 'VERDICT: PROVEN' or 'VERDICT: NOT PROVEN', followed by " +
	"one sentence citing the evidence. Never claim anything the tools did not show."

// ForensicsToolSpecs are the three tools advertised to the model.
var ForensicsToolSpecs = []ToolSpec{
	{
		Name: "confirm_key_destroyed",
		Description: "Confirm the subject's wrapped-key row is absent and an erasure was recorded. " +
			"This is the crypto-shred check: without the key the ciphertext is unrecoverable.",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"subject_id": map[string]any{"type": "string"}},
			"required":   []string{"subject_id"},
		},
	},
	{
		Name:        "check_erasure_proof",
		Description: "Return the recorded erasure-proof state for a subject (seq, fingerprint, proof ref).",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"subject_id": map[string]any{"type": "string"}},
			"required":   []string{"subject_id"},
		},
	},
	{
		Name:        "verify_hash_chain",
		Description: "Recompute the decision-log SHA-256 hash chain and report whether it is intact.",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
	},
}

// ForensicsAgent runs the bounded tool-use loop.
type ForensicsAgent struct {
	converser Converser
	tools     Tools
	maxRounds int
}

// NewForensicsAgent builds the agent. maxRounds bounds the loop so it always terminates.
func NewForensicsAgent(c Converser, t Tools, maxRounds int) *ForensicsAgent {
	if maxRounds < 1 {
		maxRounds = 4
	}
	return &ForensicsAgent{converser: c, tools: t, maxRounds: maxRounds}
}

// Audit gathers evidence about subjectID and returns the verdict with its trace.
func (a *ForensicsAgent) Audit(ctx context.Context, subjectID string) (AuditResult, error) {
	messages := []Message{{
		Role:   RoleUser,
		Blocks: []Block{{Text: fmt.Sprintf("Audit subject %s. Is its erasure provable and final?", subjectID)}},
	}}
	var calls []ToolCall

	for round := 0; round < a.maxRounds; round++ {
		res, err := a.converser.Converse(ctx, auditSystem, messages, ForensicsToolSpecs)
		if err != nil {
			return AuditResult{}, fmt.Errorf("converse round %d: %w", round, err)
		}
		messages = append(messages, res.Assistant)

		if res.StopReason != "tool_use" || len(res.ToolUses) == 0 {
			return AuditResult{Verdict: res.Text, ToolCalls: calls, Rounds: round + 1}, nil
		}

		results := make([]Block, 0, len(res.ToolUses))
		for _, tu := range res.ToolUses {
			out := a.dispatch(ctx, tu, subjectID)
			calls = append(calls, ToolCall{Name: tu.Name, Input: tu.Input, Output: out})
			results = append(results, Block{ToolResult: &ToolResult{ToolUseID: tu.ID, JSON: out}})
		}
		messages = append(messages, Message{Role: RoleUser, Blocks: results})
	}

	// Out of tool rounds: force a final verdict with no tools so the loop always terminates.
	final, err := a.converser.Converse(ctx,
		auditSystem+" You have no more tool calls; give your final verdict now.", messages, nil)
	if err != nil {
		return AuditResult{}, fmt.Errorf("final converse: %w", err)
	}
	return AuditResult{Verdict: final.Text, ToolCalls: calls, Rounds: a.maxRounds}, nil
}

// dispatch runs one tool. A tool error is returned to the model as evidence (and recorded in the
// trace), never swallowed, so a partial audit that says so beats a crash.
func (a *ForensicsAgent) dispatch(ctx context.Context, tu ToolUse, subjectID string) map[string]any {
	switch tu.Name {
	case "verify_hash_chain":
		return a.tools.VerifyHashChain(ctx)
	case "check_erasure_proof":
		return a.tools.CheckErasureProof(ctx, argSubject(tu.Input, subjectID))
	case "confirm_key_destroyed":
		return a.tools.ConfirmKeyDestroyed(ctx, argSubject(tu.Input, subjectID))
	default:
		return map[string]any{"error": fmt.Sprintf("unknown tool %q", tu.Name)}
	}
}

// argSubject reads the model's subject_id argument, falling back to the audited subject if the model
// omitted it (the audit is always scoped to one subject, so this is safe and avoids a dead round).
func argSubject(input map[string]any, fallback string) string {
	if v, ok := input["subject_id"].(string); ok && v != "" {
		return v
	}
	return fallback
}
