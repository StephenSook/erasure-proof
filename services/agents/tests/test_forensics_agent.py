from typing import Any

from erasure_agents.bedrock import ConverseResult, ToolSpec, ToolUse
from erasure_agents.forensics_agent import ForensicsAgent


def tool_use_result(tool_uses: list[ToolUse]) -> ConverseResult:
    content = [
        {"toolUse": {"toolUseId": tu.tool_use_id, "name": tu.name, "input": tu.input}}
        for tu in tool_uses
    ]
    return ConverseResult(
        stop_reason="tool_use",
        text="",
        tool_uses=tool_uses,
        assistant_message={"role": "assistant", "content": content},
    )


def end_turn_result(text: str) -> ConverseResult:
    return ConverseResult(
        stop_reason="end_turn",
        text=text,
        tool_uses=[],
        assistant_message={"role": "assistant", "content": [{"text": text}]},
    )


class ScriptedConverser:
    def __init__(self, results: list[ConverseResult]) -> None:
        self._results = list(results)
        self.calls: list[list[dict[str, Any]]] = []

    def converse(
        self, system: str, messages: list[dict[str, Any]], tools: list[ToolSpec] | None = None
    ) -> ConverseResult:
        self.calls.append([dict(m) for m in messages])
        return self._results.pop(0)


class FakeTools:
    def __init__(self, raise_on: str | None = None) -> None:
        self._raise_on = raise_on

    def _maybe_raise(self, name: str) -> None:
        if self._raise_on == name:
            raise RuntimeError("boom")

    def verify_hash_chain(self) -> dict[str, Any]:
        self._maybe_raise("verify_hash_chain")
        return {"intact": True, "rows": 3}

    def check_erasure_proof(self, subject_id: str) -> dict[str, Any]:
        self._maybe_raise("check_erasure_proof")
        return {"subject_id": subject_id, "proof_ref": "s3://proofs/x.json"}

    def confirm_key_destroyed(self, subject_id: str) -> dict[str, Any]:
        self._maybe_raise("confirm_key_destroyed")
        return {"subject_id": subject_id, "key_present": False, "erased": True}

    def run_readonly_sql(self, query: str) -> dict[str, Any]:
        self._maybe_raise("run_readonly_sql")
        return {"rows": []}


def test_audit_runs_tool_loop_and_returns_verdict() -> None:
    converser = ScriptedConverser(
        [
            tool_use_result(
                [
                    ToolUse("t1", "confirm_key_destroyed", {"subject_id": "s1"}),
                    ToolUse("t2", "verify_hash_chain", {}),
                ]
            ),
            end_turn_result("VERDICT: PROVEN the key row is gone and the chain is intact."),
        ]
    )
    agent = ForensicsAgent(converser, FakeTools())

    result = agent.audit("s1")

    assert result.verdict.startswith("VERDICT: PROVEN")
    assert result.rounds == 2
    assert [c.name for c in result.tool_calls] == ["confirm_key_destroyed", "verify_hash_chain"]
    assert result.tool_calls[0].output == {"subject_id": "s1", "key_present": False, "erased": True}
    # The second converse call must have received the tool results as a user message.
    assert any(
        block.get("role") == "user" and any("toolResult" in b for b in block.get("content", []))
        for block in converser.calls[1]
    )


def test_tool_error_is_surfaced_not_swallowed() -> None:
    converser = ScriptedConverser(
        [
            tool_use_result([ToolUse("t1", "confirm_key_destroyed", {"subject_id": "s1"})]),
            end_turn_result("VERDICT: NOT PROVEN a tool failed."),
        ]
    )
    agent = ForensicsAgent(converser, FakeTools(raise_on="confirm_key_destroyed"))

    result = agent.audit("s1")

    assert "error" in result.tool_calls[0].output
    assert "RuntimeError" in result.tool_calls[0].output["error"]
    assert result.verdict.startswith("VERDICT: NOT PROVEN")


def test_unknown_tool_returns_error() -> None:
    converser = ScriptedConverser(
        [
            tool_use_result([ToolUse("t1", "made_up_tool", {})]),
            end_turn_result("VERDICT: NOT PROVEN."),
        ]
    )
    agent = ForensicsAgent(converser, FakeTools())
    result = agent.audit("s1")
    assert "unknown tool" in result.tool_calls[0].output["error"]


def test_max_rounds_forces_final_verdict() -> None:
    # A converser that never stops asking for tools must still terminate with a forced verdict.
    always_tool = [tool_use_result([ToolUse(f"t{i}", "verify_hash_chain", {})]) for i in range(3)]
    always_tool.append(end_turn_result("VERDICT: NOT PROVEN ran out of tool budget."))
    agent = ForensicsAgent(ScriptedConverser(always_tool), FakeTools(), max_rounds=3)

    result = agent.audit("s1")

    assert result.rounds == 3
    assert result.verdict.startswith("VERDICT: NOT PROVEN")
    # Three tool rounds happened before the forced final call.
    assert len(result.tool_calls) == 3
