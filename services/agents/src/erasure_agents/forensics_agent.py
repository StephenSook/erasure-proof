"""ForensicsAgent: a Claude tool-use loop bridged to the read-only forensics tools.

Given a subject id, Claude decides which of the four read-only tools to call (the same tools the MCP
server exposes), gathers evidence, and returns a verdict. The tools are injected as an interface, so
the agent is fully testable without a database, and the real wiring (a psycopg connection or the MCP
client) is supplied at the edge.

The agent never asserts anything the tools did not return; the system prompt forbids it and the
tool outputs are the only evidence in the transcript.
"""

import dataclasses
from typing import Any, Protocol

from .bedrock import Converser, ToolSpec, ToolUse

AUDIT_SYSTEM = (
    "You are a forensic auditor for an erasure-proof system. Decide whether a data subject's "
    "personal data has been provably and irreversibly erased. Use the read-only tools to gather "
    "evidence: confirm the per-subject key row is gone (so the ciphertext can never be decrypted), "
    "confirm the erasure is recorded, and verify the decision-log hash chain is intact. Then give "
    "a final line that begins with 'VERDICT: PROVEN' or 'VERDICT: NOT PROVEN', followed by one "
    "sentence citing the evidence. Never claim anything the tools did not show."
)

TOOL_SPECS: list[ToolSpec] = [
    ToolSpec(
        name="confirm_key_destroyed",
        description=(
            "Confirm the subject's wrapped-key row is absent and an erasure was recorded. This is "
            "the crypto-shred check: without the key the ciphertext is unrecoverable."
        ),
        input_schema={
            "type": "object",
            "properties": {"subject_id": {"type": "string"}},
            "required": ["subject_id"],
        },
    ),
    ToolSpec(
        name="check_erasure_proof",
        description="Return the recorded erasure-proof state for a subject (seq, fingerprint).",
        input_schema={
            "type": "object",
            "properties": {"subject_id": {"type": "string"}},
            "required": ["subject_id"],
        },
    ),
    ToolSpec(
        name="verify_hash_chain",
        description="Recompute the decision-log SHA-256 hash chain and report if it is intact.",
        input_schema={"type": "object", "properties": {}, "required": []},
    ),
    ToolSpec(
        name="run_readonly_sql",
        description="Run a single read-only SELECT for ad-hoc evidence. Mutations are rejected.",
        input_schema={
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    ),
]


class ForensicsTools(Protocol):
    def verify_hash_chain(self) -> dict[str, Any]: ...
    def check_erasure_proof(self, subject_id: str) -> dict[str, Any]: ...
    def confirm_key_destroyed(self, subject_id: str) -> dict[str, Any]: ...
    def run_readonly_sql(self, query: str) -> dict[str, Any]: ...


@dataclasses.dataclass(frozen=True)
class ToolCall:
    name: str
    input: dict[str, Any]
    output: dict[str, Any]


@dataclasses.dataclass(frozen=True)
class AuditResult:
    verdict: str
    tool_calls: list[ToolCall]
    rounds: int


class ForensicsAgent:
    def __init__(self, converser: Converser, tools: ForensicsTools, max_rounds: int = 4) -> None:
        self._converser = converser
        self._tools = tools
        self._max_rounds = max_rounds

    def audit(self, subject_id: str) -> AuditResult:
        messages: list[dict[str, Any]] = [
            {
                "role": "user",
                "content": [
                    {"text": f"Audit subject {subject_id}. Is its erasure provable and final?"}
                ],
            }
        ]
        calls: list[ToolCall] = []

        for round_index in range(self._max_rounds):
            result = self._converser.converse(AUDIT_SYSTEM, messages, TOOL_SPECS)
            messages.append({"role": "assistant", "content": result.assistant_message["content"]})

            if result.stop_reason != "tool_use" or not result.tool_uses:
                return AuditResult(result.text, calls, round_index + 1)

            tool_results: list[dict[str, Any]] = []
            for tu in result.tool_uses:
                output = self._dispatch(tu)
                calls.append(ToolCall(tu.name, tu.input, output))
                tool_results.append(
                    {"toolResult": {"toolUseId": tu.tool_use_id, "content": [{"json": output}]}}
                )
            messages.append({"role": "user", "content": tool_results})

        # Out of tool rounds: force a final verdict. The transcript now carries tool_use and
        # tool_result blocks, and Bedrock Converse rejects a request that has tool blocks but no
        # toolConfig, so pass the specs even though we want prose; the prompt tells the model to
        # stop calling tools. If it emits another tool_use anyway, final.text is empty, so we
        # substitute an explicit inconclusive verdict rather than returning a blank.
        final = self._converser.converse(
            AUDIT_SYSTEM
            + " You have no more tool calls; give your final verdict now as text,"
            + " without calling any tool.",
            messages,
            TOOL_SPECS,
        )
        verdict = final.text or (
            "NOT PROVEN: the audit did not reach a text verdict within the tool-call budget."
        )
        return AuditResult(verdict, calls, self._max_rounds)

    def _dispatch(self, tu: ToolUse) -> dict[str, Any]:
        # A tool error is returned to the model as evidence (and recorded in the trace) rather than
        # aborting the audit; a partial audit that says so beats a crash.
        try:
            if tu.name == "verify_hash_chain":
                return self._tools.verify_hash_chain()
            if tu.name == "check_erasure_proof":
                return self._tools.check_erasure_proof(str(tu.input["subject_id"]))
            if tu.name == "confirm_key_destroyed":
                return self._tools.confirm_key_destroyed(str(tu.input["subject_id"]))
            if tu.name == "run_readonly_sql":
                return self._tools.run_readonly_sql(str(tu.input["query"]))
            return {"error": f"unknown tool {tu.name!r}"}
        except KeyError as e:
            return {"error": f"missing tool argument: {e}"}
        except Exception as e:  # noqa: BLE001 - surfaced to the model + recorded, never swallowed
            return {"error": f"{type(e).__name__}: {e}"}
