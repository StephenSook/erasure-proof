"""A thin wrapper over the Bedrock Converse API.

Converser is an interface so the agents can be tested against a scripted fake with no AWS calls.
The real implementation targets the cross-region inference-profile id (prefix `us.anthropic.`),
because the bare `anthropic.claude-*` id raises ValidationException (on-demand throughput is not
supported for these models).
"""

import dataclasses
import os
from typing import Any, Protocol

# The granted entitlement on this account is Claude Haiku 4.5; it is also the cheapest, which
# matters under the low daily-token quota. Override with AGENTS_MODEL_ID if needed.
DEFAULT_MODEL_ID = "us.anthropic.claude-haiku-4-5-20251001-v1:0"


@dataclasses.dataclass(frozen=True)
class ToolSpec:
    """A tool advertised to the model (Converse toolConfig)."""

    name: str
    description: str
    input_schema: dict[str, Any]


@dataclasses.dataclass(frozen=True)
class ToolUse:
    """A tool the model asked to call."""

    tool_use_id: str
    name: str
    input: dict[str, Any]


@dataclasses.dataclass(frozen=True)
class ConverseResult:
    """The parsed result of one Converse turn."""

    stop_reason: str
    text: str
    tool_uses: list[ToolUse]
    assistant_message: dict[str, Any]  # the raw content blocks, to append to the running transcript


class Converser(Protocol):
    def converse(
        self,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[ToolSpec] | None = None,
    ) -> ConverseResult: ...


def parse_converse_response(resp: dict[str, Any]) -> ConverseResult:
    """Parse a raw boto3 Converse response into a ConverseResult."""
    message = resp["output"]["message"]
    text_parts: list[str] = []
    tool_uses: list[ToolUse] = []
    for block in message.get("content", []):
        if "text" in block:
            text_parts.append(block["text"])
        elif "toolUse" in block:
            tu = block["toolUse"]
            tool_uses.append(ToolUse(tu["toolUseId"], tu["name"], tu.get("input", {}) or {}))
    return ConverseResult(
        stop_reason=resp.get("stopReason", ""),
        text="".join(text_parts).strip(),
        tool_uses=tool_uses,
        assistant_message=message,
    )


class BedrockConverse:
    """The real Converse client. The boto3 client is created lazily so importing this module (and
    running the mocked tests) never requires AWS credentials."""

    def __init__(
        self,
        model_id: str | None = None,
        region: str | None = None,
        max_tokens: int = 512,
        client: Any | None = None,
    ) -> None:
        self._model_id = model_id or os.environ.get("AGENTS_MODEL_ID", DEFAULT_MODEL_ID)
        self._region = region or os.environ.get("AWS_REGION", "us-east-1")
        self._max_tokens = max_tokens
        self._client = client

    def _bedrock(self) -> Any:
        if self._client is None:
            import boto3

            self._client = boto3.client("bedrock-runtime", region_name=self._region)
        return self._client

    def converse(
        self,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[ToolSpec] | None = None,
    ) -> ConverseResult:
        kwargs: dict[str, Any] = {
            "modelId": self._model_id,
            "messages": messages,
            "system": [{"text": system}],
            "inferenceConfig": {"maxTokens": self._max_tokens, "temperature": 0.0},
        }
        if tools:
            kwargs["toolConfig"] = {
                "tools": [
                    {
                        "toolSpec": {
                            "name": t.name,
                            "description": t.description,
                            "inputSchema": {"json": t.input_schema},
                        }
                    }
                    for t in tools
                ]
            }
        resp = self._bedrock().converse(**kwargs)
        return parse_converse_response(resp)
