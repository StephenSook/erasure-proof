from typing import Any

from erasure_agents.bedrock import (
    BedrockConverse,
    ToolSpec,
    parse_converse_response,
)


def test_parse_text_and_tool_use() -> None:
    resp: dict[str, Any] = {
        "output": {
            "message": {
                "role": "assistant",
                "content": [
                    {"text": "let me check"},
                    {"toolUse": {"toolUseId": "t1", "name": "verify_hash_chain", "input": {}}},
                ],
            }
        },
        "stopReason": "tool_use",
    }
    result = parse_converse_response(resp)
    assert result.stop_reason == "tool_use"
    assert result.text == "let me check"
    assert len(result.tool_uses) == 1
    assert result.tool_uses[0].name == "verify_hash_chain"
    assert result.tool_uses[0].tool_use_id == "t1"


class FakeBedrockClient:
    def __init__(self, response: dict[str, Any]) -> None:
        self.response = response
        self.calls: list[dict[str, Any]] = []

    def converse(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        return self.response


def _end_turn(text: str) -> dict[str, Any]:
    return {
        "output": {"message": {"role": "assistant", "content": [{"text": text}]}},
        "stopReason": "end_turn",
    }


def test_converse_builds_kwargs_without_tools() -> None:
    client = FakeBedrockClient(_end_turn("ok"))
    conv = BedrockConverse(model_id="us.anthropic.test", client=client, max_tokens=256)
    result = conv.converse("sys", [{"role": "user", "content": [{"text": "hi"}]}])

    assert result.text == "ok"
    (call,) = client.calls
    assert call["modelId"] == "us.anthropic.test"
    assert call["system"] == [{"text": "sys"}]
    assert call["inferenceConfig"] == {"maxTokens": 256, "temperature": 0.0}
    assert "toolConfig" not in call


def test_converse_builds_toolconfig_when_tools_given() -> None:
    client = FakeBedrockClient(_end_turn("ok"))
    conv = BedrockConverse(client=client)
    tools = [ToolSpec("verify_hash_chain", "check the chain", {"type": "object", "properties": {}})]
    conv.converse("sys", [{"role": "user", "content": [{"text": "hi"}]}], tools)

    (call,) = client.calls
    spec = call["toolConfig"]["tools"][0]["toolSpec"]
    assert spec["name"] == "verify_hash_chain"
    assert spec["inputSchema"] == {"json": {"type": "object", "properties": {}}}
