import base64
from typing import Any

import pytest

from erasure_agents.bedrock import ConverseResult, ToolSpec
from erasure_agents.memory_writer import MemoryWriter


class FakeConverser:
    def __init__(self, text: str) -> None:
        self._text = text
        self.calls: list[tuple[str, list[dict[str, Any]]]] = []

    def converse(
        self, system: str, messages: list[dict[str, Any]], tools: list[ToolSpec] | None = None
    ) -> ConverseResult:
        self.calls.append((system, messages))
        return ConverseResult(
            stop_reason="end_turn",
            text=self._text,
            tool_uses=[],
            assistant_message={"role": "assistant", "content": [{"text": self._text}]},
        )


class FakeEmbedder:
    def embed(self, text: str) -> bytes:
        self.embedded = text
        return b"\x00" * 3072


class FakeStore:
    def __init__(self) -> None:
        self.posted: dict[str, str] = {}

    def post_memory(self, content_b64: str, embedding_b64: str) -> dict[str, Any]:
        self.posted = {"content_b64": content_b64, "embedding_b64": embedding_b64}
        return {"subject_id": "subj-1", "memory_id": "mem-1"}


def test_remember_stores_extracted_memory() -> None:
    converser = FakeConverser("Stephen Sookra builds on CockroachDB and AWS.")
    embedder = FakeEmbedder()
    store = FakeStore()
    writer = MemoryWriter(converser, embedder, store)

    result = writer.remember("Hi, I'm Stephen and I build on CockroachDB and AWS all day.")

    assert result.subject_id == "subj-1"
    assert result.memory_id == "mem-1"
    assert result.memory_text == "Stephen Sookra builds on CockroachDB and AWS."
    # The stored content is base64 of exactly the extracted memory text; the embedding is base64 of
    # the 3072-byte vector.
    assert base64.b64decode(store.posted["content_b64"]).decode() == result.memory_text
    assert len(base64.b64decode(store.posted["embedding_b64"])) == 3072
    assert embedder.embedded == result.memory_text


def test_remember_empty_extraction_fails_loudly() -> None:
    writer = MemoryWriter(FakeConverser("   "), FakeEmbedder(), FakeStore())
    with pytest.raises(ValueError, match="no text"):
        writer.remember("nothing useful")
