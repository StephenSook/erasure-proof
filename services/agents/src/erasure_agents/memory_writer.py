"""MemoryWriter: real Claude inference feeding the memory layer.

Given a conversation turn, Claude distils the single durable fact worth remembering, then the writer
embeds it (GTR-base) and stores it through the real ingest path (POST /memories), so the memory the
demo later erases was genuinely written by an agent, not hand-inserted.
"""

import base64
import dataclasses
from typing import Any, Protocol

from .bedrock import Converser

EXTRACT_SYSTEM = (
    "You are the memory-writing step of an AI agent. Read the user's message and reply with ONE "
    "concise sentence stating the single durable fact about the person that is worth remembering. "
    "Reply with only that sentence: no preamble, no quotes, no explanation."
)


class Embedder(Protocol):
    def embed(self, text: str) -> bytes:
        """Return the 768-dim GTR embedding as raw little-endian float32 bytes (3072 bytes)."""
        ...


class MemoryStore(Protocol):
    def post_memory(self, content_b64: str, embedding_b64: str) -> dict[str, Any]:
        """POST /memories; returns the response including subject_id and memory_id."""
        ...


@dataclasses.dataclass(frozen=True)
class WriteResult:
    memory_text: str
    subject_id: str
    memory_id: str


class MemoryWriter:
    def __init__(self, converser: Converser, embedder: Embedder, store: MemoryStore) -> None:
        self._converser = converser
        self._embedder = embedder
        self._store = store

    def remember(self, conversation_turn: str) -> WriteResult:
        result = self._converser.converse(
            EXTRACT_SYSTEM,
            [{"role": "user", "content": [{"text": conversation_turn}]}],
        )
        memory_text = result.text.strip()
        if not memory_text:
            # Fail loudly rather than store an empty memory: the model produced nothing usable.
            raise ValueError("memory extraction returned no text")

        embedding = self._embedder.embed(memory_text)
        stored = self._store.post_memory(
            base64.b64encode(memory_text.encode("utf-8")).decode(),
            base64.b64encode(embedding).decode(),
        )
        return WriteResult(
            memory_text=memory_text,
            subject_id=stored["subject_id"],
            memory_id=stored["memory_id"],
        )
