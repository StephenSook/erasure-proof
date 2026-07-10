"""HttpMemoryStore: the MemoryWriter's client for the Go api POST /memories endpoint."""

from typing import Any

import httpx


class HttpMemoryStore:
    def __init__(self, base_url: str, timeout: float = 30.0) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout

    def post_memory(self, content_b64: str, embedding_b64: str) -> dict[str, Any]:
        resp = httpx.post(
            f"{self._base}/memories",
            json={"content": content_b64, "embedding": embedding_b64},
            timeout=self._timeout,
        )
        resp.raise_for_status()
        result: dict[str, Any] = resp.json()
        return result
