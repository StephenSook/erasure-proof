"""Live open-model inference on a Modal serverless GPU (T4), OpenAI-compatible.

This backs the console's live agent beats (forensics auditor, memory writer) when Bedrock is not
available: a new AWS account ships with a zero Bedrock quota, and the hackathon organizers
explicitly blessed open-model inference as the workaround. The Go api speaks the OpenAI
chat-completions dialect to this endpoint through the same Converser interface it uses for
Bedrock, and every on-screen result is labeled with which provider actually answered.

Design and cost guards (same posture as the inversion worker):
  * llama.cpp's native server with --jinja, so the model's own chat template drives OpenAI-style
    tool calling; Qwen2.5-3B-Instruct carries a tool-call template and the Q4_K_M GGUF fits a T4
    with room to spare. Weights are baked into the image at build time for a fast cold start.
  * gpu="T4", a short scaledown window, and max_containers=1 bound the spend: the api layer in
    front adds its own semaphore and rolling-hour budget, so one container is enough.
  * llama-server's --api-key flag gates every request; the key lives in a Modal secret and in SSM
    for the api task. The endpoint URL is not published.

Deploy:  modal deploy services/llm-worker/modal_llm.py
Secret:  modal secret create erasure-llm-secret LLM_API_KEY=<random>
The deploy prints the endpoint URL; set AGENTS_LLM_URL (+ AGENTS_LLM_SECRET via SSM) for the api.
"""

from __future__ import annotations

import subprocess

import modal

MODEL_URL = (
    "https://huggingface.co/Qwen/Qwen2.5-3B-Instruct-GGUF/resolve/main/"
    "qwen2.5-3b-instruct-q4_k_m.gguf"
)
MODEL_PATH = "/models/qwen2.5-3b-instruct-q4_k_m.gguf"
PORT = 8000

# The official llama.cpp CUDA server image; Modal injects its own Python alongside it.
image = (
    modal.Image.from_registry("ghcr.io/ggml-org/llama.cpp:server-cuda", add_python="3.11")
    .entrypoint([])  # the image's default entrypoint would start the server before Modal does
    .run_commands(f"mkdir -p /models && curl -fsSL -o {MODEL_PATH} '{MODEL_URL}'")
)

app = modal.App("erasure-proof-llm")


@app.function(
    image=image,
    gpu="T4",
    scaledown_window=300,
    max_containers=1,
    timeout=600,
    secrets=[modal.Secret.from_name("erasure-llm-secret")],
)
@modal.concurrent(max_inputs=4)
@modal.web_server(port=PORT, startup_timeout=180)
def serve() -> None:
    import os

    subprocess.Popen(
        [
            "/app/llama-server",
            "--model", MODEL_PATH,
            "--host", "0.0.0.0",
            "--port", str(PORT),
            "--jinja",              # the model's chat template drives OpenAI-style tool calls
            "-ngl", "99",           # all layers on the GPU
            "--ctx-size", "8192",
            "--api-key", os.environ["LLM_API_KEY"],
        ]
    )
