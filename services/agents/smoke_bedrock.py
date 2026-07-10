"""Tiny live Bedrock smoke: proves real Converse access with a single minimal call.

Deliberately minimal because the new-account daily-token quota is low. NOT run in CI (needs AWS
creds). Run manually:

    AWS_PROFILE=erasure-admin AWS_REGION=us-east-1 python services/agents/smoke_bedrock.py

Expects the model to reply with one word. A ThrottlingException here means access works but the daily
token quota is exhausted (request a Bedrock invocation-tokens quota increase), not that access failed.
"""

import sys

from erasure_agents.bedrock import BedrockConverse


def main() -> int:
    conv = BedrockConverse(max_tokens=16)
    result = conv.converse(
        system="You are a health probe. Reply with exactly one word.",
        messages=[{"role": "user", "content": [{"text": "Say READY."}]}],
    )
    print(f"stop_reason={result.stop_reason!r} text={result.text!r}")
    if not result.text:
        print("no text returned", file=sys.stderr)
        return 1
    print("bedrock converse OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
