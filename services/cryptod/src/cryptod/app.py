"""cryptod HTTP service. The Go orchestrator calls these endpoints on the ingest and post-commit
paths; all key handling stays here because Vec2Text and the crypto libraries are Python.

Endpoints:
  POST /prepare      generate a data key, encrypt content + embedding, return the ciphertexts
  POST /shred        DeleteImportedKeyMaterial for an imported-material subject (kill switch 2)
  POST /anchor       build, ECDSA-sign, and S3-Object-Lock-anchor an erasure proof
  POST /proof/verify verify a signed proof
  GET  /healthz      liveness

Note: this module deliberately does not use `from __future__ import annotations`; FastAPI resolves
request-body models from real annotations, and the future import turns them into strings that break
body detection.
"""

import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from . import aead, anchor, kms, proof, settings, signing


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


class PrepareRequest(BaseModel):
    subject_id: str
    content: str  # base64
    embedding: str  # base64 (raw float32 bytes of the GTR vector)


class ShredRequest(BaseModel):
    key_arn: str


class AnchorRequest(BaseModel):
    subject_hash: str  # hex
    occurred_at: str
    decision_log_seq: int
    chain_head: str  # hex
    wrapped_key_fingerprint: str  # hex
    kms_key_arn: str
    key_state: str


class VerifyRequest(BaseModel):
    proof: dict
    signature: str  # base64
    public_key_pem: str


def _load_signer(cfg: settings.Settings) -> ec.EllipticCurvePrivateKey:
    if cfg.ecdsa_signing_key_path:
        with open(cfg.ecdsa_signing_key_path, "rb") as f:
            key = load_pem_private_key(f.read(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise TypeError("configured signing key is not an EC private key")
        return key
    # Ephemeral dev key; production sets ECDSA_SIGNING_KEY_PATH (or uses KMS asymmetric sign).
    return signing.generate_private_key()


def create_app(cfg: settings.Settings | None = None) -> FastAPI:
    cfg = cfg or settings.load()
    app = FastAPI(title="cryptod", version="0.1.0")
    signer = _load_signer(cfg)
    signer_pub_pem = signing.public_key_pem(signer.public_key())

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True}

    @app.post("/prepare")
    def prepare(req: PrepareRequest) -> dict:
        if not cfg.kms_wrapping_key_arn:
            raise HTTPException(500, "KMS_WRAPPING_KEY_ARN not configured")
        dk = kms.KMS(cfg.aws_region).generate_data_key(cfg.kms_wrapping_key_arn, req.subject_id)
        aad = req.subject_id.encode()
        content_ct = aead.encrypt(dk.plaintext, _b64d(req.content), aad)
        embedding_ct = aead.encrypt(dk.plaintext, _b64d(req.embedding), aad)
        # dk.plaintext goes out of scope here; only the wrapped copy is returned for storage.
        return {
            "content_ciphertext": _b64e(content_ct.ct),
            "nonce_content": _b64e(content_ct.nonce),
            "embedding_ciphertext": _b64e(embedding_ct.ct),
            "nonce_embedding": _b64e(embedding_ct.nonce),
            "wrapped_key": _b64e(dk.wrapped),
            "wrapped_key_fingerprint": hashlib.sha256(dk.wrapped).hexdigest(),
        }

    @app.post("/shred")
    def shred(req: ShredRequest) -> dict:
        state = kms.KMS(cfg.aws_region).destroy_imported_key(req.key_arn)
        return {"key_state": state, "destroyed": state == "PendingImport"}

    @app.post("/anchor")
    def anchor_proof(req: AnchorRequest) -> dict:
        doc = proof.build_proof(
            subject_hash_hex=req.subject_hash,
            occurred_at=req.occurred_at,
            decision_log_seq=req.decision_log_seq,
            chain_head_hex=req.chain_head,
            wrapped_key_fingerprint_hex=req.wrapped_key_fingerprint,
            kms_key_arn=req.kms_key_arn,
            key_state=req.key_state,
            signer_public_key_pem=signer_pub_pem,
        )
        signature = proof.sign_proof(signer, doc)
        body = proof.canonical_bytes(doc)
        key = f"{req.subject_hash}/{req.decision_log_seq}.json"
        result = anchor.S3Anchor(cfg.aws_region).anchor(
            cfg.s3_proof_bucket, key, body, cfg.s3_object_lock_mode, cfg.s3_retain_days
        )
        return {
            "proof": doc,
            "signature": _b64e(signature),
            "proof_ref": f"s3://{result.bucket}/{result.key}",
            "object_lock_mode": result.mode,
            "retain_until": result.retain_until,
            "sha256": result.sha256,
        }

    @app.post("/proof/verify")
    def verify(req: VerifyRequest) -> dict:
        pub = signing.load_public_key_pem(req.public_key_pem)
        try:
            proof.verify_proof(pub, req.proof, _b64d(req.signature))
        except signing.InvalidSignature:
            return {"valid": False}
        return {"valid": True}

    return app


app = create_app()
