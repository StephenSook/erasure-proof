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
import binascii
import hashlib
import logging

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel

from . import aead, anchor, envelope, inversion, kms, proof, settings, signing

log = logging.getLogger("cryptod")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


class PrepareRequest(BaseModel):
    subject_id: str
    content: str  # base64
    embedding: str  # base64 (raw float32 bytes of the GTR vector)
    # Optional hex of the decision-log chain head at write time (empty at genesis). When present,
    # the AAD becomes subject_id || chain_head. Precise claim: an AAD reconstructed from a TAMPERED
    # history fails InvalidTag; the exact bytes are also stored with the row (aad_context), which
    # makes the binding verifiable against the log but does not make decryption depend on the log's
    # current state. cryptod is inside the trust boundary: the caller cross-checks the returned AAD
    # bytes but cannot detect a cryptod that encrypts under different bytes than it returns.
    chain_head: str = ""


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
    # RFC 6962 Merkle tree over the decision log at anchor time. Signing it into the proof means
    # each erasure proof also attests the transparency-log state it was recorded in. Empty/0 when
    # the caller does not supply a tree (older callers), so the field is optional.
    merkle_root: str = ""  # hex
    tree_size: int = 0


class VerifyRequest(BaseModel):
    proof: dict
    signature: str  # base64
    public_key_pem: str


class LiveInvertRequest(BaseModel):
    embedding: str  # base64 of the raw float32 GTR vector bytes (3072 bytes)
    num_steps: int = 50
    sequence_beam_width: int = 8


class EmbedRequest(BaseModel):
    text: str  # the fact to embed (canonical GTR pipeline, on the Modal GPU)


def _load_signer(cfg: settings.Settings) -> signing.ProofSigner:
    # Preferred: a KMS asymmetric key. The private key never exists in this process; the task
    # holds only kms:Sign + kms:GetPublicKey on the one signing key, and every Sign call lands in
    # CloudTrail. Fails at boot (GetPublicKey) on a wrong key or missing permission.
    if cfg.kms_signing_key_arn:
        return signing.KmsSigner(cfg.kms_signing_key_arn, cfg.aws_region)
    if cfg.ecdsa_signing_key_path:
        with open(cfg.ecdsa_signing_key_path, "rb") as f:
            key = load_pem_private_key(f.read(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise TypeError("configured signing key is not an EC private key")
        return signing.LocalSigner(key)
    # No configured key. An ephemeral key vanishes on restart, so proofs it signs can never be
    # attributed later. Fail closed when anchoring to immutable COMPLIANCE storage; otherwise warn
    # loudly so an ephemeral signer is never mistaken for a configured one.
    if cfg.s3_object_lock_mode == "COMPLIANCE":
        raise RuntimeError(
            "KMS_SIGNING_KEY_ARN or ECDSA_SIGNING_KEY_PATH is required with COMPLIANCE Object "
            "Lock: an ephemeral signer would write permanently-locked proofs signed by a key "
            "that is lost on restart"
        )
    log.warning(
        "cryptod: no KMS_SIGNING_KEY_ARN or ECDSA_SIGNING_KEY_PATH set; using an EPHEMERAL "
        "signer. Proofs will NOT verify across restarts. Configure a signer for anything but "
        "local development."
    )
    return signing.LocalSigner(signing.generate_private_key())


def create_app(cfg: settings.Settings | None = None) -> FastAPI:
    cfg = cfg or settings.load()
    app = FastAPI(title="cryptod", version="0.1.0")
    signer = _load_signer(cfg)
    signer_pub_pem = signer.public_key_pem

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True}

    @app.get("/invert")
    def invert() -> dict:
        """Serve the recorded Vec2Text golden run (the illustrative attack), clearly labeled."""
        try:
            return inversion.recorded_golden_run()
        except FileNotFoundError as e:
            raise HTTPException(503, "recorded golden run not available") from e

    @app.get("/invert/config")
    def invert_config() -> dict:
        """Whether live GPU inversion is available, so the UI can show or hide the live button."""
        return {"live_available": bool(cfg.modal_invert_url and cfg.modal_invert_secret)}

    @app.get("/embed/config")
    def embed_config() -> dict:
        """Whether live GTR embedding is available (drives the agent memory-writer)."""
        return {"embed_available": bool(cfg.modal_embed_url and cfg.modal_invert_secret)}

    @app.post("/embed/live")
    def embed_live(req: EmbedRequest) -> dict:
        """Embed a fact on the Modal GPU (canonical GTR pipeline) for the live memory-writer."""
        try:
            return inversion.live_embed(
                req.text, modal_url=cfg.modal_embed_url, modal_secret=cfg.modal_invert_secret
            )
        except inversion.LiveEmbedUnavailable as exc:
            raise HTTPException(503, f"live embedding unavailable: {exc}") from exc

    @app.post("/invert/live")
    def invert_live(req: LiveInvertRequest) -> dict:
        """Invert an embedding on the Modal T4 GPU, live. Falls back to the recorded golden run
        (with source="recorded_golden_run") if the worker is unconfigured or unreachable, so the
        demo never hard-fails; the honest source label always tells the viewer which path ran."""
        try:
            return inversion.live_inversion(
                req.embedding,
                modal_url=cfg.modal_invert_url,
                modal_secret=cfg.modal_invert_secret,
                num_steps=req.num_steps,
                sequence_beam_width=req.sequence_beam_width,
            )
        except inversion.LiveInversionUnavailable as exc:
            log.warning("live inversion unavailable, falling back to recorded: %s", exc)
            try:
                fallback = inversion.recorded_golden_run()
            except FileNotFoundError as e:
                raise HTTPException(503, "live inversion unavailable and no recorded run") from e
            fallback["fell_back"] = True
            fallback["fallback_reason"] = str(exc)
            return fallback

    @app.post("/prepare")
    def prepare(req: PrepareRequest) -> dict:
        if not cfg.kms_wrapping_key_arn:
            raise HTTPException(500, "KMS_WRAPPING_KEY_ARN not configured")
        # Two-level envelope. The subject key is generated + KMS-wrapped and stored once in
        # subject_keys; a fresh per-row data key is wrapped UNDER the subject key and stored in the
        # agent_memory row. Content and embedding are encrypted with the row key. Erasure deletes
        # the subject_keys row, so the subject key (only ever held there in KMS-wrapped form) is
        # gone, the row key can never be unwrapped, and the ciphertext is dead. The row wrapped key
        # surviving in agent_memory is useless without the destroyed subject key.
        subject = kms.KMS(cfg.aws_region).generate_data_key(
            cfg.kms_wrapping_key_arn, req.subject_id
        )
        row_key = envelope.new_data_key()
        row_material = envelope.wrap_data_key(subject.plaintext, row_key)
        # AAD = subject_id || chain_head: the ciphertext is bound to both the person and the
        # decision-log state at write time. The head is a SHA-256, so exactly 64 hex chars (or
        # empty at genesis); the length check also rejects whitespace-containing hex (bytes.fromhex
        # silently accepts it) and caps the field. Malformed input is a caller error, not a 500.
        if req.chain_head and len(req.chain_head) != 64:
            raise HTTPException(400, "chain_head must be empty or 64 hex chars")
        try:
            chain_head = bytes.fromhex(req.chain_head) if req.chain_head else b""
        except ValueError as e:
            raise HTTPException(400, "chain_head must be hex") from e
        aad = req.subject_id.encode() + chain_head
        content_ct = aead.encrypt(row_key, _b64d(req.content), aad)
        embedding_ct = aead.encrypt(row_key, _b64d(req.embedding), aad)
        # subject.plaintext and row_key go out of scope here; only wrapped copies are returned.
        return {
            "content_ciphertext": _b64e(content_ct.ct),
            "nonce_content": _b64e(content_ct.nonce),
            "embedding_ciphertext": _b64e(embedding_ct.ct),
            "nonce_embedding": _b64e(embedding_ct.nonce),
            "subject_wrapped_key": _b64e(subject.wrapped),
            "subject_key_fingerprint": hashlib.sha256(subject.wrapped).hexdigest(),
            "row_wrapped_key": _b64e(row_material.wrapped),
            "kms_key_arn": cfg.kms_wrapping_key_arn,
            # The origin the key was made with. /prepare always uses GenerateDataKey today; the
            # orchestrator branches on this for the imported-material kill switch, so it is reported
            # explicitly rather than inferred downstream.
            "key_origin": "GENERATE_DATA_KEY",
            # The exact AAD bytes used, returned so the caller stores them verbatim in the row
            # (agent_memory.aad_context); any future decrypt must present these exact bytes.
            "aad": _b64e(aad),
        }

    @app.post("/shred")
    def shred(req: ShredRequest, response: Response) -> dict:
        # The delete itself propagates on failure (500). A non-PendingImport result here means the
        # material was deleted but confirmation is still lagging (KMS eventual consistency), NOT
        # that erasure failed, so we return 202 with an explicit pending status rather than a
        # misleading destroyed:false.
        state = kms.KMS(cfg.aws_region).destroy_imported_key(req.key_arn)
        if state == "PendingImport":
            return {"destroyed": True, "key_state": state}
        response.status_code = 202
        return {"destroyed": False, "status": "pending_confirmation", "key_state": state}

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
            merkle_root_hex=req.merkle_root,
            tree_size=req.tree_size,
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
            # The EXACT canonical bytes the signature covers, so callers can store and later
            # verify them verbatim (browser WebCrypto) with no cross-language re-canonicalization.
            "proof_canonical": _b64e(body),
            "signer_public_key_pem": signer_pub_pem,
            "proof_ref": f"s3://{result.bucket}/{result.key}",
            "object_lock_mode": result.mode,
            "retain_until": result.retain_until,
            "sha256": result.sha256,
        }

    @app.post("/proof/verify")
    def verify(req: VerifyRequest) -> dict:
        # A bad signature is a legitimate valid:false. Malformed input (bad PEM, bad base64) is a
        # caller error (400), not a server fault (500) and not a false valid:false.
        try:
            pub = signing.load_public_key_pem(req.public_key_pem)
            signature = _b64d(req.signature)
        except (ValueError, binascii.Error) as e:
            raise HTTPException(400, f"malformed input: {type(e).__name__}") from e
        try:
            proof.verify_proof(pub, req.proof, signature)
        except signing.InvalidSignature:
            return {"valid": False}
        return {"valid": True}

    return app


app = create_app()
