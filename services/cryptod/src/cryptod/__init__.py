"""cryptod: all key handling, signing, and proof logic for erasure-proof.

Python is mandatory here because Vec2Text ships only as PyTorch models; the same service
therefore owns AES-256-GCM (pyca/cryptography), the envelope key hierarchy, KMS, ECDSA proof
signing, S3 Object Lock anchoring, and the read-only forensics tools.
"""

__all__ = ["aead", "envelope", "signing", "proof"]
