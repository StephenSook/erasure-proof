"""ECDSA P-256 signing for erasure proofs.

pyca/cryptography is used (not the pure-Python `ecdsa` package, which warns it "should not be used
in production"). Two signer implementations share the ProofSigner interface:

- LocalSigner: an in-process EC private key (dev file key or ephemeral). The key exists in the
  service's memory.
- KmsSigner: delegates to a KMS asymmetric key (ECC_NIST_P256, SIGN_VERIFY). The private key never
  exists outside KMS; the service holds only kms:Sign permission, so a compromised task cannot
  exfiltrate the signing key, only ask KMS to sign while the compromise lasts (and every Sign call
  is in CloudTrail).

Both produce DER-encoded ECDSA-with-SHA-256 signatures over the same bytes, so the verification
path (here, the Lambda verifier, and the browser's WebCrypto) is identical regardless of signer.
"""

from __future__ import annotations

from typing import Protocol

import boto3
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

__all__ = ["generate_private_key", "sign", "verify", "public_key_pem", "load_public_key_pem",
           "InvalidSignature", "ProofSigner", "LocalSigner", "KmsSigner"]

_CURVE = ec.SECP256R1()  # NIST P-256

# KMS Sign with MessageType=RAW rejects messages over 4096 bytes (the service hashes internally).
# Canonical proofs are ~1 KB, so this is headroom, not a constraint we design around; the guard
# exists so a future oversized proof fails loudly here instead of opaquely inside AWS.
_KMS_RAW_MESSAGE_LIMIT = 4096


def generate_private_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(_CURVE)


def sign(private_key: ec.EllipticCurvePrivateKey, payload: bytes) -> bytes:
    """Return a DER-encoded ECDSA signature over SHA-256(payload)."""
    return private_key.sign(payload, ec.ECDSA(hashes.SHA256()))


def verify(public_key: ec.EllipticCurvePublicKey, signature: bytes, payload: bytes) -> None:
    """Raise cryptography.exceptions.InvalidSignature if the signature does not verify."""
    public_key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))


def public_key_pem(public_key: ec.EllipticCurvePublicKey) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def load_public_key_pem(pem: str) -> ec.EllipticCurvePublicKey:
    key = serialization.load_pem_public_key(pem.encode())
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("not an EC public key")
    return key


class ProofSigner(Protocol):
    """What the proof path needs from a signer: DER ECDSA-SHA-256 bytes and the public key PEM
    embedded in every proof so verifiers need no out-of-band key distribution."""

    @property
    def public_key_pem(self) -> str: ...

    def sign(self, payload: bytes) -> bytes: ...


class LocalSigner:
    """An in-process EC private key (dev file key or ephemeral)."""

    def __init__(self, private_key: ec.EllipticCurvePrivateKey) -> None:
        self._key = private_key
        self.public_key_pem = public_key_pem(private_key.public_key())

    def sign(self, payload: bytes) -> bytes:
        return sign(self._key, payload)


class KmsSigner:
    """Signs via a KMS asymmetric key (ECC_NIST_P256, SIGN_VERIFY, ECDSA_SHA_256).

    MessageType=RAW is used deliberately: KMS hashes the message with SHA-256 itself, which is
    byte-identical to LocalSigner's ec.ECDSA(SHA256()) signatures, AND it is the mode moto
    implements faithfully (moto's DIGEST mode re-hashes the digest, producing signatures nothing
    can verify; empirically confirmed against moto 5.2.2). RAW caps the message at 4096 bytes,
    far above any canonical proof.

    The public key is fetched once at construction (kms:GetPublicKey) and pinned for the process
    lifetime; a wrong-key or no-permission misconfiguration therefore fails at boot, not on the
    first erasure.
    """

    def __init__(self, key_arn: str, region: str) -> None:
        self._kms = boto3.client("kms", region_name=region)
        self._key_arn = key_arn
        meta = self._kms.get_public_key(KeyId=key_arn)
        if "ECDSA_SHA_256" not in meta.get("SigningAlgorithms", []):
            raise ValueError(
                f"KMS key {key_arn} does not support ECDSA_SHA_256; "
                "the signing key must be ECC_NIST_P256 with KeyUsage=SIGN_VERIFY"
            )
        der_public = serialization.load_der_public_key(meta["PublicKey"])
        if not isinstance(der_public, ec.EllipticCurvePublicKey):
            raise ValueError(f"KMS key {key_arn} is not an EC key")
        self.public_key_pem = public_key_pem(der_public)

    def sign(self, payload: bytes) -> bytes:
        if len(payload) > _KMS_RAW_MESSAGE_LIMIT:
            raise ValueError(
                f"payload is {len(payload)} bytes; KMS RAW signing caps at "
                f"{_KMS_RAW_MESSAGE_LIMIT}"
            )
        result = self._kms.sign(
            KeyId=self._key_arn,
            Message=payload,
            MessageType="RAW",
            SigningAlgorithm="ECDSA_SHA_256",
        )
        return result["Signature"]
