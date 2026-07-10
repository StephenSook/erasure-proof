"""ECDSA P-256 signing for erasure proofs.

pyca/cryptography is used (not the pure-Python `ecdsa` package, which warns it "should not be used
in production"). In deployment the private key lives in SSM SecureString, or better, signing is
delegated to a KMS asymmetric key so the private key never exists in the service. This module is
the local/dev signer and the verification path used everywhere.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

__all__ = ["generate_private_key", "sign", "verify", "public_key_pem", "load_public_key_pem",
           "InvalidSignature"]

_CURVE = ec.SECP256R1()  # NIST P-256


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
