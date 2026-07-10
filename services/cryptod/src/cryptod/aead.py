"""AES-256-GCM authenticated encryption.

The erasure guarantee rests on this module: content and the GTR embedding are encrypted under a
per-subject key with the subject id bound as associated data. When the key is destroyed, the
ciphertext is unrecoverable and decryption raises InvalidTag. pyca/cryptography raises InvalidTag
"when the ciphertext has been changed, but ... also ... when the key, nonce, or associated data
are wrong" (cryptography.io AEAD docs), which is exactly the property the property test asserts.

Rules (never relaxed):
  * 256-bit keys.
  * A fresh 96-bit nonce per encryption. NIST SP 800-38D recommends a 96-bit IV; never reuse a
    (key, nonce) pair.
  * subject_id (and, later, the decision-log chain head) is bound as associated_data so a
    ciphertext cannot be replayed under another subject or against a rewritten log.
  * Keys and plaintext are never logged.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_BYTES = 32   # AES-256
NONCE_BYTES = 12  # 96-bit, per NIST SP 800-38D


def generate_key() -> bytes:
    """Return a fresh 256-bit AES key."""
    return AESGCM.generate_key(bit_length=256)


@dataclass(frozen=True)
class Ciphertext:
    """A nonce and its ciphertext. The nonce is public; the key is not stored here."""

    nonce: bytes
    ct: bytes


def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> Ciphertext:
    """Encrypt plaintext under key with a fresh nonce, binding aad (e.g. subject_id)."""
    if len(key) != KEY_BYTES:
        raise ValueError("key must be 32 bytes (AES-256)")
    nonce = os.urandom(NONCE_BYTES)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return Ciphertext(nonce=nonce, ct=ct)


def decrypt(key: bytes, ciphertext: Ciphertext, aad: bytes) -> bytes:
    """Decrypt, raising cryptography.exceptions.InvalidTag on the wrong key, nonce, aad, or tamper.

    After the key is destroyed there is no value of `key` that succeeds, so the plaintext (and the
    embedding it encodes) is unrecoverable. That is the crypto-erasure guarantee.
    """
    if len(key) != KEY_BYTES:
        raise ValueError("key must be 32 bytes (AES-256)")
    return AESGCM(key).decrypt(ciphertext.nonce, ciphertext.ct, aad)
