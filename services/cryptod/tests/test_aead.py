"""The crypto-erasure invariant, as a property test.

For random plaintexts and subjects: a correct roundtrip returns the plaintext, and after the key
is destroyed (any key other than the exact one) decryption raises InvalidTag rather than returning
recoverable data. AES-GCM authenticates, so a wrong key never yields silent garbage that an
inverter could work on: the embedding is genuinely unrecoverable.
"""

from __future__ import annotations

import numpy as np
import pytest
from cryptography.exceptions import InvalidTag
from hypothesis import given
from hypothesis import strategies as st

from cryptod import aead

subject_ids = st.binary(min_size=16, max_size=16)
plaintexts = st.binary(min_size=0, max_size=4096)


@given(plaintext=plaintexts, subject_id=subject_ids)
def test_roundtrip(plaintext: bytes, subject_id: bytes) -> None:
    key = aead.generate_key()
    ct = aead.encrypt(key, plaintext, aad=subject_id)
    assert aead.decrypt(key, ct, aad=subject_id) == plaintext


@given(plaintext=plaintexts, subject_id=subject_ids)
def test_key_destruction_makes_decrypt_raise(plaintext: bytes, subject_id: bytes) -> None:
    key = aead.generate_key()
    ct = aead.encrypt(key, plaintext, aad=subject_id)

    # Destroy the key: the caller no longer holds it, only a fresh (wrong) key exists.
    destroyed = aead.generate_key()
    assert destroyed != key
    with pytest.raises(InvalidTag):
        aead.decrypt(destroyed, ct, aad=subject_id)


@given(plaintext=plaintexts, subject_id=subject_ids, other_id=subject_ids)
def test_wrong_subject_aad_raises(plaintext: bytes, subject_id: bytes, other_id: bytes) -> None:
    if subject_id == other_id:
        return
    key = aead.generate_key()
    ct = aead.encrypt(key, plaintext, aad=subject_id)
    # A ciphertext cannot be replayed under another subject: wrong AAD fails.
    with pytest.raises(InvalidTag):
        aead.decrypt(key, ct, aad=other_id)


@given(subject_id=subject_ids)
def test_tampered_ciphertext_raises(subject_id: bytes) -> None:
    key = aead.generate_key()
    ct = aead.encrypt(key, b"the person's name", aad=subject_id)
    flipped = bytes([ct.ct[0] ^ 0x01]) + ct.ct[1:]
    with pytest.raises(InvalidTag):
        aead.decrypt(key, aead.Ciphertext(nonce=ct.nonce, ct=flipped), aad=subject_id)


def test_embedding_unrecoverable_after_key_destruction() -> None:
    # A 768-dim float32 GTR embedding, the real payload shape.
    embedding = np.random.randn(768).astype("float32").tobytes()
    subject_id = b"\x11" * 16
    key = aead.generate_key()
    ct = aead.encrypt(key, embedding, aad=subject_id)

    del key  # crypto-shred
    # No available key decrypts; the embedding bytes are unrecoverable.
    for _ in range(8):
        with pytest.raises(InvalidTag):
            aead.decrypt(aead.generate_key(), ct, aad=subject_id)


def test_fresh_nonce_per_encryption() -> None:
    key = aead.generate_key()
    nonces = {aead.encrypt(key, b"x", aad=b"s").nonce for _ in range(200)}
    assert len(nonces) == 200  # no nonce reuse
