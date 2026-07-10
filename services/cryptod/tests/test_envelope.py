"""Envelope hierarchy: destroying the subject key erases every per-row data key."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from cryptod import aead, envelope


def test_wrap_unwrap_roundtrip() -> None:
    subject_key = envelope.new_subject_key()
    data_key = envelope.new_data_key()
    material = envelope.wrap_data_key(subject_key, data_key)
    assert envelope.unwrap_data_key(subject_key, material) == data_key


def test_subject_key_destruction_erases_data_key() -> None:
    subject_key = envelope.new_subject_key()
    data_key = envelope.new_data_key()
    material = envelope.wrap_data_key(subject_key, data_key)

    # Destroying the subject key (deleting its subject_keys row) makes the data key unrecoverable.
    del subject_key
    with pytest.raises(envelope.InvalidUnwrap):
        envelope.unwrap_data_key(envelope.new_subject_key(), material)


@given(
    plaintext=st.binary(min_size=0, max_size=512),
    subject_id=st.binary(min_size=16, max_size=16),
)
def test_full_two_level_erasure(plaintext: bytes, subject_id: bytes) -> None:
    # Encrypt content under a per-row data key wrapped by the subject key.
    subject_key = envelope.new_subject_key()
    data_key = envelope.new_data_key()
    material = envelope.wrap_data_key(subject_key, data_key)
    ct = aead.encrypt(data_key, plaintext, aad=subject_id)

    # A legitimate reader unwraps then decrypts.
    recovered_key = envelope.unwrap_data_key(subject_key, material)
    assert aead.decrypt(recovered_key, ct, aad=subject_id) == plaintext

    # Erasure destroys only the subject key. The data key and thus the plaintext are gone.
    del subject_key, data_key, recovered_key
    with pytest.raises(envelope.InvalidUnwrap):
        envelope.unwrap_data_key(envelope.new_subject_key(), material)
