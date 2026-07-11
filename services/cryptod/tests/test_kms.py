"""KMS envelope path (moto) and the RSA-OAEP import wrap (pure crypto).

The imported-material lifecycle (get_parameters_for_import / import_key_material /
delete_imported_key_material) is NOT implemented by moto, and real KMS does not enforce the
encryption-context mismatch under moto, so those behaviors are proven by the real-AWS smoke, not
here. What moto covers, the envelope generate/decrypt round trip, is tested here; the wrap logic is
tested against a locally generated RSA key so it needs no KMS at all.
"""

from __future__ import annotations

import boto3
import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from moto import mock_aws

from cryptod import aead
from cryptod.kms import KMS


@mock_aws
def test_generate_data_key_and_decrypt_round_trip():
    key_id = boto3.client("kms", region_name="us-east-1").create_key()["KeyMetadata"]["KeyId"]
    k = KMS("us-east-1")
    dk = k.generate_data_key(key_id, "subject-1")
    assert len(dk.plaintext) == 32
    assert dk.wrapped
    assert k.decrypt_data_key(dk.wrapped, "subject-1") == dk.plaintext


@mock_aws
def test_envelope_encrypts_and_erasure_makes_it_unrecoverable():
    # End to end with the AES layer: encrypt an embedding under the KMS data key, then model
    # erasure as loss of the wrapped key. Without the wrapped key there is no way back to the
    # plaintext data key, so the ciphertext is unrecoverable.
    key_id = boto3.client("kms", region_name="us-east-1").create_key()["KeyMetadata"]["KeyId"]
    k = KMS("us-east-1")
    dk = k.generate_data_key(key_id, "subject-1")
    embedding = b"\x42" * 3072
    ct = aead.encrypt(dk.plaintext, embedding, aad=b"subject-1")

    # Legitimate read: unwrap the data key, decrypt.
    recovered_key = k.decrypt_data_key(dk.wrapped, "subject-1")
    assert aead.decrypt(recovered_key, ct, aad=b"subject-1") == embedding

    # Erasure: the wrapped key is gone (deleted from the DB), so the exact data key can no longer be
    # reproduced. Prove the ciphertext is then unrecoverable by showing no other key opens it: any
    # freshly generated data key fails with InvalidTag, so only the now-destroyed key ever could.
    del dk, recovered_key
    other_key = k.generate_data_key(key_id, "subject-1").plaintext
    with pytest.raises(InvalidTag):
        aead.decrypt(other_key, ct, aad=b"subject-1")


def test_provision_imported_key_rejects_wrong_material_size():
    k = KMS("us-east-1")
    with pytest.raises(ValueError):
        k.provision_imported_key("demo", b"too-short")


def test_wrap_material_is_rsa_oaep_sha256():
    # KMS wraps imported material with RSAES_OAEP_SHA_256 under the public key it returns. Prove our
    # wrap matches by decrypting with the corresponding private key.
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_der = priv.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    material = b"\x11" * 32
    wrapped = KMS._wrap_material(pub_der, material)
    recovered = priv.decrypt(
        wrapped,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    assert recovered == material
