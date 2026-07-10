import hashlib

from forensics_mcp.chain import GENESIS_PREV_HASH, link


def test_link_deterministic_and_length():
    sh = hashlib.sha256(b"s").digest()
    a = link(GENESIS_PREV_HASH, 1, "erasure", "gdpr_art_17", sh)
    b = link(GENESIS_PREV_HASH, 1, "erasure", "gdpr_art_17", sh)
    assert a == b
    assert len(a) == 32


def test_link_matches_go_canonical_form():
    # Must equal SHA-256(prev || "seq|action|basis" || subject_hash), the Go writer's form.
    sh = hashlib.sha256(b"s").digest()
    expected = hashlib.sha256(GENESIS_PREV_HASH + b"1|erasure|gdpr_art_17" + sh).digest()
    assert link(GENESIS_PREV_HASH, 1, "erasure", "gdpr_art_17", sh) == expected


def test_link_changes_with_every_field():
    sh = hashlib.sha256(b"s").digest()
    base = link(GENESIS_PREV_HASH, 1, "erasure", "gdpr_art_17", sh)
    assert link(GENESIS_PREV_HASH, 2, "erasure", "gdpr_art_17", sh) != base
    assert link(GENESIS_PREV_HASH, 1, "ingest", "gdpr_art_17", sh) != base
    assert link(GENESIS_PREV_HASH, 1, "erasure", "ai_act_art_19", sh) != base
    assert link(base, 1, "erasure", "gdpr_art_17", sh) != base
