# Compliance mapping

This project sits on a real regulatory fault line: the obligation to erase personal data and the
obligation to retain decision logs point in opposite directions, and no single system reconciles
them cleanly today.

## The two obligations

- GDPR Article 17 (right to erasure): a data subject can compel erasure of their personal data.
  For agent memory, deleting the row is insufficient because the embedding is reconstructible
  (Vec2Text, arXiv:2310.06816). Genuine erasure requires the personal embedding to become
  unrecoverable.
- EU AI Act Article 19(1), Regulation (EU) 2024/1689: providers of high-risk AI systems must keep
  automatically generated logs for a period appropriate to the purpose, at least six months.
  Enforceable from August 2, 2026 (sixteen days before this hackathon's deadline). Article 19(2)
  defers to sector law where it is stricter.
- MiFID II: for financial entities, the record-retention floor is five to seven years, which is
  longer than the AI Act minimum and is the sharper example to lead with.

## How this project reconciles them

In one serializable transaction:

- The personal embedding is crypto-shredded (the key is destroyed), satisfying Article 17: the
  personal data is genuinely unrecoverable, not merely hidden.
- The decision log row is retained, pseudonymized (subject_hash = SHA-256(subject_id), no raw PII),
  hash-chained, and anchored in write-once storage, satisfying Article 19(1) / MiFID II: the
  decision record survives and is tamper-evident.

The pseudonymized log contains the fact and lawful basis of the decision, not the personal data
itself, so retaining it does not conflict with the erasure. This is the destroy-the-personal-data,
keep-the-decision-record pattern, done atomically so the two never diverge.

## Honest limitations

- Whether an embedding legally constitutes personal data has no binding ruling we rely on; the
  defensible position is "an embedding may be personal data", and this project treats it as such.
- Legal holds (litigation overriding scheduled erasure) are modeled in the design and described,
  not fully built, in this window.
- This is a demonstration of a technical pattern, not legal advice.
