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

## Erasure is a qualified right

A practitioner nuance raised by our validator: the right to erasure is not absolute. Article 17
grounds bite mainly where processing rests on consent or legitimate interests; data processed
under other bases (legal obligation, for example) carries different duties. That is exactly why
the decision log records a `lawful_basis` on every action: an erasure decision is only defensible
if the basis it was evaluated against travels with the record. The demo's controlled vocabulary
(`gdpr_art_17`, `ai_act_art_19`) is a minimal instance of that idea, not a full basis taxonomy.

## Relationship to the Privacy Claims Token (PCT)

The [PCT specification](https://pctspec.opsf.org) (v0.1 draft, Open Proof Standards Foundation,
CC BY 4.0) is an open, JWT-model token that travels WITH data and encodes the obligations that
govern it: jurisdiction of origin, permitted purposes, the lawful basis at collection, consent
status, transfer restrictions. Every verification event emits a tamper-evident audit record.

How this project relates, stated precisely:

- Same philosophy, complementary artifacts. PCT operationalizes obligations at runtime, BEFORE an
  action; this project produces signed evidence that the erasure obligation was FULFILLED, after.
  A PCT-governed pipeline needs exactly the completion evidence this system emits.
- The decision log's `lawful_basis`-at-write-time binding is the in-database analogue of PCT's
  lawful-basis-at-collection claim, enforced inside one system rather than carried between systems.
- NOT a conformance claim. Our proof is ECDSA P-256 over canonical JSON, not a JWT (PCT specifies
  RS256/HS256 per RFC 7519), and PCT v1.0 is still being finalized from its first public comment
  window. Expressing the erasure proof as a PCT extension claim is future work, not a shipped
  feature.

Validator context: the erasure-gap quotes are from three independent experts. Two spoke to us with
their permission: Peter Borner in his role as interim chair of OPSF, and Debbie Reynolds ("The Data
Diva"), Global Data Privacy and Emerging Technologies Expert. The third, Carey Lening (Privacat
Insights), reached the same conclusion in a public analysis, "Why Provable Data Erasure Is Really
Hard, Actually" (https://insights.priva.cat/p/why-provable-data-erasure-is-really).

## Honest limitations

- Whether an embedding legally constitutes personal data has no binding ruling we rely on; the
  defensible position is "an embedding may be personal data", and this project treats it as such.
- Legal holds (litigation overriding scheduled erasure) are modeled in the design and described,
  not fully built, in this window.
- This is a demonstration of a technical pattern, not legal advice.
