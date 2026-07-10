# Agent Skills

Machine-executable Agent Skills authored by this project, following the
[Agent Skills Specification](https://agentskills.io/specification) and the conventions of the
upstream [cockroachlabs/cockroachdb-skills](https://github.com/cockroachlabs/cockroachdb-skills)
repository.

- [`verifying-cryptographic-erasure`](verifying-cryptographic-erasure/SKILL.md): builds and verifies
  the destroy-and-retain crypto-erasure pattern on CockroachDB (per-subject key destruction inside
  one SERIALIZABLE transaction that also retains a hash-chained decision log). Validated against the
  upstream `scripts/validate-spec.py` (zero errors; the two remaining warnings are naive-substring
  false positives the upstream exemplars also trigger, the gerund check and the "AI Act" -> "i "
  match).

## Upstream contribution

The intended home is the upstream repo's `cockroachdb-security-and-governance` domain. The upstream
process is proposal-first (open a new-skill issue before the PR), so opening that PR is a separate,
outward-facing step done deliberately, not automatically.
