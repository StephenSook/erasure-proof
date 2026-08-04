const tiers: { cap: string; status: string; note: string }[] = [
  {
    cap: 'Crypto-erasure by key destruction',
    status: 'Wired live',
    note: 'Real AWS KMS + AES-256-GCM. Irreversible only if no plaintext key was ever persisted (NIST SP 800-88 Rev. 2).',
  },
  {
    cap: 'Atomic destroy-and-retain',
    status: 'Wired live',
    note: 'One SERIALIZABLE CockroachDB transaction, retried on 40001.',
  },
  {
    cap: 'Signed proof in S3 Object Lock',
    status: 'Wired live',
    note: 'ECDSA P-256 signature, anchored in a WORM bucket.',
  },
  {
    cap: 'Append-only decision log',
    status: 'Wired live',
    note: 'UPDATE and DELETE revoked from the agent role. The owner/admin credential is exempt by CockroachDB ownership; we do not claim otherwise.',
  },
  {
    cap: 'Vec2Text inversion (the leak)',
    status: 'Recorded',
    note: 'A genuine golden run on a Modal T4, reproducible. The live proof is the InvalidTag decrypt failure after erasure.',
  },
  {
    cap: 'Node-kill durability',
    status: 'Local cluster',
    note: 'Real Raft on a local 3-node cluster; managed cloud nodes cannot be killed. Recorded and labeled.',
  },
  {
    cap: 'Live AI forensics agent + memory-writer',
    status: 'Live (open model)',
    note: 'A real tool-use loop over the read-only forensic tools, served by an open model (Qwen2.5-3B, llama.cpp on a Modal serverless GPU). Every on-screen verdict labels the provider that answered; Bedrock becomes primary if AWS grants the new-account quota.',
  },
  {
    cap: 'Titan v2 side-by-side embedding',
    status: 'Bedrock quota-gated',
    note: 'The code and IAM are wired, but AWS ships new accounts with a zero Bedrock quota and our increase is pending, so the panel shows its honest unavailable state. Titan has no public inverter today; the panel states that this is an accident of tooling, not a safety guarantee.',
  },
]

export function Trust() {
  return (
    <div className="prose">
      <h1>What is real, and what is recorded</h1>
      <p className="lead">
        Every claim in this demo is one we can defend. Where something is recorded or runs locally, it
        says so here and in the console itself.
      </p>
      <table className="tiers">
        <thead>
          <tr>
            <th>Capability</th>
            <th>Status</th>
            <th>Note</th>
          </tr>
        </thead>
        <tbody>
          {tiers.map((t) => (
            <tr key={t.cap}>
              <td>{t.cap}</td>
              <td>{t.status}</td>
              <td className="muted">{t.note}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2>Validated by the field</h2>
      <p className="muted">
        While validating this project we asked whether the problem is real. Peter Borner, interim
        chair of the Open Proof Standards Foundation (the body publishing the Privacy Claims Token
        specification), answered: &quot;I don&apos;t know of anyone that can currently identify the
        obligations placed on data at the time of collection. I also don&apos;t know of anyone that
        can then prove they erased the data fully and correctly.&quot; Quoted with permission. Our
        lawful-basis-bound decision log answers the first half inside one database; the signed
        erasure proof answers the second. We align with PCT&apos;s audit-first philosophy but do not
        claim PCT conformance (different signature model; the spec is a v0.1 draft).
      </p>
      <p className="muted">
        A second independent expert, Debbie Reynolds, &quot;The Data Diva,&quot; Global Data
        Privacy and Emerging Technologies Expert, named the exact failure mode this project defends
        against: &quot;The bigger concern is not simply whether every copy is physically erased, but
        whether data that should have reached the end of its lifecycle is later exposed in a breach
        or inadvertently becomes active again.&quot; Quoted with permission. Crypto-shredding the
        key (not soft-deleting the row) is what makes a re-exposed ciphertext unreadable, and the
        resurrection guard refuses to re-add an erased subject.
      </p>
      <p className="muted">
        A third expert reached the same conclusion in public: Carey Lening (Privacat Insights)
        published{' '}
        <a
          href="https://insights.priva.cat/p/why-provable-data-erasure-is-really"
          target="_blank"
          rel="noreferrer noopener"
        >
          &quot;Why Provable Data Erasure Is Really Hard, Actually&quot;
        </a>
        , writing that key-based encryption still requires proving you &quot;destroyed every copy of
        the key,&quot; which is the exact NIST forward-secrecy condition this project makes central.
      </p>

      <h2>Conditions we state out loud</h2>
      <ul className="muted">
        <li>Serializable, not strictly serializable (Jepsen confirmed CockroachDB lacks the latter).</li>
        <li>C-SPANN vector indexing was a preview (L2-only) in v25.2; the current stable docs (v26.2) no longer mark it preview and document L2, cosine, and inner-product distance. We use L2 search.</li>
        <li>Append-only holds against the agent and operator roles, not the owner/admin credential.</li>
        <li>Row-Level Security is incompatible with change-data-capture queries on the same table, and changefeeds do not filter by RLS; our changefeed runs on the non-RLS decision log only.</li>
        <li>Crypto-erasure is irreversible only with no persisted plaintext key and no escrowed or backed-up key copies.</li>
        <li>The closest prior art for the encrypted-vector primitive is CyborgDB; the contribution here is the combination (crypto-erased embedding + atomically retained decision log + externally anchored signed proof).</li>
      </ul>
    </div>
  )
}
