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

      <h2>Conditions we state out loud</h2>
      <ul className="muted">
        <li>Serializable, not strictly serializable (Jepsen confirmed CockroachDB lacks the latter).</li>
        <li>C-SPANN vector indexing is in preview and Euclidean-only at preview.</li>
        <li>Append-only holds against the agent and operator roles, not the owner/admin credential.</li>
        <li>Crypto-erasure is irreversible only with no persisted plaintext key and no escrowed or backed-up key copies.</li>
        <li>The closest prior art for the encrypted-vector primitive is CyborgDB; the contribution here is the combination (crypto-erased embedding + atomically retained decision log + externally anchored signed proof).</li>
      </ul>
    </div>
  )
}
