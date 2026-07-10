// The required "which CockroachDB tools and AWS services, and how" surface, wired-or-cut honest:
// everything named here is invoked by shipped code today. This page is updated at submission time
// if the tool set changes; it never claims ahead of the code.

interface Box {
  title: string
  detail: string
  hue: string
}

const FLOW: Box[] = [
  {
    title: 'Demo console (this site)',
    detail: 'React SPA; the proof verifier runs client-side WebCrypto',
    hue: 'var(--hue-cyan)',
  },
  {
    title: 'Go api',
    detail: 'ingest, SERIALIZABLE erasure txn (crdbpgx retry), demo gateway',
    hue: 'var(--hue-blue)',
  },
  {
    title: 'CockroachDB',
    detail: 'ONE system of record: relational + vector (C-SPANN) + hash-chained audit log',
    hue: 'var(--hue-turquoise)',
  },
  {
    title: 'cryptod (Python)',
    detail: 'AES-256-GCM envelopes, ECDSA proofs, Vec2Text golden run',
    hue: 'var(--hue-yellow)',
  },
  {
    title: 'AWS KMS + S3 Object Lock + Bedrock',
    detail: 'key destruction is the erasure; WORM proof anchor; agent inference',
    hue: 'var(--hue-corail)',
  },
]

export function Architecture() {
  return (
    <div className="prose">
      <h1>Architecture</h1>
      <p className="lead">
        One database holds the relational state, the vector memory, and the audit log, which is what
        lets an erasure destroy a key, purge an embedding, and retain the legally required log entry
        in a single serializable transaction.
      </p>

      <div className="arch">
        {FLOW.map((b) => (
          <div className="arch__box" key={b.title} style={{ ['--hue' as string]: b.hue }}>
            <div className="arch__title">{b.title}</div>
            <div className="arch__detail">{b.detail}</div>
          </div>
        ))}
      </div>

      <h2>CockroachDB tools in use</h2>
      <ul className="muted">
        <li>
          Distributed Vector Indexing (C-SPANN, preview): the live GTR embedding is indexed with a
          subject_id prefix, so per-subject similarity search is index-accelerated and the erasure
          purge (setting the vector NULL) is a plain UPDATE the index survives. Euclidean at preview.
        </li>
        <li>
          ccloud CLI: provisions and operates the CockroachDB Cloud cluster that serves as the
          system of record (cluster create, connection info, CA cert flows).
        </li>
        <li>
          The database itself: SERIALIZABLE transactions with the official crdbpgx retry wrapper,
          least-privilege SQL roles, row-level security scoping the agent to one declared subject,
          and an append-only hash-chained decision log.
        </li>
      </ul>
      <p className="muted">
        The Managed MCP Server and the Agent Skills repo are being evaluated; they are not claimed
        here until they are load-bearing in shipped code.
      </p>

      <h2>AWS services in use (all load-bearing)</h2>
      <ul className="muted">
        <li>
          KMS: the erasure mechanism itself. Per-subject envelope keys via GenerateDataKey with the
          subject bound as encryption context; destroying the wrapped key row is the crypto-shred,
          and imported-material subjects get a second kill switch (DeleteImportedKeyMaterial).
        </li>
        <li>
          S3 Object Lock: every erasure proof is ECDSA-signed and anchored to a WORM bucket
          (GOVERNANCE in development, COMPLIANCE for the judged proofs), so the record of an erasure
          cannot be quietly rewritten, even by us.
        </li>
        <li>Bedrock (Claude): the memory-writer and forensics agents run real inference.</li>
      </ul>

      <h2>Why one database and not a bolted-on vector store</h2>
      <p>
        Destroy-and-retain must be atomic. With memory split across a database and a separate vector
        store, the erasure and the retained decision log cannot commit together, and a crash between
        the two leaves either a live embedding for an erased person or a log entry for an erasure
        that did not happen. Here both commit in one serializable transaction, and the erasure
        survives node failure via Raft.
      </p>
    </div>
  )
}
