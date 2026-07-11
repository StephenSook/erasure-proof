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
          Distributed Vector Indexing (C-SPANN): the live GTR embedding is indexed with a
          subject_id prefix, so per-subject similarity search is index-accelerated and the erasure
          purge (setting the vector NULL) is a plain UPDATE the index survives. We use L2 (Euclidean)
          distance; C-SPANN was a preview in v25.2 and is no longer marked preview in the current
          stable docs (v26.2), which document L2, cosine, and inner-product.
        </li>
        <li>
          Managed MCP Server: the independent verification path. A least-privilege service
          account reads the decision-log chain head through cockroachlabs.cloud/mcp
          (select_query), so a verifier does not have to trust our API layer, and every call is
          audit-logged by CockroachDB Cloud. The Cloud RBAC check runs per tool call: the
          under-privileged role is refused, the cluster-scoped operator role is permitted
          (infra/ccloud/mcp-verify.sh).
        </li>
        <li>
          ccloud CLI with service-account RBAC: provisions and operates the cloud cluster, and
          demonstrates the three distinct denial boundaries with one script
          (infra/ccloud/rbac-demo.sh): a control-plane HTTP 403 (same key: 200 on its scoped
          cluster, 403 on billing), the MCP-layer Cloud RBAC refusal, and the data-plane
          SQLSTATE 42501 when the agent role attempts to tamper with the append-only log.
        </li>
        <li>
          Agent Skills: a verifying-cryptographic-erasure skill authored in this repo following
          the upstream cockroachlabs/cockroachdb-skills conventions and validated with their own
          validate-spec.py (zero errors); the upstream contribution PR is in flight.
        </li>
        <li>
          The database itself: SERIALIZABLE transactions with the official crdbpgx retry wrapper,
          least-privilege SQL roles, row-level security scoping the agent to one declared subject,
          and an append-only hash-chained decision log.
        </li>
      </ul>

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
