import { Link } from 'react-router-dom'

export function Landing() {
  return (
    <div className="prose">
      <h1>Prove a person&apos;s data is truly gone from an agent&apos;s memory.</h1>
      <p className="lead">
        When a regulator asks whether someone&apos;s data is erased from an AI agent, most teams can
        only prove they deleted a row. But a deleted embedding is still reconstructible: Vec2Text
        recovers the original text from the vector.
      </p>
      <p>
        This system cryptographically destroys the embedding so it cannot be reconstructed, retains the
        legally required decision log in the same serializable transaction, emits an externally
        anchored signed proof, and holds the erasure across a node failure. Built on CockroachDB and
        AWS.
      </p>
      <Link className="cta" to="/demo">
        Open the demo console -&gt;
      </Link>
    </div>
  )
}
