// The six demo stages, mirroring the video beats 1:1. Each stage owns a hue (color-coded IA).

export type StageId = 'memory' | 'leak' | 'envelope' | 'erase' | 'durability' | 'audit'

export type StageStatus = 'idle' | 'running' | 'done' | 'error'

export interface StageMeta {
  id: StageId
  n: number
  title: string
  eyebrow: string
  hue: string // a CSS custom-property reference from tokens.css
  desc: string
}

export const STAGES: StageMeta[] = [
  {
    id: 'memory',
    n: 1,
    title: 'Store a memory',
    eyebrow: 'Agent memory',
    hue: 'var(--hue-blue)',
    desc: 'An agent stores a memory about a real person. Content and the 768-dim GTR embedding are encrypted with a per-row key; the row is provisioned through the real ingest path.',
  },
  {
    id: 'leak',
    n: 2,
    title: 'The leak',
    eyebrow: 'Why deletion is not enough',
    hue: 'var(--hue-red)',
    desc: 'A deleted row still leaves the embedding reconstructible. Vec2Text inverts the vector back to the original text, recovering the name.',
  },
  {
    id: 'envelope',
    n: 3,
    title: 'The envelope',
    eyebrow: 'How it is protected',
    hue: 'var(--hue-yellow)',
    desc: 'The durable copies are ciphertext only. A per-subject key wraps every per-row key; destroying the subject key makes every row key unrecoverable.',
  },
  {
    id: 'erase',
    n: 4,
    title: 'Crypto-erase',
    eyebrow: 'Destroy and retain, atomically',
    hue: 'var(--hue-corail)',
    desc: 'One SERIALIZABLE transaction destroys the key, purges the live vector, appends the pseudonymized decision log, and records the erasure. Then a signed proof is anchored in S3 Object Lock.',
  },
  {
    id: 'durability',
    n: 5,
    title: 'Survive a node kill',
    eyebrow: 'Durability via Raft',
    hue: 'var(--hue-turquoise)',
    desc: 'The erasure holds across a node failure. This runs on the local 3-node cluster (managed cloud nodes cannot be killed), demonstrating the committed state surviving on a surviving replica.',
  },
  {
    id: 'audit',
    n: 6,
    title: 'Prove it',
    eyebrow: 'Verifiable retention',
    hue: 'var(--hue-green)',
    desc: 'The retained decision log is hash-chained and append-only. The agent role cannot rewrite it, the chain verifies, and the erased personal data is gone under GDPR Article 17 while the log satisfies EU AI Act Article 19.',
  },
]
