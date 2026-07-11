import { useState } from 'react'

// Copy a runnable curl for the exact endpoint a beat calls, so a judge can replay it against the
// deployed API and get the same result (Saraf's DevEx lens: prove the API is real, not faked).
// The command targets the current origin, so on the deployed URL it runs as-is; in mock/dev it is
// still the right shape. Only put this on genuinely API-backed, safe-to-replay beats.

export function CopyCurl({
  method,
  path,
  body,
  label = 'Copy as curl',
}: {
  method: 'GET' | 'POST'
  path: string
  body?: unknown
  label?: string
}) {
  const [copied, setCopied] = useState(false)

  const build = (): string => {
    const origin = typeof window !== 'undefined' ? window.location.origin : 'https://<deployed-url>'
    const parts = [`curl -sS -X ${method} ${origin}${path}`]
    if (body !== undefined) {
      parts.push(`-H 'Content-Type: application/json'`)
      parts.push(`-d '${JSON.stringify(body)}'`)
    }
    return parts.join(' ')
  }

  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(build())
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1600)
    } catch {
      setCopied(false) // clipboard blocked (rare); the button simply does nothing visible
    }
  }

  return (
    <button className="btn btn--small btn--ghost copycurl" onClick={onCopy} title={build()}>
      {copied ? 'curl copied' : label}
    </button>
  )
}
