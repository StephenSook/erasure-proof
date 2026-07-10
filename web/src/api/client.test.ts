import { afterEach, describe, expect, it, vi } from 'vitest'
import { createHttpClient } from './client'

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('createHttpClient', () => {
  it('posts ingest to /memories with content and embedding', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ subject_id: 's', memory_id: 'm' }))
    vi.stubGlobal('fetch', fetchMock)

    const res = await createHttpClient('').ingest('c-b64', 'e-b64')

    expect(res).toEqual({ subject_id: 's', memory_id: 'm' })
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('/memories')
    expect(init.method).toBe('POST')
    expect(JSON.parse(init.body as string)).toEqual({ content: 'c-b64', embedding: 'e-b64' })
  })

  it('sends subject_id as a query param on GET memory', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ subject_id: 'abc' }))
    vi.stubGlobal('fetch', fetchMock)

    await createHttpClient('http://api').getMemory('a b/c')

    const [url] = fetchMock.mock.calls[0] as [string]
    expect(url).toBe('http://api/api/memory?subject_id=a%20b%2Fc')
  })

  it('maps a 404 to an ApiError carrying the status', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse({ error: 'no memory' }, 404)))
    await expect(createHttpClient('').getMemory('x')).rejects.toMatchObject({ status: 404 })
  })

  it('unwraps the decision-log rows envelope', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse({ rows: [{ seq: 1 }, { seq: 2 }] })))
    const rows = await createHttpClient('').getDecisionLog()
    expect(rows).toHaveLength(2)
  })

  it('turns a network failure into an ApiError with status 0', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')))
    await expect(createHttpClient('').verifyChain()).rejects.toMatchObject({ status: 0 })
  })
})
