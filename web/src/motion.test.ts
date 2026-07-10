import { describe, expect, it } from 'vitest'
import { motionEnabled } from './motion'

function fakeStorage(): Storage {
  const store = new Map<string, string>()
  return {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => void store.set(k, v),
    removeItem: (k: string) => void store.delete(k),
    clear: () => store.clear(),
    key: () => null,
    get length() {
      return store.size
    },
  } as Storage
}

function fakeWindow(opts: { reduce?: boolean; search?: string; storage?: Storage }) {
  return {
    matchMedia: (q: string) => ({ matches: q.includes('reduce') ? (opts.reduce ?? false) : false }),
    location: { search: opts.search ?? '' },
    sessionStorage: opts.storage,
  } as unknown as Parameters<typeof motionEnabled>[0]
}

describe('motionEnabled', () => {
  it('is false with no window or no matchMedia (test runners, old browsers)', () => {
    expect(motionEnabled(undefined)).toBe(false)
    expect(
      motionEnabled({ location: { search: '' } } as unknown as Parameters<typeof motionEnabled>[0]),
    ).toBe(false)
  })

  it('is false when the user prefers reduced motion', () => {
    expect(motionEnabled(fakeWindow({ reduce: true }))).toBe(false)
  })

  it('is false with ?minimal=1', () => {
    expect(motionEnabled(fakeWindow({ search: '?minimal=1' }))).toBe(false)
  })

  it('latches ?minimal=1 into sessionStorage so it survives navigation', () => {
    const storage = fakeStorage()
    expect(motionEnabled(fakeWindow({ search: '?minimal=1', storage }))).toBe(false)
    // Later navigation drops the query string; the latch keeps motion off.
    expect(motionEnabled(fakeWindow({ search: '', storage }))).toBe(false)
  })

  it('is true otherwise', () => {
    expect(motionEnabled(fakeWindow({}))).toBe(true)
  })
})
