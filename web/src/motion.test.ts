import { beforeEach, describe, expect, it } from 'vitest'
import { motionEnabled, resetMotionLatchForTest } from './motion'

function fakeWindow(opts: { reduce?: boolean; search?: string }) {
  return {
    matchMedia: (q: string) => ({ matches: q.includes('reduce') ? (opts.reduce ?? false) : false }),
    location: { search: opts.search ?? '' },
  } as unknown as Parameters<typeof motionEnabled>[0]
}

describe('motionEnabled', () => {
  beforeEach(() => resetMotionLatchForTest())

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

  it('latches ?minimal=1 in memory so it survives navigation', () => {
    expect(motionEnabled(fakeWindow({ search: '?minimal=1' }))).toBe(false)
    // Later navigation drops the query string; the in-memory latch keeps motion off.
    expect(motionEnabled(fakeWindow({ search: '' }))).toBe(false)
  })

  it('is true otherwise', () => {
    expect(motionEnabled(fakeWindow({}))).toBe(true)
  })
})
