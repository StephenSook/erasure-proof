// getClient picks the real HTTP client or the mock, so the console runs against a live backend or
// standalone. Set VITE_USE_MOCK=1 for the mock; VITE_API_BASE overrides the api origin (default:
// relative, same-origin).

import { createHttpClient } from './client'
import { createMockClient } from './mock'
import { type DemoApi } from './types'

// The mock is a module singleton so separate pages (the demo console, the proof verifier) share
// one stateful instance, like they share one real backend. Tests construct their own isolated
// instances via createMockClient directly.
let mockSingleton: DemoApi | null = null

export function getClient(): DemoApi {
  if (import.meta.env.VITE_USE_MOCK === '1') {
    mockSingleton ??= createMockClient()
    return mockSingleton
  }
  return createHttpClient(import.meta.env.VITE_API_BASE ?? '')
}

export * from './types'
export { createHttpClient } from './client'
export { createMockClient } from './mock'
