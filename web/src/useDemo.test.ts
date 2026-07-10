import { act, renderHook, waitFor } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { createMockClient } from './api'
import { useDemo } from './useDemo'

describe('useDemo', () => {
  it('runs the full loop to done via autopilot', async () => {
    const { result } = renderHook(() => useDemo(createMockClient()))

    await act(async () => {
      await result.current.actions.runAll()
    })

    await waitFor(() => {
      expect(result.current.state.status.audit).toBe('done')
    })
    expect(result.current.state.status.memory).toBe('done')
    expect(result.current.state.memoryAfter?.embedding_present).toBe(false)
    expect(result.current.state.chain?.intact).toBe(true)
    expect(result.current.state.rbac?.denied).toBe(true)
  })

  it('errors a later stage that runs before stage 1', async () => {
    const { result } = renderHook(() => useDemo(createMockClient()))

    await act(async () => {
      await result.current.actions.runErase().catch(() => undefined)
    })

    expect(result.current.state.status.erase).toBe('error')
    expect(result.current.state.error.erase).toMatch(/stage 1/)
  })

  it('reset clears the state back to idle', async () => {
    const { result } = renderHook(() => useDemo(createMockClient()))
    await act(async () => {
      await result.current.actions.runMemory()
    })
    expect(result.current.state.status.memory).toBe('done')

    act(() => {
      result.current.actions.reset()
    })
    expect(result.current.state.status.memory).toBe('idle')
    expect(result.current.state.subjectId).toBe('')
  })
})
