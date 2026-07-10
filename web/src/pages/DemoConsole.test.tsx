import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { DemoConsole } from './DemoConsole'

// Force the mock client so the console runs without a backend.
beforeEach(() => {
  vi.stubEnv('VITE_USE_MOCK', '1')
})
afterEach(() => {
  vi.unstubAllEnvs()
})

function renderConsole() {
  return render(
    <MemoryRouter>
      <DemoConsole />
    </MemoryRouter>,
  )
}

describe('DemoConsole', () => {
  it('renders all six stage headings', () => {
    renderConsole()
    expect(screen.getByRole('heading', { name: '1. Store a memory' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '4. Crypto-erase' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '6. Prove it' })).toBeInTheDocument()
  })

  it('stores a memory and shows the live vector present', async () => {
    renderConsole()
    // Both the rail nav and the stage action say "Store a memory"; scope to the stage panel.
    const stage = document.getElementById('stage-memory') as HTMLElement
    fireEvent.click(within(stage).getByRole('button', { name: 'Store a memory' }))
    await waitFor(() => {
      expect(screen.getByText(/present \(C-SPANN\)/)).toBeInTheDocument()
    })
  })
})
