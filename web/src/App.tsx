import { lazy, Suspense } from 'react'
import { NavLink, Route, Routes } from 'react-router-dom'
import { ScrollProgress } from './components/ScrollProgress'
import { Landing } from './pages/Landing'

// The landing page stays eager (it is the entry; a spinner there would be worse than the bytes).
// Every other page is its own chunk, so the first paint ships without the demo console, the
// WebCrypto verifier, or the architecture SVG. Each page keeps a named export for tests; the
// .then() maps it to the default shape lazy() expects.
const DemoConsole = lazy(() =>
  import('./pages/DemoConsole').then((m) => ({ default: m.DemoConsole })),
)
const ProofVerifier = lazy(() =>
  import('./pages/ProofVerifier').then((m) => ({ default: m.ProofVerifier })),
)
const Architecture = lazy(() =>
  import('./pages/Architecture').then((m) => ({ default: m.Architecture })),
)
const Trust = lazy(() => import('./pages/Trust').then((m) => ({ default: m.Trust })))

const navClass = ({ isActive }: { isActive: boolean }) => (isActive ? 'active' : undefined)

export function App() {
  return (
    <div className="app">
      <ScrollProgress />
      <header className="header">
        <div className="header__brand">
          <NavLink to="/" className="header__mark">
            erasure<b>-proof</b>
          </NavLink>
          <span className="header__tag">crypto-erasure for agent memory</span>
        </div>
        <nav className="header__nav">
          <NavLink to="/demo" className={navClass}>
            Demo
          </NavLink>
          <NavLink to="/proof" className={navClass}>
            Verify
          </NavLink>
          <NavLink to="/architecture" className={navClass}>
            Architecture
          </NavLink>
          <NavLink to="/trust" className={navClass}>
            Trust
          </NavLink>
        </nav>
      </header>
      {/* The fallback is intentionally quiet: chunks arrive from CloudFront in tens of ms, and a
          flashing spinner would be more visible than the wait. */}
      <Suspense fallback={<div className="page-loading" aria-busy="true" />}>
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/demo" element={<DemoConsole />} />
          <Route path="/proof" element={<ProofVerifier />} />
          <Route path="/proof/:subjectId" element={<ProofVerifier />} />
          <Route path="/architecture" element={<Architecture />} />
          <Route path="/trust" element={<Trust />} />
          <Route path="*" element={<Landing />} />
        </Routes>
      </Suspense>
    </div>
  )
}
