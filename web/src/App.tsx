import { NavLink, Route, Routes } from 'react-router-dom'
import { Architecture } from './pages/Architecture'
import { DemoConsole } from './pages/DemoConsole'
import { Landing } from './pages/Landing'
import { ProofVerifier } from './pages/ProofVerifier'
import { Trust } from './pages/Trust'

const navClass = ({ isActive }: { isActive: boolean }) => (isActive ? 'active' : undefined)

export function App() {
  return (
    <div className="app">
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
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/demo" element={<DemoConsole />} />
        <Route path="/proof" element={<ProofVerifier />} />
        <Route path="/proof/:subjectId" element={<ProofVerifier />} />
        <Route path="/architecture" element={<Architecture />} />
        <Route path="/trust" element={<Trust />} />
        <Route path="*" element={<Landing />} />
      </Routes>
    </div>
  )
}
