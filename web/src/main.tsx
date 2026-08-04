import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { App } from './App'
import '@fontsource/jetbrains-mono/latin-400.css'
import '@fontsource/jetbrains-mono/latin-700.css'
import '@fontsource/dseg7-classic/latin-400.css'
import '@fontsource/dseg14-classic/latin-400.css'
import './styles/fonts.css'
import './styles/tokens.css'
import './styles/app.css'

// PWA install surface: the service worker is a pure network passthrough (no caching, so the
// trust surfaces never serve stale evidence); production only, so dev reloads stay clean.
if ('serviceWorker' in navigator && import.meta.env.PROD) {
  window.addEventListener('load', () => {
    void navigator.serviceWorker.register('/sw.js').catch(() => undefined)
  })
}

const root = document.getElementById('root')
if (!root) {
  throw new Error('root element not found')
}
createRoot(root).render(
  <StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </StrictMode>,
)
