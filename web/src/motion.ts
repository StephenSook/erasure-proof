// The single gate every animation goes through. Motion is presentation only: nothing in the demo
// state machine depends on it, so disabling it (reduced-motion users, ?minimal=1, test runners
// without matchMedia) collapses the UI to instant final states with zero behaviour change.

type MotionWindow = Pick<Window, 'matchMedia' | 'location'>

// ?minimal=1 is latched in an in-memory module variable so it survives internal SPA navigation
// (router links drop the query string). A module variable is used rather than sessionStorage because
// demo artifacts must not touch web storage (project rule); the latch resets on a full page reload,
// where the query string is re-read anyway.
let minimalLatched = false

// Test-only hook to clear the in-memory latch between cases. Not referenced by the app.
export function resetMotionLatchForTest(): void {
  minimalLatched = false
}

export function motionEnabled(
  win: MotionWindow | undefined = typeof window === 'undefined' ? undefined : window,
): boolean {
  if (!win || typeof win.matchMedia !== 'function') {
    // No matchMedia (jsdom, ancient browsers): fail safe to no motion.
    return false
  }
  if (win.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    return false
  }
  if (new URLSearchParams(win.location.search).get('minimal') === '1') {
    minimalLatched = true
    return false
  }
  return !minimalLatched
}
