// The single gate every animation goes through. Motion is presentation only: nothing in the demo
// state machine depends on it, so disabling it (reduced-motion users, ?minimal=1, test runners
// without matchMedia) collapses the UI to instant final states with zero behaviour change.

type MotionWindow = Pick<Window, 'matchMedia' | 'location'> & { sessionStorage?: Storage }

const MINIMAL_KEY = 'erasure-proof:minimal'

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
  // ?minimal=1 is latched into sessionStorage so it survives internal navigation (router links drop
  // the query string). sessionStorage can throw in some privacy modes; treat that as not latched.
  try {
    if (new URLSearchParams(win.location.search).get('minimal') === '1') {
      win.sessionStorage?.setItem(MINIMAL_KEY, '1')
      return false
    }
    if (win.sessionStorage?.getItem(MINIMAL_KEY) === '1') {
      return false
    }
  } catch {
    // Storage unavailable: fall through with just the query-string check above.
  }
  return true
}
