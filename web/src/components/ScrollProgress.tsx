import { useEffect, useRef } from 'react'

// A thin fixed bar at the top of the viewport whose width tracks scroll progress. Decorative and
// aria-hidden (it conveys no information a screen reader needs; scroll position is native). It
// updates on scroll via a single rAF-coalesced handler, so it is cheap; under reduced motion the
// CSS gives it no transition, so it simply reflects position without easing.

export function ScrollProgress() {
  const barRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    let pending = false
    const update = () => {
      pending = false
      const bar = barRef.current
      if (!bar) {
        return
      }
      const doc = document.documentElement
      const max = doc.scrollHeight - doc.clientHeight
      const p = max > 0 ? Math.min(1, Math.max(0, window.scrollY / max)) : 0
      bar.style.transform = `scaleX(${p})`
    }
    const onScroll = () => {
      if (!pending) {
        pending = true
        requestAnimationFrame(update)
      }
    }
    update()
    window.addEventListener('scroll', onScroll, { passive: true })
    window.addEventListener('resize', onScroll, { passive: true })
    return () => {
      window.removeEventListener('scroll', onScroll)
      window.removeEventListener('resize', onScroll)
    }
  }, [])

  return (
    <div className="scroll-progress" aria-hidden="true">
      <div className="scroll-progress__bar" ref={barRef} />
    </div>
  )
}
