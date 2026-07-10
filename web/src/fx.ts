// Motion effects for the console. Presentation only: every function is a no-op unless
// motionEnabled() and the target elements exist, so tests and reduced-motion users always see the
// instant final state the plain UI already renders.

import { animate, stagger } from 'animejs'
import { motionEnabled } from './motion'

const SCRAMBLE_CHARS = '0123456789abcdef'

// In-flight scrambles, so a re-run cancels the previous animation on the same element instead of
// racing it (two racing scrambles could latch mid-scramble garbage as the "final" text).
const scrambling = new WeakMap<HTMLElement, { pause: () => void }>()

/** Per-character scramble-in: the element's final text resolves left to right out of hex noise. */
export function scrambleIn(el: HTMLElement, durationMs = 900): void {
  const inflight = scrambling.get(el)
  inflight?.pause()
  // A fresh call reads the (React-rendered) current text as truth; a call that interrupted an
  // in-flight scramble must use the latched original, because the current text is mid-noise.
  const finalText = inflight ? (el.dataset.finalText ?? '') : (el.textContent ?? '')
  el.dataset.finalText = finalText
  if (!motionEnabled() || finalText.length === 0) {
    return
  }
  const progress = { p: 0 }
  const anim = animate(progress, {
    p: 1,
    duration: durationMs,
    ease: 'outQuad',
    onUpdate: () => {
      const settled = Math.floor(progress.p * finalText.length)
      let out = finalText.slice(0, settled)
      for (let i = settled; i < finalText.length; i++) {
        const ch = finalText[i]
        out += ch === ' ' ? ' ' : SCRAMBLE_CHARS[Math.floor(Math.random() * SCRAMBLE_CHARS.length)]
      }
      el.textContent = out
    },
    onComplete: () => {
      el.textContent = finalText
      scrambling.delete(el)
    },
  })
  scrambling.set(el, anim)
}

/** Stagger-reveal the direct result blocks of a stage (used when a stage completes). */
export function revealResults(stageEl: HTMLElement): void {
  if (!motionEnabled()) {
    return
  }
  const blocks = stageEl.querySelectorAll<HTMLElement>('.kv-grid, .note, .code, .chain')
  if (blocks.length === 0) {
    return
  }
  animate(blocks, {
    opacity: [0, 1],
    translateY: [10, 0],
    duration: 450,
    delay: stagger(90),
    ease: 'outQuad',
  })
}

/** Flare a stage's accent bar when it completes. */
export function pulseStageBar(stageEl: HTMLElement): void {
  if (!motionEnabled()) {
    return
  }
  const bar = stageEl.querySelector<HTMLElement>('.stage__bar')
  if (!bar) {
    return
  }
  animate(bar, {
    scaleY: [1, 2.4, 1],
    duration: 520,
    ease: 'outQuad',
  })
}

/** Stagger the whole stage list in on first mount. */
export function revealStages(panelEl: HTMLElement): void {
  if (!motionEnabled()) {
    return
  }
  const stages = panelEl.querySelectorAll<HTMLElement>('.stage')
  if (stages.length === 0) {
    return
  }
  animate(stages, {
    opacity: [0, 1],
    translateY: [16, 0],
    duration: 550,
    delay: stagger(80),
    ease: 'outQuad',
  })
}
