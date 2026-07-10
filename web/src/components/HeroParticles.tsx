// The landing hero: 768 particles (one per GTR dimension) converge out of noise into the demo
// subject's name, then scatter back to noise as you scroll. That IS the thesis in one image: a name
// reconstructible from a vector, then provable noise.
//
// Graceful degradation everywhere: without motion (reduced-motion, ?minimal=1) or without a canvas
// 2d context (jsdom), it renders nothing and the static heading beside it carries the page.

import { useEffect, useRef } from 'react'
import { animate } from 'animejs'
import { motionEnabled } from '../motion'

const PARTICLES = 768
const WORD = 'STEPHEN SOOKRA'
const HUE = '#00ffaa'

interface Particle {
  nx: number // noise position
  ny: number
  tx: number // target (text) position
  ty: number
  size: number
  alpha: number
}

/** Sample up to n points from the word drawn on an offscreen canvas. */
function sampleWord(width: number, height: number, n: number): { x: number; y: number }[] {
  const off = document.createElement('canvas')
  off.width = width
  off.height = height
  const ctx = off.getContext('2d')
  if (!ctx) {
    return []
  }
  ctx.fillStyle = '#fff'
  ctx.font = `700 ${Math.floor(height * 0.42)}px "DINish Condensed", sans-serif`
  ctx.textAlign = 'center'
  ctx.textBaseline = 'middle'
  ctx.fillText(WORD, width / 2, height / 2)
  const img = ctx.getImageData(0, 0, width, height).data
  const points: { x: number; y: number }[] = []
  const step = 3
  for (let y = 0; y < height; y += step) {
    for (let x = 0; x < width; x += step) {
      if (img[(y * width + x) * 4 + 3] > 128) {
        points.push({ x, y })
      }
    }
  }
  // Thin evenly down to n points.
  if (points.length <= n) {
    return points
  }
  const out: { x: number; y: number }[] = []
  for (let i = 0; i < n; i++) {
    out.push(points[Math.floor((i * points.length) / n)])
  }
  return out
}

export function HeroParticles() {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  // With motion off there are no particles: render nothing rather than an empty canvas block with a
  // caption describing dots that never appear. The static heading carries the hero.
  const enabled = motionEnabled()

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas || !motionEnabled()) {
      return
    }
    const ctx = canvas.getContext('2d')
    if (!ctx) {
      return
    }

    const width = (canvas.width = canvas.offsetWidth)
    const height = (canvas.height = canvas.offsetHeight)
    if (width === 0 || height === 0) {
      return
    }

    let cancelled = false
    let particles: Particle[] = []
    // state.p: 0 = noise, 1 = the word. One shared progress value drives every particle.
    const state = { p: 0 }
    let currentAnim: { pause: () => void } | null = null

    const draw = () => {
      ctx.clearRect(0, 0, width, height)
      ctx.fillStyle = HUE
      for (const pt of particles) {
        const x = pt.nx + (pt.tx - pt.nx) * state.p
        const y = pt.ny + (pt.ty - pt.ny) * state.p
        ctx.globalAlpha = pt.alpha * (0.35 + 0.65 * state.p)
        ctx.fillRect(x, y, pt.size, pt.size)
      }
      ctx.globalAlpha = 1
    }

    const toward = (target: number, duration: number) => {
      currentAnim?.pause()
      currentAnim = animate(state, {
        p: target,
        duration,
        ease: 'inOutQuad',
        onUpdate: draw,
      })
    }

    // Scatter back to noise once the hero is meaningfully scrolled past; reconverge when back.
    // Only restart the tween when the threshold actually flips: restarting per scroll event would
    // freeze the ease-in curve near its start and churn an animation object per event.
    let lastScattered = false
    const onScroll = () => {
      if (cancelled) {
        return
      }
      const scattered = window.scrollY > height * 0.35
      if (scattered === lastScattered) {
        return
      }
      lastScattered = scattered
      toward(scattered ? 0 : 1, 900)
    }

    const start = () => {
      if (cancelled) {
        return
      }
      const targets = sampleWord(width, height, PARTICLES)
      if (targets.length === 0) {
        return
      }
      particles = targets.map((t) => ({
        nx: Math.random() * width,
        ny: Math.random() * height,
        tx: t.x,
        ty: t.y,
        size: 1.6 + Math.random() * 1.8,
        alpha: 0.5 + Math.random() * 0.5,
      }))
      draw()
      toward(1, 1800)
      window.addEventListener('scroll', onScroll, { passive: true })
    }

    // Wait for the display font so the sampled word has the right shape.
    if (typeof document.fonts?.ready?.then === 'function') {
      void document.fonts.ready.then(start)
    } else {
      start()
    }

    return () => {
      cancelled = true
      currentAnim?.pause()
      window.removeEventListener('scroll', onScroll)
    }
  }, [])

  if (!enabled) {
    return null
  }
  return (
    <div className="hero-canvas-wrap" aria-hidden="true">
      <canvas ref={canvasRef} className="hero-canvas" />
      <div className="hero-canvas__caption">768 dots, one per GTR embedding dimension</div>
    </div>
  )
}
