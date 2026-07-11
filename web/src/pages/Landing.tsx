import { animate, onScroll, stagger } from 'animejs'
import { useEffect, useRef } from 'react'
import { Link } from 'react-router-dom'
import { HeroParticles } from '../components/HeroParticles'
import { motionEnabled } from '../motion'

interface Section {
  eyebrow: string
  title: string
  body: string
  hue: string
}

const SECTIONS: Section[] = [
  {
    eyebrow: 'The leak',
    title: 'Deleting the row is not enough.',
    body: 'The embedding is still on disk, and Vec2Text reconstructs the original text from it, including the name. A deleted memory that can be regenerated was never erased.',
    hue: 'var(--hue-red)',
  },
  {
    eyebrow: 'The fix',
    title: 'Destroy the key, keep the log, in one transaction.',
    body: 'The embedding is crypto-shredded by destroying its per-subject key, while the legally required decision log is retained in the same SERIALIZABLE transaction. GDPR Article 17 and EU AI Act Article 19 both hold, atomically.',
    hue: 'var(--hue-corail)',
  },
  {
    eyebrow: 'The proof',
    title: 'Signed, anchored, and it survives a node kill.',
    body: 'Every erasure emits an ECDSA-signed proof anchored in S3 Object Lock, the decision log is hash-chained and append-only against the agent role, and the committed erasure survives node failure via Raft.',
    hue: 'var(--hue-turquoise)',
  },
]

export function Landing() {
  const wrapRef = useRef<HTMLDivElement>(null)
  // With motion off the sections must appear instantly: the reveal is CSS, so it also needs the
  // no-motion class (the media query only covers the OS-level preference).
  const motion = motionEnabled()

  useEffect(() => {
    const wrap = wrapRef.current
    if (!wrap) {
      return
    }
    const sections = Array.from(wrap.querySelectorAll<HTMLElement>('.lp-section'))

    // Reduced motion / ?minimal=1 / tests: no ScrollObserver, no animation. Show every section at
    // its settled state instantly. This is the state the axe a11y gate scans (it runs under
    // prefers-reduced-motion), so scrubbed intermediate opacities never reach it.
    if (!motionEnabled()) {
      sections.forEach((s) => s.classList.add('in'))
      return
    }

    // Motion on: the container is instantly visible, and anime.js reveals each section's
    // eyebrow/title/body/cta with a staggered fade + slide TRIGGERED on scroll-enter (not synced):
    // content that must be READ has to end fully opaque and stay there, so a scrubbed opacity tied
    // to scroll position is deliberately NOT used here (that is reserved for the decorative hero
    // parallax below). A separate IntersectionObserver flips the page hue to the section in view.
    const scrubbers: { revert: () => void }[] = []
    sections.forEach((s) => {
      // Container instantly visible with no CSS reveal transition; anime owns the child reveal.
      s.classList.add('lp-section--scrub')
      const parts = s.querySelectorAll<HTMLElement>(
        '.lp-section__eyebrow, .lp-section__title, .lp-section__body, .cta',
      )
      if (parts.length === 0) {
        return
      }
      const anim = animate(parts, {
        opacity: { from: 0, to: 1 },
        translateY: { from: 34, to: 0 },
        duration: 620,
        delay: stagger(80),
        ease: 'outQuad',
        // Trigger once as the section enters from the bottom; the animation runs to completion and
        // stays at opacity 1. No sync, so the text is never left mid-fade in the reading zone.
        autoplay: onScroll({ target: s, enter: 'bottom-=120 top' }),
      })
      scrubbers.push(anim)
    })

    // Subtle scroll-SYNCED parallax (the scrubbed feel), on the decorative hero only: the copy
    // drifts up and dims tied to scroll position as you move past it. Safe to scrub because it is
    // not content you stop to read at a fixed position.
    const hero = wrap.querySelector<HTMLElement>('.hero')
    const heroCopy = wrap.querySelector<HTMLElement>('.hero__copy')
    let heroAnim: { revert: () => void } | null = null
    if (hero && heroCopy) {
      heroAnim = animate(heroCopy, {
        translateY: { from: 0, to: -48 },
        opacity: { from: 1, to: 0.35 },
        ease: 'linear',
        autoplay: onScroll({ target: hero, enter: 'top top', leave: 'bottom top', sync: 0.2 }),
      })
    }

    const io = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting) {
            const hue = (e.target as HTMLElement).dataset.hue
            if (hue) {
              wrap.style.setProperty('--hue', hue)
            }
          }
        }
      },
      { threshold: 0.4 },
    )
    sections.forEach((s) => io.observe(s))

    return () => {
      io.disconnect()
      scrubbers.forEach((a) => a.revert())
      heroAnim?.revert()
    }
  }, [])

  return (
    <div className={motion ? 'landing' : 'landing no-motion'} ref={wrapRef}>
      <div className="hero">
        <HeroParticles />
        <div className="hero__copy">
          <div className="hero__eyebrow">The system of record for agentic memory</div>
          <h1 className="hero__title">
            Prove a person&apos;s data is <em>truly gone</em> from an agent&apos;s memory.
          </h1>
          <p className="hero__lead">
            CockroachDB keeps agent memory durable and consistent through failure. But a system of
            record is only complete if it can prove memory is gone when the law demands it. Most
            teams can only prove they deleted a row, and the embedding is still reconstructible. We
            crypto-shred it, retain the mandated decision log atomically, and hand you a signed proof
            that survives a node kill.
          </p>
          <Link className="cta" to="/demo">
            Open the demo console -&gt;
          </Link>
        </div>
      </div>

      {SECTIONS.map((s) => (
        <section className="lp-section" key={s.eyebrow} data-hue={s.hue}>
          <div className="lp-section__eyebrow">{s.eyebrow}</div>
          <h2 className="lp-section__title">{s.title}</h2>
          <p className="lp-section__body">{s.body}</p>
        </section>
      ))}

      <section className="lp-section lp-section--last in">
        <Link className="cta" to="/demo">
          Run the whole loop yourself -&gt;
        </Link>
      </section>
    </div>
  )
}
