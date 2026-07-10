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
  // With motion off the sections must appear instantly: the reveal transition is CSS, so it also
  // needs suppressing via a class (the media query only covers the OS-level preference).
  const motion = motionEnabled()

  // Reveal sections as they enter the viewport and flip the page hue to the visible section's.
  // With motion disabled the CSS class is applied immediately below, so nothing is hidden.
  useEffect(() => {
    const wrap = wrapRef.current
    if (!wrap) {
      return
    }
    const sections = Array.from(wrap.querySelectorAll<HTMLElement>('.lp-section'))
    if (!motionEnabled() || typeof IntersectionObserver === 'undefined') {
      sections.forEach((s) => s.classList.add('in'))
      return
    }
    const io = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting) {
            const el = e.target as HTMLElement
            el.classList.add('in')
            const hue = el.dataset.hue
            if (hue) {
              wrap.style.setProperty('--hue', hue)
            }
          }
        }
      },
      { threshold: 0.35 },
    )
    sections.forEach((s) => io.observe(s))
    return () => io.disconnect()
  }, [])

  return (
    <div className={motion ? 'landing' : 'landing no-motion'} ref={wrapRef}>
      <div className="hero">
        <HeroParticles />
        <div className="hero__copy">
          <h1 className="hero__title">
            Prove a person&apos;s data is <em>truly gone</em> from an agent&apos;s memory.
          </h1>
          <p className="hero__lead">
            Most teams can only prove they deleted a row. The embedding is still reconstructible. We
            crypto-shred it, retain the mandated decision log atomically, and hand you a signed proof
            that survives node failure.
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
