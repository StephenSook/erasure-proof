// A seven-segment (or fourteen-segment, for letters) LCD readout in the DSEG typeface, with the
// unlit "888" segments ghosted behind the value, like hardware.

export function LcdCounter({
  label,
  value,
  family = '7',
  width = 6,
}: {
  label: string
  value: string
  family?: '7' | '14'
  width?: number
}) {
  const ghostChar = family === '7' ? '8' : '~' // DSEG14 renders '~' as the all-segments-on glyph
  return (
    <div className="lcd">
      <div className="lcd__label">{label}</div>
      <div className={`lcd__value lcd__value--${family}`}>
        <span className="lcd__ghost" aria-hidden="true">
          {ghostChar.repeat(width)}
        </span>
        <span className="lcd__text">{value.slice(-width)}</span>
      </div>
    </div>
  )
}
