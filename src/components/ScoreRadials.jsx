import { useEffect, useRef, useState } from 'react'

const R = 46
const C = 2 * Math.PI * R

// prefers-reduced-motion 감지.
function usePrefersReducedMotion() {
  const [reduced, setReduced] = useState(
    () => typeof window !== 'undefined' &&
      window.matchMedia &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches
  )
  useEffect(() => {
    if (!window.matchMedia) return
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)')
    const on = () => setReduced(mq.matches)
    mq.addEventListener?.('change', on)
    return () => mq.removeEventListener?.('change', on)
  }, [])
  return reduced
}

// 마운트 시 0 -> target 카운트업 애니메이션.
function useCountUp(target, reduced, duration = 1000) {
  const [v, setV] = useState(reduced ? target : 0)
  const raf = useRef(0)
  useEffect(() => {
    if (reduced) { setV(target); return }
    const start = performance.now()
    const tick = (now) => {
      const t = Math.min(1, (now - start) / duration)
      const eased = 1 - Math.pow(1 - t, 3) // easeOutCubic
      setV(target * eased)
      if (t < 1) raf.current = requestAnimationFrame(tick)
    }
    raf.current = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf.current)
  }, [target, reduced, duration])
  return v
}

// invert=true → 위험도(높을수록 빨강). 나머지는 높을수록 초록.
function Radial({ label, value, invert, hint }) {
  const reduced = usePrefersReducedMotion()
  const target = Math.max(0, Math.min(100, Number(value) || 0))
  const v = useCountUp(target, reduced)

  const good = invert ? 100 - target : target // 0(나쁨)~100(좋음)
  const hue = good * 1.2 // 0=빨강 → 120=초록
  const stroke = `hsl(${hue} 78% 54%)`
  const offset = C * (1 - v / 100)

  return (
    <div className="radial">
      <svg viewBox="0 0 110 110" role="img" aria-label={`${label} ${Math.round(target)}점`}>
        <circle cx="55" cy="55" r={R} className="radial__track" />
        <circle
          cx="55"
          cy="55"
          r={R}
          className="radial__bar"
          style={{
            stroke,
            strokeDasharray: C,
            strokeDashoffset: offset,
            transition: reduced ? 'none' : 'stroke .6s var(--ease)',
          }}
        />
        <text x="55" y="55" className="radial__num">{Math.round(v)}</text>
      </svg>
      <span className="radial__label">{label}</span>
      {hint && <span className="radial__hint">{hint}</span>}
    </div>
  )
}

// scores.{trust, stability, suitability, risk} 4축 원형 그래프.
export default function ScoreRadials({ scores }) {
  const s = scores || {}
  return (
    <div className="radials">
      <Radial label="신뢰도" value={s.trust} hint="높을수록 좋음" />
      <Radial label="안정성" value={s.stability} hint="높을수록 좋음" />
      <Radial label="적합성" value={s.suitability} hint="높을수록 좋음" />
      <Radial label="위험도" value={s.risk} invert hint="높을수록 나쁨" />
    </div>
  )
}
