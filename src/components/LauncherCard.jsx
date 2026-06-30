import { useRef, useState } from 'react'

// 마우스 위치 → 회전각 + sheen 위치. rAF로 throttle.
function applyTilt(e, el) {
  const r = el.getBoundingClientRect()
  const px = (e.clientX - r.left) / r.width - 0.5 // -0.5~0.5
  const py = (e.clientY - r.top) / r.height - 0.5
  el.style.setProperty('--ry', `${px * 16}deg`)
  el.style.setProperty('--rx', `${-py * 16}deg`)
  el.style.setProperty('--mx', `${(px + 0.5) * 100}%`)
  el.style.setProperty('--my', `${(py + 0.5) * 100}%`)
}

function reset(el) {
  if (!el) return
  el.style.setProperty('--rx', '0deg')
  el.style.setProperty('--ry', '0deg')
}

// 무료·키 불필요 스크린샷 서비스 폴백 체인. 앞에서 실패하면 다음, 모두 실패하면 글자 폴백.
const SHOT_SERVICES = [
  (u) => `https://image.thum.io/get/width/640/crop/440/noanimate/${u}`,
  (u) => `https://s0.wp.com/mshots/v1/${encodeURIComponent(u)}?w=640&h=440`,
]

// 3D tilt + 홀로그래픽 sheen 카드. 실제 <a>로 키보드/새 탭/우클릭 지원.
// hidden: 마퀴 무한루프용 복제본 → 접근성 트리/탭 순서에서 제외(원본만 노출).
export default function LauncherCard({ site, hidden = false }) {
  const ref = useRef(null)
  const raf = useRef(0)
  const [shotIdx, setShotIdx] = useState(0)
  const [shotFailed, setShotFailed] = useState(false)

  const onMove = (e) => {
    const el = ref.current
    if (!el) return
    cancelAnimationFrame(raf.current)
    raf.current = requestAnimationFrame(() => applyTilt(e, el))
  }
  const onLeave = () => {
    cancelAnimationFrame(raf.current)
    reset(ref.current)
  }
  const onShotError = () => {
    // 다음 서비스로, 다 떨어지면 글자 폴백
    if (shotIdx < SHOT_SERVICES.length - 1) setShotIdx((i) => i + 1)
    else setShotFailed(true)
  }

  const initial = (site.name || '?').charAt(0)
  const shotSrc = site.thumb || SHOT_SERVICES[shotIdx](site.url)

  return (
    <a
      ref={ref}
      className="card"
      style={{ '--hue': site.hue }}
      href={site.url}
      target="_blank"
      rel="noopener noreferrer"
      onMouseMove={onMove}
      onMouseLeave={onLeave}
      aria-label={`${site.name} — ${site.desc} (새 탭에서 열기)`}
      aria-hidden={hidden || undefined}
      tabIndex={hidden ? -1 : undefined}
    >
      <span className="card__arrow" aria-hidden="true">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
          <path d="M7 17 17 7M9 7h8v8" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </span>
      <span className="card__shot" aria-hidden="true">
        <span className="card__shot-fallback">{initial}</span>
        {!shotFailed && (
          <img
            className="card__shot-img"
            src={shotSrc}
            alt=""
            loading="lazy"
            referrerPolicy="no-referrer"
            onError={onShotError}
          />
        )}
      </span>
      <h3 className="card__title">{site.name}</h3>
      <p className="card__desc">{site.desc}</p>
      <span className="card__go">바로가기 →</span>
    </a>
  )
}
