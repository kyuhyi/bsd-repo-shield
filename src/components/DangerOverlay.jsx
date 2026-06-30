import { useEffect } from 'react'

// report.dangerLock === true 일 때 전체화면 빨강 깜빡임 경고.
// Esc 또는 닫기 버튼으로 닫을 수 있으나 verdict 패널의 danger 상태는 유지된다.
export default function DangerOverlay({ show, onClose, reason, repoName }) {
  useEffect(() => {
    if (!show) return
    const onKey = (e) => { if (e.key === 'Escape') onClose?.() }
    window.addEventListener('keydown', onKey)
    // 배경 스크롤 잠금.
    const prev = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      window.removeEventListener('keydown', onKey)
      document.body.style.overflow = prev
    }
  }, [show, onClose])

  if (!show) return null

  return (
    <div className="danger-overlay" role="alertdialog" aria-modal="true" aria-label="심각한 위험 경고">
      <div className="danger-overlay__inner">
        <div className="danger-overlay__skull" aria-hidden="true">⛔</div>
        <h1>위험: 이 저장소를 clone하지 마세요</h1>
        <p>
          {repoName ? <><b>{repoName}</b> 저장소에서 </> : ''}
          심각한 위협이 탐지되었습니다. 코드를 내려받거나 설치 스크립트를 실행하면
          비밀정보 유출·악성 코드 실행 등의 피해를 입을 수 있습니다.
        </p>
        {reason && <div className="danger-overlay__reason">{reason}</div>}
        <button type="button" className="danger-overlay__btn" onClick={onClose} autoFocus>
          이해했습니다 — 경고 닫기
        </button>
        <span className="danger-overlay__esc">Esc 키로도 닫을 수 있습니다. 닫아도 위험 판정은 유지됩니다.</span>
      </div>
    </div>
  )
}
