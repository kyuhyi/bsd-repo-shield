// 로딩 중 스캔 진행 표시. 엔진 onProgress 콜백 데이터를 반영.
// progress: { phase, scanned, total, rateRemaining } — 모두 optional.
export default function ScanProgress({ progress }) {
  const { phase, scanned, total, rateRemaining } = progress || {}
  const hasTotal = typeof total === 'number' && total > 0
  const pct = hasTotal ? Math.min(100, Math.round((scanned / total) * 100)) : 0

  return (
    <div className="scan" role="status" aria-live="polite">
      <div className="scan__head">
        <span className="scan__pulse" aria-hidden="true" />
        <span className="scan__title">저장소 정적 분석 중</span>
        {phase && <span className="scan__phase">{phase}</span>}
      </div>

      <div className={`scan__bar${hasTotal ? '' : ' scan__bar--indeterminate'}`}>
        <div className="scan__bar-fill" style={hasTotal ? { width: `${pct}%` } : undefined} />
      </div>

      <div className="scan__meta">
        {hasTotal ? (
          <span>검사 파일 <b>{scanned ?? 0}</b> / {total} ({pct}%)</span>
        ) : (
          typeof scanned === 'number' && <span>검사한 파일 <b>{scanned}</b>개</span>
        )}
        {typeof rateRemaining === 'number' && (
          <span>남은 API 호출 <b>{rateRemaining}</b></span>
        )}
      </div>
    </div>
  )
}
