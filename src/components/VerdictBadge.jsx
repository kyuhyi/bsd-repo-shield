import { verdictMeta, verdictStyleVars, riskBand } from './verdictMeta.js'

// 반원형 위험 게이지 (riskScore 0~100). 채움 색 = verdict 색.
function RiskGauge({ score, color }) {
  const v = Math.max(0, Math.min(100, Number(score) || 0))
  // 반원: 반지름 40, 둘레의 절반.
  const r = 40
  const semi = Math.PI * r // 반원 호 길이
  const offset = semi * (1 - v / 100)
  return (
    <div className="risk-gauge" title={`종합 위험 점수 ${v}/100`}>
      <svg viewBox="0 0 100 58" aria-label={`위험 점수 ${v}점`}>
        <path d="M6 52 A 40 40 0 0 1 94 52" fill="none" stroke="#0c121b" strokeWidth="9" strokeLinecap="round" />
        <path
          d="M6 52 A 40 40 0 0 1 94 52"
          fill="none"
          stroke={color}
          strokeWidth="9"
          strokeLinecap="round"
          strokeDasharray={semi}
          strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset 1s var(--ease)' }}
        />
        <text x="50" y="46" className="risk-gauge__num" textAnchor="middle">{v}</text>
      </svg>
      <span className="risk-gauge__cap">위험 {riskBand(v)}</span>
    </div>
  )
}

// 신호등 verdict 배지 + scanLimitedReason "일부 미검사" 보조 배지.
export default function VerdictBadge({ verdict, riskScore, scanLimitedReason, scannedFiles }) {
  const m = verdictMeta(verdict)
  const limited = Boolean(scanLimitedReason)

  // safe 문구는 미검사 시 "검사한 범위 내"로 한정 (거짓 안심 방지).
  let line = m.line
  if (m.key === 'safe' && limited) line = '검사한 범위 내에서 위협 미발견'

  return (
    <div className="verdict-badge" style={verdictStyleVars(verdict)}>
      <span className="verdict-badge__icon" aria-hidden="true">{m.icon}</span>
      <div className="verdict-badge__body">
        <div className="verdict-badge__label">
          {m.label}
          {limited && (
            <span
              className="limited-tag"
              title={`일부 파일을 검사하지 못했습니다: ${scanLimitedReason}`}
            >
              일부 미검사
            </span>
          )}
        </div>
        <div className="verdict-badge__sub">{line}</div>
        {limited && (
          <div className="verdict-badge__sub" style={{ color: 'var(--text-faint)', marginTop: 4 }}>
            미검사 사유: {scanLimitedReason}
          </div>
        )}
      </div>
      <RiskGauge score={riskScore} color={m.color} />
    </div>
  )
}
