import { useState } from 'react'
import { SEVERITY_ORDER, verdictMeta } from './verdictMeta.js'
import AiExplainPanel from './ai/AiExplainPanel.jsx'

const CATEGORY_LABEL = {
  'secret-exfiltration': '비밀정보 유출',
  'install-hook': '설치 훅',
  'remote-code-exec': '원격 코드 실행',
  obfuscation: '난독화',
  'suspicious-network': '의심 네트워크',
  'crypto-miner': '암호화폐 채굴',
  'dependency-risk': '의존성 위험',
  'dependency-hygiene': '의존성 위생 (취약점)',
  'source-mismatch': '출처 불일치',
}

const SEV_LABEL = { critical: 'critical', high: 'high', medium: 'medium', low: 'low' }

// snippet 내 위험 토큰을 강조 (휴리스틱 — 안전한 텍스트 하이라이트, 코드 실행 아님).
const DANGER_TOKENS = [
  'curl', 'wget', 'bash', 'sh -c', 'eval', 'exec', 'child_process', 'spawn',
  'process.env', 'atob', 'base64', 'fromCharCode', 'XMLHttpRequest', 'fetch(',
  'postinstall', 'preinstall', 'rm -rf', 'chmod', 'nc ', 'ncat', '/dev/tcp',
  'powershell', 'Invoke-Expression', 'AWS_SECRET', 'PRIVATE_KEY', 'token',
]

function highlight(snippet) {
  if (!snippet) return null
  // 토큰 경계로 분할해 강조. 정규식 특수문자 이스케이프.
  const esc = DANGER_TOKENS.map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
  const re = new RegExp(`(${esc.join('|')})`, 'gi')
  const parts = String(snippet).split(re)
  return parts.map((p, i) =>
    re.test(p) && DANGER_TOKENS.some((t) => p.toLowerCase() === t.toLowerCase())
      ? <span key={i} className="tok-danger">{p}</span>
      : <span key={i}>{p}</span>
  )
}

function FindingCard({ f, aiConfig, verdict, dangerLock }) {
  const longSnippet = (f.snippet || '').split('\n').length > 4 || (f.snippet || '').length > 160
  const [open, setOpen] = useState(!longSnippet && Boolean(f.snippet))
  const hasSnippet = Boolean(f.snippet)
  const loc = f.file ? `${f.file}${f.line != null ? `:${f.line}` : ''}` : null

  return (
    <article className="finding" data-sev={f.severity}>
      <div className="finding__top">
        <span className="sev-badge" data-sev={f.severity}>{SEV_LABEL[f.severity] || f.severity}</span>
        <span className="finding__cat">{CATEGORY_LABEL[f.category] || f.category}</span>
        {loc && <span className="finding__loc">{loc}</span>}
      </div>

      <h4 className="finding__title">{f.title}</h4>

      {hasSnippet && (
        <>
          <button
            type="button"
            className="finding__snip-toggle"
            aria-expanded={open}
            onClick={() => setOpen((o) => !o)}
          >
            <span className="caret">▸</span> {open ? '코드 숨기기' : '코드 보기'}
          </button>
          {open && (
            <pre className="finding__snippet"><code>{highlight(f.snippet)}</code></pre>
          )}
        </>
      )}

      {f.description && (
        <div className="finding__why">
          <span className="bulb" aria-hidden="true">💡</span>
          <span><b>왜 위험한가</b> · {f.description}</span>
        </div>
      )}

      {f.rule && <div className="finding__rule">rule: {f.rule}</div>}

      <AiExplainPanel
        finding={f}
        aiConfig={aiConfig}
        verdictLabel={verdictMeta(verdict).label}
        dangerLock={Boolean(dangerLock)}
      />
    </article>
  )
}

// 빈 상태: findings 0건 + safe.
function EmptyState({ scannedFiles, limited }) {
  return (
    <div className="empty-findings">
      <div className="em-icon" aria-hidden="true">✓</div>
      <h3>위협 미발견</h3>
      <p>
        검사한 {scannedFiles != null ? `${scannedFiles}개 ` : ''}파일에서 알려진 위협 패턴이 발견되지 않았습니다.
        {limited && ' (단, 일부 파일은 검사되지 않았습니다 — 위 “일부 미검사” 표식 참고)'}
      </p>
    </div>
  )
}

// 의존성 위생(일반 CVE)은 개수가 많아 본문을 도배하므로 1개 요약 카드로 압축.
// 상세 목록은 EnrichmentPanel의 '공급망 검사'(접이식 상위 5개)에 위임 — 중복·과밀 방지.
function HygieneSummary({ count }) {
  return (
    <article className="finding finding--hygiene" data-sev="medium">
      <div className="finding__top">
        <span className="sev-badge" data-sev="medium">위생</span>
        <span className="finding__cat">의존성 위생 (취약점)</span>
        <span className="finding__loc">{count}건</span>
      </div>
      <h4 className="finding__title">알려진 취약점이 있는 의존성 {count}건 — 악성은 아닙니다</h4>
      <div className="finding__why">
        <span className="bulb" aria-hidden="true">💡</span>
        <span>
          <b>의존성의 알려진 CVE</b>입니다(공급망 위생). 저장소 자체가 악성이라는 뜻은 아니며 clone을 막을 사유는 아닙니다.
          상세 목록은 아래 <b>‘외부 인텔 / 보안 권고’의 공급망 검사</b>에서 펼쳐 볼 수 있습니다.
        </span>
      </div>
    </article>
  )
}

// findings 심각도순 정렬 후 카드 리스트. verdict는 상위에서 별도 처리(여기선 findings만).
export default function FindingList({ findings, verdict, scannedFiles, scanLimitedReason, aiConfig, dangerLock }) {
  const list = Array.isArray(findings) ? findings : []
  // 위생 항목은 분리 → 본문은 실제 위협만, 위생은 요약 1장.
  const hygiene = list.filter((f) => f.category === 'dependency-hygiene')
  const threats = list.filter((f) => f.category !== 'dependency-hygiene')
  const sorted = [...threats].sort(
    (a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9)
  )

  // 위협·위생 모두 없을 때만 빈/메타 분기.
  if (sorted.length === 0 && hygiene.length === 0) {
    if (verdict === 'safe') {
      return <EmptyState scannedFiles={scannedFiles} limited={Boolean(scanLimitedReason)} />
    }
    // findings는 없지만 verdict가 caution/danger — 메타/신뢰 신호 기반.
    return (
      <div className="card-block" style={{ padding: '18px 20px', color: 'var(--text-dim)', fontSize: '.9rem' }}>
        탐지된 코드 패턴은 없지만 저장소 메타데이터·신뢰 신호를 근거로 <b style={{ color: 'var(--text)' }}>
          {verdict === 'danger' ? '위험' : '주의'}</b>으로 판정되었습니다. 위 신뢰 신호 표와 요약을 확인하세요.
      </div>
    )
  }

  return (
    <div>
      <div className="findings__head">
        탐지된 위협 <span className="findings__count">({sorted.length}건)</span>
        {hygiene.length > 0 && (
          <span className="findings__count findings__count--hygiene"> · 의존성 위생 {hygiene.length}건</span>
        )}
      </div>
      <div className="findings">
        {sorted.map((f) => (
          <FindingCard key={f.id} f={f} aiConfig={aiConfig} verdict={verdict} dangerLock={dangerLock} />
        ))}
        {hygiene.length > 0 && <HygieneSummary count={hygiene.length} />}
      </div>
    </div>
  )
}
