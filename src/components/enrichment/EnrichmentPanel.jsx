import { useEffect, useState } from 'react'
import { fetchGithubAdvisories } from '../../config/advisories.js'

// 외부 인텔(enrichment) 표시 + 보안 권고 배지.
// 계약: report.enrichment 는 optional. 없으면 섹션 자체를 숨긴다(v1 호환).
// 원칙: intelErrors가 있으면 "일부 외부조회 실패"를 정직히 표기(미조회를 안전으로 위장 금지).
// UX: 긴 목록은 심각도순 상위 N개만 보이고 더보기/접기로 펼친다(정보 과잉 방지).

const SEV_RANK = { critical: 0, high: 1, medium: 2, moderate: 2, low: 3, unknown: 4 }
const TOP_N = 5

function sevRank(s) {
  return SEV_RANK[String(s || 'unknown').toLowerCase()] ?? 4
}

function SevTag({ severity }) {
  const s = String(severity || 'unknown').toLowerCase()
  // moderate(GitHub) → medium 시각화로 매핑.
  const key = s === 'moderate' ? 'medium' : (SEV_RANK[s] != null ? s : 'low')
  return <span className="enr-sev" data-sev={key}>{s}</span>
}

// 상위 N개만 보이고 나머지는 더보기/접기. items가 N 이하면 그냥 전부 표시.
function MoreToggle({ open, hidden, onToggle, noun = '개' }) {
  return (
    <button type="button" className="enr-more" onClick={onToggle} aria-expanded={open}>
      {open ? '접기 ▲' : `+${hidden}${noun} 더보기 ▼`}
    </button>
  )
}

// --- 공급망 ---
function SupplyChain({ sc }) {
  const [open, setOpen] = useState(false)
  if (!sc) return null
  const vulnerable = (Array.isArray(sc.vulnerable) ? sc.vulnerable : [])
    .slice()
    .sort((a, b) => sevRank(a.severity) - sevRank(b.severity))
  const typosquat = Array.isArray(sc.typosquat) ? sc.typosquat : []
  const clean = vulnerable.length === 0 && typosquat.length === 0
  const shown = open ? vulnerable : vulnerable.slice(0, TOP_N)
  const hidden = vulnerable.length - shown.length

  return (
    <div className="enr-block">
      <div className="enr-block__head">
        <span className="enr-ic" aria-hidden="true">📦</span>
        공급망 검사
        {sc.ecosystem && <span className="enr-tag">{sc.ecosystem}</span>}
        {typeof sc.checked === 'number' && <span className="enr-muted">의존성 {sc.checked}개 조회</span>}
        {vulnerable.length > 0 && <span className="enr-tag enr-tag--bad">취약 {vulnerable.length}건</span>}
      </div>

      {clean && (
        <p className="enr-ok">조회한 의존성에서 알려진 취약/악성 항목이 발견되지 않았습니다.</p>
      )}

      {vulnerable.length > 0 && (
        <>
          <ul className="enr-list">
            {shown.map((v, i) => (
              <li key={`${v.name}-${i}`} className="enr-row enr-row--bad">
                <SevTag severity={v.severity} />
                <code className="enr-pkg">{v.name}</code>
                <span className="enr-advisory">{v.advisory}</span>
              </li>
            ))}
          </ul>
          {vulnerable.length > TOP_N && (
            <MoreToggle open={open} hidden={hidden} onToggle={() => setOpen((o) => !o)} noun="건" />
          )}
        </>
      )}

      {typosquat.length > 0 && (
        <div className="enr-typo">
          <b>타이포스쿼팅 의심:</b>{' '}
          {typosquat.map((t, i) => <code key={i} className="enr-pkg enr-pkg--warn">{t}</code>)}
          <p className="enr-muted">유명 패키지와 철자가 비슷합니다 — 이름을 정확히 확인하세요.</p>
        </div>
      )}
    </div>
  )
}

// --- 출처 불일치 ---
function SourceMismatch({ sm }) {
  if (!sm) return null
  const matches = sm.repoMatches
  const bad = matches === false
  const unknown = matches == null
  return (
    <div className={`enr-block ${bad ? 'enr-block--warn' : ''}`}>
      <div className="enr-block__head">
        <span className="enr-ic" aria-hidden="true">🔀</span>
        출처 일치 검사
        {sm.registry && <span className="enr-tag">{sm.registry}</span>}
      </div>
      <p className={bad ? 'enr-bad' : unknown ? 'enr-muted' : 'enr-ok'}>
        {bad && (
          <>
            <b>⚠ 설치되는 코드가 이 GitHub 저장소와 다를 수 있습니다.</b>{' '}
            레지스트리에 게시된 패키지가 이 저장소를 가리키지 않습니다. 게시된 패키지를 직접 확인하세요.
          </>
        )}
        {matches === true && '레지스트리 게시본이 이 저장소를 가리킵니다(출처 일치).'}
        {unknown && '출처 일치 여부를 확인하지 못했습니다.'}
      </p>
      {sm.note && <p className="enr-note">{sm.note}</p>}
    </div>
  )
}

// --- 포렌식 ---
function Forensics({ fx }) {
  if (!fx) return null
  const flags = Array.isArray(fx.flags) ? fx.flags : []
  const hasMeta = fx.ownerCreatedAt != null || fx.contributors != null
  if (!flags.length && !hasMeta) return null
  return (
    <div className={`enr-block ${flags.length ? 'enr-block--warn' : ''}`}>
      <div className="enr-block__head">
        <span className="enr-ic" aria-hidden="true">🕵</span>
        커밋·소유자 포렌식
      </div>
      <div className="enr-meta-row">
        {fx.ownerCreatedAt != null && (
          <span className="enr-muted">소유자 계정 생성: <b>{String(fx.ownerCreatedAt).slice(0, 10)}</b></span>
        )}
        {fx.contributors != null && (
          <span className="enr-muted">기여자 <b>{fx.contributors}</b>명</span>
        )}
      </div>
      {flags.length > 0 && (
        <ul className="enr-flags">
          {flags.map((f, i) => <li key={i} className="enr-flag">⚑ {f}</li>)}
        </ul>
      )}
    </div>
  )
}

// --- 커밋된 시크릿 ---
function Secrets({ sec }) {
  const [open, setOpen] = useState(false)
  if (!sec || typeof sec.count !== 'number') return null
  if (sec.count === 0) return null
  const samples = Array.isArray(sec.samples) ? sec.samples : []
  const shown = open ? samples : samples.slice(0, TOP_N)
  const hidden = samples.length - shown.length
  return (
    <div className="enr-block enr-block--warn">
      <div className="enr-block__head">
        <span className="enr-ic" aria-hidden="true">🔑</span>
        커밋된 시크릿
        <span className="enr-tag enr-tag--bad">{sec.count}건</span>
      </div>
      <p className="enr-bad">
        저장소에 커밋된 시크릿(키/토큰)이 발견되었습니다. 노출된 자격증명은 즉시 폐기·교체되어야 합니다.
      </p>
      {samples.length > 0 && (
        <>
          <ul className="enr-list">
            {shown.map((s, i) => (
              <li key={i} className="enr-row">
                <code className="enr-pkg">{s.file}</code>
                <span className="enr-advisory">{s.kind}</span>
              </li>
            ))}
          </ul>
          {samples.length > TOP_N && (
            <MoreToggle open={open} hidden={hidden} onToggle={() => setOpen((o) => !o)} noun="건" />
          )}
        </>
      )}
    </div>
  )
}

// --- 보안 권고 배지(GitHub advisories; OSV는 enrichment.supplyChain 재사용) ---
function AdvisoryBadges({ owner, name, token, supplyChainVuln }) {
  const [state, setState] = useState({ loading: true, advisories: [], error: null })
  const [open, setOpen] = useState(false)

  useEffect(() => {
    let alive = true
    setState({ loading: true, advisories: [], error: null })
    fetchGithubAdvisories(owner, name, { token }).then((r) => {
      if (alive) setState({ loading: false, advisories: r.advisories, error: r.error })
    })
    return () => { alive = false }
  }, [owner, name, token])

  const gh = state.advisories || []
  const osv = Array.isArray(supplyChainVuln) ? supplyChainVuln : []
  // gh/osv를 하나의 배지 목록으로 합쳐 심각도순 정렬 → 상위 N개만, 나머지는 접기.
  const items = [
    ...gh.map((a) => ({ kind: 'gh', sev: a.severity, data: a })),
    ...osv.map((v) => ({ kind: 'osv', sev: v.severity, data: v })),
  ].sort((a, b) => sevRank(a.sev) - sevRank(b.sev))
  const total = items.length

  if (state.loading) {
    return <div className="enr-adv enr-muted"><span className="spin" aria-hidden="true" /> 보안 권고 조회 중…</div>
  }

  if (total === 0 && !state.error) {
    return (
      <div className="enr-adv enr-adv--clean">
        <span className="enr-badge enr-badge--ok">권고 0건</span>
        <span className="enr-muted">이 저장소/패키지에 보고된 GitHub·OSV 보안 권고가 없습니다.</span>
      </div>
    )
  }

  const shown = open ? items : items.slice(0, TOP_N)
  const hidden = total - shown.length

  return (
    <div className="enr-adv">
      <div className="enr-adv__head">
        <span className="enr-ic" aria-hidden="true">📣</span>
        이미 보고된 보안 권고
        {total > 0 && <span className="enr-tag enr-tag--bad">{total}건</span>}
      </div>
      <div className="enr-adv__badges">
        {shown.map((it, i) => (
          it.kind === 'gh' ? (
            it.data.htmlUrl ? (
              <a key={`gh-${i}`} className="enr-badge enr-badge--adv" href={it.data.htmlUrl} target="_blank" rel="noopener noreferrer" title={it.data.summary}>
                <SevTag severity={it.data.severity} /> {it.data.ghsaId} ↗
              </a>
            ) : (
              <span key={`gh-${i}`} className="enr-badge enr-badge--adv" title={it.data.summary}>
                <SevTag severity={it.data.severity} /> {it.data.ghsaId}
              </span>
            )
          ) : (
            <span key={`osv-${i}`} className="enr-badge enr-badge--adv" title={`${it.data.name}: ${it.data.advisory}`}>
              <SevTag severity={it.data.severity} /> OSV · {it.data.advisory}
            </span>
          )
        ))}
      </div>
      {total > TOP_N && (
        <MoreToggle open={open} hidden={hidden} onToggle={() => setOpen((o) => !o)} noun="건" />
      )}
      {state.error && <p className="enr-note">⚠ {state.error}</p>}
    </div>
  )
}

/**
 * report.enrichment + GitHub advisories 통합 표시. 전체 패널도 접기/펴기 가능.
 * props: report (VerdictReport), token (선택, advisory 조회용)
 */
export default function EnrichmentPanel({ report, token }) {
  const [collapsed, setCollapsed] = useState(false)
  const enr = report?.enrichment
  const repo = report?.repo
  // enrichment도 없고 repo도 없으면 advisory도 못 띄움 → 전체 숨김.
  if (!enr && !repo) return null

  const intelErrors = Array.isArray(enr?.intelErrors) ? enr.intelErrors : []
  const hasEnrBody =
    Boolean(enr?.supplyChain) ||
    Boolean(enr?.sourceMismatch) ||
    Boolean(enr?.forensics) ||
    (enr?.secrets?.count > 0)

  return (
    <div className="enrichment card-block">
      <button
        type="button"
        className="card-block__head enrichment__toggle"
        onClick={() => setCollapsed((c) => !c)}
        aria-expanded={!collapsed}
      >
        <span aria-hidden="true">🛰</span> 외부 인텔 / 보안 권고
        {intelErrors.length > 0 && (
          <span className="enr-partial" title={intelErrors.join('\n')}>일부 외부조회 실패</span>
        )}
        <span className="enrichment__chev" aria-hidden="true">{collapsed ? '▼' : '▲'}</span>
      </button>

      {!collapsed && (
        <div className="enrichment__body">
          {/* 보안 권고는 키 없이 항상 시도(repo 있으면) */}
          {repo && (
            <AdvisoryBadges
              owner={repo.owner}
              name={repo.name}
              token={token}
              supplyChainVuln={enr?.supplyChain?.vulnerable}
            />
          )}

          {hasEnrBody && (
            <div className="enrichment__intel">
              <SupplyChain sc={enr?.supplyChain} />
              <SourceMismatch sm={enr?.sourceMismatch} />
              <Forensics fx={enr?.forensics} />
              <Secrets sec={enr?.secrets} />
            </div>
          )}

          {intelErrors.length > 0 && (
            <div className="enr-errors">
              <b>외부 조회 실패 소스(정직성):</b>
              <ul>
                {intelErrors.map((e, i) => <li key={i}>{e}</li>)}
              </ul>
              <p className="enr-muted">조회 실패는 안전 신호가 아닙니다 — 위 항목은 미확인 상태입니다.</p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
