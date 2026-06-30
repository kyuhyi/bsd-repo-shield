import { withCommas, formatDateRel, chipClass } from './verdictMeta.js'

// repo 메타 + signals.trust 를 표로 표시. 사용자가 좋아한 표 형식.
export default function TrustSignalTable({ repo, trust }) {
  const created = formatDateRel(repo?.createdAt)
  const pushed = formatDateRel(repo?.pushedAt)

  // repo 메타에서 파생한 기본 행 + 엔진이 준 signals.trust 칩.
  const metaRows = [
    {
      label: '⭐ 스타',
      value: withCommas(repo?.stars),
      chip: repo?.stars >= 1000 ? '높음 (+신뢰)' : repo?.stars >= 100 ? '보통' : '낮음',
      cls: repo?.stars >= 1000 ? 'chip--good' : repo?.stars >= 100 ? 'chip--neutral' : 'chip--neutral',
    },
    {
      label: '🍴 포크',
      value: withCommas(repo?.forks),
      chip: repo?.forks >= 200 ? '활발 (+신뢰)' : '보통',
      cls: repo?.forks >= 200 ? 'chip--good' : 'chip--neutral',
    },
    {
      label: '📅 생성 / 최근 푸시',
      value: `${created.date} / ${pushed.date}`,
      chip: pushed.rel ? `최근 푸시 ${pushed.rel}` : '—',
      cls: pushedChip(repo?.pushedAt),
    },
    {
      label: '📄 라이선스',
      value: repo?.license || '없음',
      chip: repo?.license ? '양호 (+신뢰)' : '미지정 (주의)',
      cls: repo?.license ? 'chip--good' : 'chip--bad',
    },
    {
      label: '🗂 상태',
      value: repo?.archived ? '아카이브됨' : `기본 브랜치 ${repo?.defaultBranch || '—'}`,
      chip: repo?.archived ? '보관됨 (주의)' : '활성',
      cls: repo?.archived ? 'chip--bad' : 'chip--neutral',
    },
  ]

  return (
    <div className="card-block">
      <div className="card-block__head">신뢰 신호</div>
      <table className="trust-table">
        <thead>
          <tr>
            <th>신호</th>
            <th>값</th>
            <th>평가</th>
          </tr>
        </thead>
        <tbody>
          {metaRows.map((r) => (
            <tr key={r.label}>
              <th scope="row">{r.label}</th>
              <td className="val">{r.value}</td>
              <td><span className={`chip ${r.cls}`}>{r.chip}</span></td>
            </tr>
          ))}
          {Array.isArray(trust) && trust.map((s, i) => (
            <tr key={`ts-${i}`}>
              <th scope="row">{s.label}</th>
              <td className="val">{s.value}</td>
              <td><span className={`chip ${chipClass(s.weight)}`}>{s.weight}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function pushedChip(iso) {
  if (!iso) return 'chip--neutral'
  const days = (Date.now() - new Date(iso).getTime()) / 86_400_000
  if (Number.isNaN(days)) return 'chip--neutral'
  if (days <= 90) return 'chip--good'
  if (days <= 365) return 'chip--neutral'
  return 'chip--bad'
}
