import VerdictBadge from './VerdictBadge.jsx'
import TrustSignalTable from './TrustSignalTable.jsx'
import ScoreRadials from './ScoreRadials.jsx'
import FindingList from './FindingList.jsx'
import EnrichmentPanel from './enrichment/EnrichmentPanel.jsx'

// VerdictReport 전체를 조립해 표시.
// aiConfig: AI 해설용(키/모델) — 키 없으면 finding 카드의 AI 버튼만 비활성.
// token: 보안 권고 조회 시 GitHub 한도 완화용(선택).
export default function VerdictPanel({ report, aiConfig, token }) {
  if (!report) return null
  const { repo, verdict, riskScore, scores, summary, findings, signals, scannedFiles, scanLimitedReason, dangerLock } = report

  // 정합성 콘솔 경고: riskScore와 verdict 모순 시 (verdict 우선, 렌더는 계속).
  if (typeof riskScore === 'number') {
    if (verdict === 'safe' && riskScore >= 40) {
      // eslint-disable-next-line no-console
      console.warn(`[RepoShield] verdict=safe 인데 riskScore=${riskScore} — verdict를 우선 표시합니다.`)
    }
  }

  return (
    <div className="panel">
      {repo && (
        <div className="panel__repo">
          <b>{repo.owner}/{repo.name}</b>
          {repo.url && (
            <a href={repo.url} target="_blank" rel="noopener noreferrer">{repo.url} ↗</a>
          )}
        </div>
      )}

      <VerdictBadge
        verdict={verdict}
        riskScore={riskScore}
        scanLimitedReason={scanLimitedReason}
        scannedFiles={scannedFiles}
      />

      <TrustSignalTable repo={repo} trust={signals?.trust} />

      <ScoreRadials scores={scores} />

      {summary && (
        <div className="summary">
          <b>요약</b>
          {summary}
        </div>
      )}

      {/* v2: 외부 인텔 + 보안 권고. enrichment 없어도 repo로 advisory는 조회(키 불필요). */}
      <EnrichmentPanel report={report} token={token} />

      <FindingList
        findings={findings}
        verdict={verdict}
        dangerLock={dangerLock}
        scannedFiles={scannedFiles}
        scanLimitedReason={scanLimitedReason}
        aiConfig={aiConfig}
      />
    </div>
  )
}
