import { useCallback, useRef, useState } from 'react'
import logoUrl from './assets/bsdlogo.png'
import { GooeyText } from './components/GooeyText.jsx'
import { verifyRepo } from './engine/index.js'
import { TRENDING_SITES } from './data/sites.js'
import UrlInput from './components/UrlInput.jsx'
import ScanProgress from './components/ScanProgress.jsx'
import VerdictPanel from './components/VerdictPanel.jsx'
import DangerOverlay from './components/DangerOverlay.jsx'
import LauncherCard from './components/LauncherCard.jsx'
import AiSettings, { useAiConfig } from './components/ai/AiSettings.jsx'

// 엔진 err.code → 사용자 메시지.
const ERROR_COPY = {
  invalid_url: {
    title: '올바른 GitHub URL이 아닙니다',
    body: 'https://github.com/owner/repo 형식으로 공개 저장소 주소를 입력해 주세요.',
  },
  not_found: {
    title: '저장소를 찾을 수 없습니다',
    body: '존재하지 않거나 비공개 저장소일 수 있습니다. 주소를 다시 확인해 주세요.',
  },
  rate_limit: {
    title: 'GitHub API 호출 한도 초과',
    body: '잠시 후 다시 시도하거나, 토큰을 입력하면 한도가 늘어납니다.',
  },
  network: {
    title: '네트워크 오류',
    body: '인터넷 연결을 확인한 뒤 다시 시도해 주세요.',
  },
}

// 상태 머신: idle → loading → (partial | success | error)
export default function App() {
  const [status, setStatus] = useState('idle') // idle | loading | success | partial | error
  const [report, setReport] = useState(null)
  const [error, setError] = useState(null)
  const [progress, setProgress] = useState(null)
  const [dangerOpen, setDangerOpen] = useState(false)
  const [activeToken, setActiveToken] = useState(undefined) // 보안 권고 조회 한도 완화용(선택)
  const lastArgs = useRef(null)

  // AI 해설 설정(키/모델) — 메모리 보관, finding 카드로 전달. 키는 OpenRouter로만 직접 전송.
  const aiConfig = useAiConfig()

  const run = useCallback(async (url, token) => {
    lastArgs.current = { url, token }
    setActiveToken(token || undefined)
    setStatus('loading')
    setReport(null)
    setError(null)
    setProgress(null)
    setDangerOpen(false)

    try {
      const result = await verifyRepo(url, {
        token,
        onProgress: (p) => setProgress(p),
      })
      setReport(result)
      // scanLimitedReason 있으면 partial (success로 취급 금지).
      setStatus(result?.scanLimitedReason ? 'partial' : 'success')
      if (result?.dangerLock === true) setDangerOpen(true)
    } catch (err) {
      const code = err?.code && ERROR_COPY[err.code] ? err.code : 'network'
      setError({ code, message: err?.message })
      setStatus('error')
    }
  }, [])

  const retry = () => {
    if (lastArgs.current) run(lastArgs.current.url, lastArgs.current.token)
  }

  const loading = status === 'loading'
  const showPanel = (status === 'success' || status === 'partial') && report
  const ec = error ? (ERROR_COPY[error.code] || ERROR_COPY.network) : null

  return (
    <div className="app">
      <header className="app__header">
        <img className="brand-logo" src={logoUrl} alt="RepoShield 로고" />
        <div className="brand-text">
          <h1>Repo<b>Shield</b></h1>
          <p>git clone 전에 저장소 안전성을 3초 안에 판단</p>
        </div>
      </header>

      {/* ---------- 상단: 보안 검증기 ---------- */}
      <section className="verifier" aria-label="GitHub 저장소 보안 검증기">
        <div className="hero__gooey" aria-hidden="true">
          <GooeyText
            texts={['Reliability', 'Stability', 'Suitability', 'Risk level']}
            morphTime={1}
            cooldownTime={0.25}
          />
        </div>
        <div className="hero__eyebrow">Security Verifier</div>
        <h2 className="hero__title">이 저장소, clone 해도 될까요?</h2>
        <p className="hero__sub">
          GitHub 공개 저장소 URL을 입력하면 API 키 탈취·악성 설치 스크립트·원격 코드 실행 등
          위험 패턴을 정적 분석하고 신호등으로 알려드립니다. 코드를 내려받기 전에 확인하세요.
        </p>

        <UrlInput onSubmit={run} loading={loading} />

        {loading && <ScanProgress progress={progress} />}

        {status === 'error' && ec && (
          <div className="verify-error" role="alert">
            <span className="verify-error__icon" aria-hidden="true">!</span>
            <div>
              <h3>{ec.title}</h3>
              <p>{ec.body}</p>
              <button type="button" className="retry" onClick={retry}>다시 시도</button>
            </div>
          </div>
        )}

        {showPanel && (
          <div className="panel-wrap">
            <AiSettings config={aiConfig} />
            <VerdictPanel report={report} aiConfig={aiConfig} token={activeToken} />
          </div>
        )}
      </section>

      {/* ---------- 하단: 트렌딩 런처 ---------- */}
      <div className="section-divider">Trending Launcher</div>
      <section aria-label="트렌딩 사이트 런처">
        <div className="launcher-marquee">
          {/* 한 줄 무한 좌측 슬라이드. 끊김 없는 루프를 위해 카드 2벌 복제(복제본은 a11y 제외). 호버 시 정지. */}
          <div className="launcher-track">
            {TRENDING_SITES.map((site) => (
              <LauncherCard key={site.url} site={site} />
            ))}
            {TRENDING_SITES.map((site) => (
              <LauncherCard key={`dup-${site.url}`} site={site} hidden />
            ))}
          </div>
        </div>
      </section>

      <footer className="app__footer">
        <b>RepoShield</b> · 백엔드 없이 브라우저에서 GitHub 공개 API로 검증합니다. 결과는 휴리스틱 정적 분석이며 최종 판단은 사용자에게 있습니다.
      </footer>

      {/* 전체화면 위험 경고 — dangerLock === true 일 때만 */}
      <DangerOverlay
        show={dangerOpen}
        onClose={() => setDangerOpen(false)}
        reason={report?.summary}
        repoName={report?.repo ? `${report.repo.owner}/${report.repo.name}` : undefined}
      />
    </div>
  )
}
