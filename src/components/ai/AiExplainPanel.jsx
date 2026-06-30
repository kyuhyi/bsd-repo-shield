import { useEffect, useRef, useState } from 'react'
import { explainStream } from '../../config/aiExplain.js'

// 한 finding에 대한 AI 해설 버튼 + 패널.
// - 키 미입력이면 버튼 비활성 + 안내.
// - 스트리밍 점진 표시, AbortController 취소.
// - AI가 '안전'이라 해도 우리 룰 판정(verdict/severity/dangerLock)을 덮지 않음 — 둘 다 표기.
//
// props: finding, aiConfig { apiKey, model }, verdictLabel(string), dangerLock(bool)
export default function AiExplainPanel({ finding, aiConfig, verdictLabel, dangerLock }) {
  const [open, setOpen] = useState(false)
  const [text, setText] = useState('')
  const [phase, setPhase] = useState('idle') // idle | loading | streaming | done | error | aborted
  const [error, setError] = useState(null)    // { message, raw }
  const ctrlRef = useRef(null)

  const apiKey = aiConfig?.apiKey?.trim() || ''
  const model = aiConfig?.model?.trim() || ''
  const ready = Boolean(apiKey) && Boolean(model)

  // 언마운트 시 진행 중 호출 취소.
  useEffect(() => () => { ctrlRef.current?.abort() }, [])

  const run = async () => {
    if (!ready) return
    // 이전 호출이 있으면 취소.
    ctrlRef.current?.abort()
    const ctrl = new AbortController()
    ctrlRef.current = ctrl
    setOpen(true)
    setText('')
    setError(null)
    setPhase('loading')

    try {
      let started = false
      const finalText = await explainStream({
        apiKey,
        model,
        finding,
        signal: ctrl.signal,
        onChunk: (delta) => {
          if (!started) { started = true; setPhase('streaming') }
          setText((t) => t + delta)
        },
      })
      // onChunk가 한 번도 안 불렸지만(논스트림 폴백) 텍스트가 온 경우.
      if (!started && finalText) setText(finalText)
      setPhase('done')
    } catch (e) {
      if (e?.name === 'AbortError') {
        setPhase('aborted')
        return
      }
      setError({ message: e?.message || 'AI 호출에 실패했습니다.', raw: e?.raw || '' })
      setPhase('error')
    } finally {
      if (ctrlRef.current === ctrl) ctrlRef.current = null
    }
  }

  const cancel = () => {
    ctrlRef.current?.abort()
    ctrlRef.current = null
    setPhase('aborted')
  }

  const busy = phase === 'loading' || phase === 'streaming'

  return (
    <div className="ai-explain">
      <div className="ai-explain__bar">
        <button
          type="button"
          className="ai-explain__btn"
          onClick={busy ? cancel : run}
          disabled={!ready && !busy}
          aria-expanded={open}
          title={ready ? '이 코드를 AI가 풀어 설명' : 'OpenRouter 키를 입력하면 활성화됩니다'}
        >
          <span aria-hidden="true">🤖</span>
          {busy ? 'AI 해설 취소' : (phase === 'done' || phase === 'error') ? 'AI 해설 다시' : 'AI 해설'}
        </button>
        {!ready && (
          <span className="ai-explain__locked">
            OpenRouter 키를 넣으면 의심 코드를 AI가 풀어 설명합니다.
          </span>
        )}
      </div>

      {open && (
        <div className="ai-explain__panel" role="region" aria-label="AI 해설">
          {/* 우리 룰 판정은 AI와 무관하게 항상 함께 표기 — AI가 안전이라 해도 덮지 않음 */}
          <div className="ai-explain__verdict-note">
            <span className="ai-explain__chip">RepoShield 판정</span>
            <span>
              우리 룰: <b>{verdictLabel}</b>
              {dangerLock && <b className="ai-explain__lock"> · 절대 clone 금지(dangerLock)</b>}
              <span className="ai-explain__muted"> — AI 의견과 다르면 둘 다 보고 직접 판단하세요. 안전성 도구는 보수적으로 유지됩니다.</span>
            </span>
          </div>

          {busy && (
            <div className="ai-explain__status">
              <span className="spin" aria-hidden="true" />
              {phase === 'loading' ? '모델 응답 대기 중…' : '해설 생성 중…'}
            </div>
          )}

          {text && (
            <div className="ai-explain__text">
              {text}
              {phase === 'streaming' && <span className="ai-explain__cursor" aria-hidden="true">▍</span>}
            </div>
          )}

          {phase === 'aborted' && !busy && (
            <div className="ai-explain__status ai-explain__status--muted">취소되었습니다.</div>
          )}

          {phase === 'error' && error && (
            <div className="ai-explain__error" role="alert">
              <div className="ai-explain__error-msg">⚠ {error.message}</div>
              {error.raw && (
                <pre className="ai-explain__error-raw"><code>{error.raw}</code></pre>
              )}
              <button type="button" className="ai-explain__retry" onClick={run}>다시 시도</button>
            </div>
          )}

          {phase === 'done' && !error && (
            <div className="ai-explain__footnote">
              🤖 AI 보조 의견입니다. 사실과 다를 수 있으니 코드를 직접 확인하세요.
            </div>
          )}
        </div>
      )}
    </div>
  )
}
