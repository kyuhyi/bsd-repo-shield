import { useEffect, useState } from 'react'

// 토큰을 '이 기기에 저장'(opt-in)하면 localStorage에 보관 → 다음 방문에 자동 채움.
// 안전: read-only(권한 없는) 토큰 권장. 저장은 명시적 선택이며 언제든 지울 수 있다.
const TOKEN_KEY = 'reposhield.gh_token'

const storage = {
  get() {
    try { return localStorage.getItem(TOKEN_KEY) || '' } catch { return '' }
  },
  set(v) {
    try { localStorage.setItem(TOKEN_KEY, v) } catch { /* 프라이빗 모드 등 — 무시 */ }
  },
  remove() {
    try { localStorage.removeItem(TOKEN_KEY) } catch { /* 무시 */ }
  },
}

// URL 입력 + "검증" 버튼 + (선택) 토큰 입력.
export default function UrlInput({ onSubmit, loading }) {
  const [url, setUrl] = useState('')
  const saved = storage.get()
  const [token, setToken] = useState(saved)
  const [remember, setRemember] = useState(Boolean(saved))
  // 저장된 토큰이 있으면 토큰 영역을 펼친 채로 시작(자동 채움이 보이도록).
  const [showToken, setShowToken] = useState(Boolean(saved))

  // remember가 켜져 있으면 토큰 변경을 즉시 저장, 꺼지면 저장본 제거.
  useEffect(() => {
    if (remember && token.trim()) storage.set(token.trim())
    else if (!remember) storage.remove()
  }, [remember, token])

  const submit = (e) => {
    e.preventDefault()
    const u = url.trim()
    if (!u || loading) return
    onSubmit(u, token.trim() || undefined)
  }

  const clearSaved = () => {
    setToken('')
    setRemember(false)
    storage.remove()
  }

  return (
    <form className="url-form" onSubmit={submit}>
      <div className="url-row">
        <label className="url-field">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
            <path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.5 1.5" strokeLinecap="round" strokeLinejoin="round" />
            <path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.5-1.5" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <input
            className="url-input"
            type="text"
            inputMode="url"
            autoComplete="off"
            spellCheck="false"
            placeholder="https://github.com/owner/repo"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            aria-label="검증할 GitHub 저장소 URL"
            disabled={loading}
          />
        </label>
        <button className="btn-verify" type="submit" disabled={loading || !url.trim()}>
          {loading ? <span className="spin" aria-hidden="true" /> : (
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" aria-hidden="true">
              <path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z" strokeLinejoin="round" />
              <path d="M9 12l2 2 4-4" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          )}
          {loading ? '검증 중…' : '검증'}
        </button>
      </div>

      <button
        type="button"
        className="token-toggle"
        onClick={() => setShowToken((s) => !s)}
        aria-expanded={showToken}
      >
        {showToken ? '▾' : '▸'} GitHub 토큰 (선택 — rate limit 완화)
        {saved && !showToken && <span className="token-saved-dot" title="이 기기에 저장됨">● 저장됨</span>}
      </button>

      {showToken && (
        <div className="token-row">
          <input
            className="token-input"
            type="password"
            autoComplete="off"
            placeholder="ghp_… (권한 없는 read-only 토큰 권장)"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            aria-label="선택 GitHub 액세스 토큰"
            disabled={loading}
          />
          <div className="token-controls">
            <label className="token-remember">
              <input
                type="checkbox"
                checked={remember}
                onChange={(e) => setRemember(e.target.checked)}
              />
              이 기기에 저장 (다음부터 자동 입력)
            </label>
            {(token || saved) && (
              <button type="button" className="token-clear" onClick={clearSaved}>지우기</button>
            )}
          </div>
          <span className="token-hint">
            {remember
              ? '이 브라우저에만 저장됩니다. 공용 PC에서는 사용하지 마세요. 토큰은 GitHub API 호출에만 쓰이며 서버로 전송되지 않습니다.'
              : '토큰은 브라우저에서 GitHub API 호출에만 쓰이며 서버로 전송·저장되지 않습니다. 매번 입력이 번거로우면 위에서 “이 기기에 저장”을 켜세요.'}
          </span>
        </div>
      )}
    </form>
  )
}
