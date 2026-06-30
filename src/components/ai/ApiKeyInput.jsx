import { useEffect, useId, useRef, useState } from 'react'

// localStorage 키. "이 기기에 저장"을 선택했을 때만 사용.
const STORAGE_KEY = 'reposhield.openrouter.key'

// 저장된 키를 읽는다(저장된 적 없으면 null). 외부에서도 초기값으로 쓸 수 있게 export.
export function readStoredKey() {
  try {
    return localStorage.getItem(STORAGE_KEY) || null
  } catch {
    return null
  }
}

/**
 * OpenRouter API 키 입력.
 * - type=password, 화면 마스킹, 붙여넣기 허용.
 * - 기본 미저장(메모리만). "이 기기에 저장" 선택 시에만 localStorage + "지우기" 제공.
 * - 키는 onChange로 부모(메모리)에만 전달. 우리 어디로도 전송/로깅하지 않는다.
 *
 * props: value(string), onChange(key:string)=>void
 */
export default function ApiKeyInput({ value, onChange }) {
  const inputId = useId()
  const [reveal, setReveal] = useState(false)
  // 저장된 키가 이미 있으면 "저장" 체크 상태로 시작.
  const [persist, setPersist] = useState(() => readStoredKey() != null)
  const mounted = useRef(false)

  // 마운트 시 저장된 키가 있으면 부모로 끌어올린다(1회).
  useEffect(() => {
    if (mounted.current) return
    mounted.current = true
    const stored = readStoredKey()
    if (stored && !value) onChange(stored)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // persist 토글 또는 value 변경 시 저장 상태 반영.
  useEffect(() => {
    if (!mounted.current) return
    try {
      if (persist && value) {
        localStorage.setItem(STORAGE_KEY, value)
      } else {
        localStorage.removeItem(STORAGE_KEY)
      }
    } catch {
      /* 저장 실패(프라이빗 모드 등)는 조용히 무시 — 메모리값은 유지 */
    }
  }, [persist, value])

  const handleClear = () => {
    onChange('')
    try { localStorage.removeItem(STORAGE_KEY) } catch { /* ignore */ }
  }

  const hasKey = Boolean(value)

  return (
    <div className="apikey">
      <label className="apikey__label" htmlFor={inputId}>
        OpenRouter API 키
        <span className="apikey__opt">선택 · AI 해설용</span>
      </label>

      <div className="apikey__row">
        <div className="apikey__field">
          <input
            id={inputId}
            className="apikey__input"
            type={reveal ? 'text' : 'password'}
            value={value}
            onChange={(e) => onChange(e.target.value)}
            placeholder="sk-or-v1-..."
            autoComplete="off"
            autoCorrect="off"
            autoCapitalize="off"
            spellCheck={false}
            // 1Password 등 자동 채움이 키를 동기화하지 않도록 힌트.
            data-1p-ignore="true"
            data-lpignore="true"
          />
          <button
            type="button"
            className="apikey__reveal"
            onClick={() => setReveal((r) => !r)}
            aria-label={reveal ? '키 숨기기' : '키 보기'}
            title={reveal ? '키 숨기기' : '키 보기'}
          >
            {reveal ? '🙈' : '👁'}
          </button>
        </div>
        {hasKey && (
          <button type="button" className="apikey__clear" onClick={handleClear}>
            지우기
          </button>
        )}
      </div>

      <div className="apikey__foot">
        <label className="apikey__persist">
          <input
            type="checkbox"
            checked={persist}
            onChange={(e) => setPersist(e.target.checked)}
          />
          <span>이 기기에 저장</span>
        </label>
        <p className="apikey__note">
          🔒 키는 당신의 브라우저에서 <b>openrouter.ai로만 직접</b> 전송되며, 우리 서버로
          전송하거나 저장하지 않습니다. {persist
            ? '“이 기기에 저장”을 켜면 이 브라우저의 localStorage에만 보관됩니다.'
            : '기본은 메모리에만 두며 새로고침 시 사라집니다.'}
        </p>
      </div>
    </div>
  )
}
