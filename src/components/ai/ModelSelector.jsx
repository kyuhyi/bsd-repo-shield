import { useId, useState } from 'react'
import { AI_MODELS, looksLikeSlug } from '../../config/aiModels.js'

const CUSTOM = '__custom__'

/**
 * 모델 드롭다운 + 커스텀 슬러그 입력.
 * props: value(string 현재 슬러그), onChange(slug:string)=>void
 */
export default function ModelSelector({ value, onChange }) {
  const selectId = useId()
  // 현재 value가 목록에 있으면 그걸, 아니면 커스텀 모드.
  const known = AI_MODELS.some((m) => m.id === value)
  const [custom, setCustom] = useState(!known)

  const handleSelect = (e) => {
    const v = e.target.value
    if (v === CUSTOM) {
      setCustom(true)
      // 커스텀 진입 시 입력은 비워 사용자가 직접 채우게.
      onChange('')
    } else {
      setCustom(false)
      onChange(v)
    }
  }

  const customInvalid = custom && value.trim() !== '' && !looksLikeSlug(value)

  return (
    <div className="model-sel">
      <label className="model-sel__label" htmlFor={selectId}>모델</label>
      <select
        id={selectId}
        className="model-sel__select"
        value={custom ? CUSTOM : value}
        onChange={handleSelect}
      >
        {AI_MODELS.map((m) => (
          <option key={m.id} value={m.id}>
            {m.label}{m.hot ? ' 🔥' : ''} — {m.id}
          </option>
        ))}
        <option value={CUSTOM}>직접 입력…</option>
      </select>

      {custom && (
        <div className="model-sel__custom">
          <input
            className="model-sel__input"
            type="text"
            value={value}
            onChange={(e) => onChange(e.target.value)}
            placeholder="provider/model 예: anthropic/claude-opus-4.8"
            autoComplete="off"
            spellCheck={false}
            aria-invalid={customInvalid}
          />
          <p className="model-sel__hint">
            {customInvalid
              ? '형식이 provider/model 같지 않습니다. 그래도 그대로 호출은 시도합니다.'
              : '임의 OpenRouter 슬러그 입력 가능. 목록: openrouter.ai/models'}
          </p>
        </div>
      )}
    </div>
  )
}
