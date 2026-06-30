import { useState } from 'react'
import ApiKeyInput, { readStoredKey } from './ApiKeyInput.jsx'
import ModelSelector from './ModelSelector.jsx'
import { DEFAULT_MODEL } from '../../config/aiModels.js'

// AI 설정 상태를 한곳에서 관리하는 훅. App이 호출해 finding 카드로 내려보낸다.
export function useAiConfig() {
  const [apiKey, setApiKey] = useState(() => readStoredKey() || '')
  const [model, setModel] = useState(DEFAULT_MODEL)
  return { apiKey, setApiKey, model, setModel }
}

/**
 * 접이식 AI 설정 패널 (키 + 모델). 결과 패널 상단에 위치.
 * props: config(useAiConfig 반환), defaultOpen(bool)
 */
export default function AiSettings({ config, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen)
  const ready = Boolean(config.apiKey?.trim())

  return (
    <div className="ai-settings card-block">
      <button
        type="button"
        className="ai-settings__head"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
      >
        <span className="ai-settings__title">
          <span aria-hidden="true">🤖</span> AI 코드 해설
          <span className={`ai-settings__state ${ready ? 'is-on' : 'is-off'}`}>
            {ready ? '활성' : '키 필요'}
          </span>
        </span>
        <span className="ai-settings__caret" data-open={open}>▾</span>
      </button>

      {open && (
        <div className="ai-settings__body">
          <p className="ai-settings__intro">
            본인 OpenRouter 키로 의심 코드를 AI가 풀어 설명합니다(선택 기능). 키가 없어도 룰 기반
            탐지는 그대로 동작하며, 각 항목의 <b>🤖 AI 해설</b> 버튼만 비활성화됩니다.
          </p>
          <ApiKeyInput value={config.apiKey} onChange={config.setApiKey} />
          <ModelSelector value={config.model} onChange={config.setModel} />
        </div>
      )}
    </div>
  )
}
