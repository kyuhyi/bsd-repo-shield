// src/config/aiModels.js — OpenRouter 모델 슬러그 모음.
//
// 모델 가용성은 자주 바뀐다. 슬러그가 OpenRouter에 없으면 호출이 404/400을 주며,
// 그 경우 우리는 에러 원문을 사용자에게 보여주고 다른 모델 선택을 유도한다(임의 폴백 금지).
// 변동 시 이 파일만 수정. 최신 목록: https://openrouter.ai/models
//
// 확인 시점(2026-06): openrouter.ai/api/v1/models 에서 아래 두 개는 실재 확인:
//   - anthropic/claude-opus-4.8   ✅ 확인됨
//   - openai/gpt-5.5              ✅ 확인됨
// "Codex 5.5"는 확인 시점에 OpenRouter 카탈로그에 해당 슬러그가 없었다(추정값).
// 실제 슬러그는 https://openrouter.ai/models 에서 확인해 교체할 것.

export const AI_MODELS = [
  { label: 'Claude Opus 4.8', id: 'anthropic/claude-opus-4.8', hot: true, note: 'OpenRouter 확인됨' },
  // 추정 슬러그 — OpenRouter에 아직 없을 수 있음. openrouter.ai/models에서 확인 후 교체.
  { label: 'Codex 5.5', id: 'openai/gpt-5.5-codex', hot: true, note: '추정 슬러그 · openrouter.ai/models에서 확인' },
  { label: 'GPT-5.5', id: 'openai/gpt-5.5', hot: true, note: 'OpenRouter 확인됨' },
]

export const DEFAULT_MODEL = 'anthropic/claude-opus-4.8'

// 사용자가 직접 입력한 임의 슬러그를 허용. 형식 가이드(provider/model)만 가볍게 검증.
export function looksLikeSlug(s) {
  return typeof s === 'string' && /^[\w.-]+\/[\w.:-]+$/.test(s.trim())
}
