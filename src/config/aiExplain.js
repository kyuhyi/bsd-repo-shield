// src/config/aiExplain.js — OpenRouter 직접 호출 유틸 (브라우저에서만, CORS 허용).
//
// 보안 제1원칙(이 도구의 존재 이유):
//   - apiKey는 오직 https://openrouter.ai 로만 전송한다. 우리 서버(없음)·로깅·분석 어디로도 보내지 않는다.
//   - 이 모듈은 apiKey를 console에 찍지 않으며, 에러 메시지에도 키를 절대 포함하지 않는다.
//   - 키는 호출 인자로만 받고 모듈 스코프에 보관하지 않는다(메모리 잔류 최소화).

const ENDPOINT = 'https://openrouter.ai/api/v1/chat/completions'

const SYSTEM_PROMPT =
  '너는 보안 분석가다. 주어진 코드 조각이 실제로 무슨 동작을 하는지 비전문가도 ' +
  '이해하게 한국어로 설명하라. 특히 외부 전송·시크릿 접근·코드 실행 여부를 명확히 하라. ' +
  '과장이나 공포 조장 없이 사실에 기반해 설명하고, 확실치 않으면 "불확실"이라고 말하라. ' +
  '4~6문장 이내로 간결하게.'

// finding → 사용자 프롬프트.
export function buildUserPrompt(finding) {
  const f = finding || {}
  const file = f.file || '(파일 미상)'
  const line = f.line != null ? `:${f.line}` : ''
  const snippet = f.snippet ? f.snippet : '(코드 조각 없음 — 메타데이터 기반 탐지)'
  const why = f.description || '(설명 없음)'
  const cat = f.category || '(미분류)'
  return [
    `다음은 정적 분석 도구가 의심스럽다고 표시한 코드다.`,
    ``,
    `위치: ${file}${line}`,
    `우리 룰이 분류한 카테고리: ${cat}`,
    `우리 룰이 의심한 이유: ${why}`,
    ``,
    `코드 조각:`,
    '```',
    snippet,
    '```',
    ``,
    `이 코드가 실제로 위험한가? 무엇을 하는가? 위에서 짚은 동작(외부 전송·시크릿 접근·코드 실행)이 있는지 사실 기반으로 설명하라.`,
  ].join('\n')
}

// OpenRouter 권장 헤더 + Authorization. 키는 여기서만 쓰이고 반환·로깅되지 않는다.
function buildHeaders(apiKey) {
  return {
    Authorization: `Bearer ${apiKey}`,
    'Content-Type': 'application/json',
    // OpenRouter 권장(랭킹/식별용, 선택). 우리 도메인만 노출(키 아님).
    'HTTP-Referer': typeof location !== 'undefined' ? location.origin : 'https://reposhield.local',
    'X-Title': 'RepoShield',
  }
}

// 상태코드 → 사용자 안내(원문 status/text는 별도 보존). 키는 절대 포함 안 함.
function statusHint(status) {
  switch (status) {
    case 401: return '키 오류(401): API 키가 올바른지 확인하세요.'
    case 402: return '잔액 부족(402): OpenRouter 크레딧을 확인하세요.'
    case 403: return '권한 거부(403): 이 키로 해당 모델에 접근할 수 없을 수 있습니다.'
    case 404: return '모델 없음(404): 모델 슬러그가 OpenRouter에 없습니다. 다른 모델을 선택하세요.'
    case 429: return '요청 한도(429): 잠시 후 다시 시도하세요.'
    default: return status >= 500 ? `OpenRouter 서버 오류(${status})` : `요청 실패(${status})`
  }
}

/**
 * 비스트리밍 호출. 성공 시 전체 텍스트 반환.
 * @returns {Promise<string>}
 */
export async function explainOnce({ apiKey, model, finding, signal }) {
  let res
  try {
    res = await fetch(ENDPOINT, {
      method: 'POST',
      signal,
      headers: buildHeaders(apiKey),
      body: JSON.stringify({
        model,
        messages: [
          { role: 'system', content: SYSTEM_PROMPT },
          { role: 'user', content: buildUserPrompt(finding) },
        ],
      }),
    })
  } catch (e) {
    if (e?.name === 'AbortError') throw e
    const err = new Error('네트워크 오류: OpenRouter에 연결하지 못했습니다.')
    err.code = 'network'
    throw err
  }
  if (!res.ok) {
    let body = ''
    try { body = await res.text() } catch { /* ignore */ }
    const err = new Error(statusHint(res.status))
    err.code = String(res.status)
    err.raw = body // 원문(키 미포함) — UI에서 그대로 표시 가능.
    throw err
  }
  const data = await res.json()
  return data?.choices?.[0]?.message?.content ?? ''
}

/**
 * 스트리밍 호출. onChunk(delta:string)로 점진 전달. 미지원/실패 시 explainOnce로 폴백 가능.
 * SSE(text/event-stream)를 직접 파싱.
 * @returns {Promise<string>} 최종 누적 텍스트
 */
export async function explainStream({ apiKey, model, finding, signal, onChunk }) {
  let res
  try {
    res = await fetch(ENDPOINT, {
      method: 'POST',
      signal,
      headers: buildHeaders(apiKey),
      body: JSON.stringify({
        model,
        stream: true,
        messages: [
          { role: 'system', content: SYSTEM_PROMPT },
          { role: 'user', content: buildUserPrompt(finding) },
        ],
      }),
    })
  } catch (e) {
    if (e?.name === 'AbortError') throw e
    const err = new Error('네트워크 오류: OpenRouter에 연결하지 못했습니다.')
    err.code = 'network'
    throw err
  }

  if (!res.ok) {
    let body = ''
    try { body = await res.text() } catch { /* ignore */ }
    const err = new Error(statusHint(res.status))
    err.code = String(res.status)
    err.raw = body
    throw err
  }

  // 스트림 본문이 없으면(드물게) 일반 JSON으로 폴백.
  if (!res.body || typeof res.body.getReader !== 'function') {
    const data = await res.json().catch(() => null)
    const text = data?.choices?.[0]?.message?.content ?? ''
    if (text && typeof onChunk === 'function') onChunk(text)
    return text
  }

  const reader = res.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  let acc = ''

  // SSE: "data: {json}\n\n", 종료 마커 "data: [DONE]".
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })

    let idx
    while ((idx = buffer.indexOf('\n')) !== -1) {
      const rawLine = buffer.slice(0, idx)
      buffer = buffer.slice(idx + 1)
      const line = rawLine.trim()
      if (!line || line.startsWith(':')) continue // 빈 줄·코멘트(keep-alive)
      if (!line.startsWith('data:')) continue
      const payload = line.slice(5).trim()
      if (payload === '[DONE]') return acc
      try {
        const json = JSON.parse(payload)
        const delta = json?.choices?.[0]?.delta?.content
        if (delta) {
          acc += delta
          if (typeof onChunk === 'function') onChunk(delta)
        }
      } catch {
        /* 부분 청크(아직 완성 안 된 JSON)는 무시하고 다음 줄로 */
      }
    }
  }
  return acc
}
