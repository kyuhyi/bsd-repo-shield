# AI Explainer — 사용자 키 기반 AI 코드 해설 + 보안 권고 (v2, #5)

의심 코드를 **자연어로 "이게 실제 뭘 하는지"** 설명해 비전문가도 판단하게 한다. 사용자가 **본인 OpenRouter API 키**를 입력해 사용(선택 기능). 키 없으면 #1~#4 룰/DB 탐지는 그대로 동작하고, AI 해설 버튼만 비활성.

목차: 1) 키 입력 UX·보안 2) 모델 선택 3) OpenRouter 호출 4) 해설 프롬프트 5) 보안 권고 조회 6) 폴백

---

## 1. 키 입력 UX · 보안 (가장 중요)

우리는 **키 유출을 막는 도구**다. 우리 스스로 키를 새면 자기모순 → 엄격히:
- 키는 **브라우저 메모리에만**. 기본은 미저장. "이 기기에 저장" 옵션 선택 시에만 localStorage, "지우기" 버튼 제공.
- 키는 **openrouter.ai 외 어디로도 전송 금지**. 로깅/분석/우리 서버(없음) 전송 절대 금지.
- 입력 필드는 `type="password"`, 붙여넣기 허용, 화면에 마스킹.
- 안내 문구: "키는 당신 브라우저에서 OpenRouter로만 직접 전송되며 저장되지 않습니다."

## 2. 모델 선택 (가장 핫한 모델 + 커스텀)

드롭다운으로 "핫한" 모델 제공 + 직접 입력. **슬러그는 `src/config/aiModels.js`에 모아 두어 쉽게 갱신**(모델 가용성은 자주 바뀜 — 실제 슬러그는 openrouter.ai/models에서 확인해 맞춘다):

```js
// src/config/aiModels.js — 슬러그는 OpenRouter 기준. 변동 시 여기만 수정.
export const AI_MODELS = [
  { label: 'Claude Opus 4.8', id: 'anthropic/claude-opus-4.8', hot: true },
  { label: 'Codex 5.5',       id: 'openai/gpt-5.5-codex',       hot: true },
  { label: 'GPT-5.5',         id: 'openai/gpt-5.5',             hot: true },
]
export const DEFAULT_MODEL = 'anthropic/claude-opus-4.8'
// + UI에 "직접 입력" 옵션으로 임의 슬러그 허용
```
> 슬러그가 OpenRouter에 없으면 호출이 404/400을 준다. 그 경우 에러를 사용자에게 그대로 보여주고 다른 모델 선택을 유도(임의 폴백으로 다른 모델 과금 금지).

## 3. OpenRouter 호출 (브라우저 직접, CORS 허용)

```js
async function explain({ apiKey, model, prompt, signal }) {
  const res = await fetch('https://openrouter.ai/api/v1/chat/completions', {
    method: 'POST', signal,
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      'HTTP-Referer': location.origin,   // OpenRouter 권장(랭킹/식별용, 선택)
      'X-Title': 'RepoShield',
    },
    body: JSON.stringify({ model, messages: [
      { role: 'system', content: SYSTEM_PROMPT },
      { role: 'user', content: prompt },
    ]}),
  });
  if (!res.ok) throw new Error(`AI ${res.status}: ${await res.text()}`);
  const data = await res.json();
  return data.choices?.[0]?.message?.content ?? '';
}
```
- 가능하면 스트리밍(`stream:true`, SSE 파싱)으로 해설을 점진 표시. 미지원 시 일반 호출.
- 호출 실패(401 키오류/402 잔액/429 한도/404 모델)는 **사용자에게 원문 표기** + 재시도/모델변경 안내.

## 4. 해설 프롬프트 (의심 snippet → 한국어 설명)

SYSTEM: "너는 보안 분석가다. 주어진 코드 조각이 실제로 무슨 동작을 하는지 비전문가도 이해하게 한국어로 설명하라. 특히 외부 전송·시크릿 접근·코드 실행 여부를 명확히. 과장/공포조장 없이 사실 기반으로. 확실치 않으면 '불확실'이라 말하라."
USER: finding의 `{file}`, `{snippet}`, 우리 룰이 의심한 이유(`{description}`, `{category}`)를 제공하고 "이 코드가 실제 위험한가? 무엇을 하는가?"를 묻는다.

→ 결과를 finding 카드 안 "🤖 AI 해설" 섹션에 표시. 우리 룰 판정과 AI 의견이 **다르면 둘 다 보여주고** 사용자가 판단하게(어느 쪽도 절대 진실로 단정 안 함).

## 5. 보안 권고 조회 (AI와 별개, 키 불필요)

GitHub/OSV의 **이미 알려진 권고**를 함께 표시:
- `GET https://api.github.com/repos/{o}/{r}/security-advisories` (있으면)
- OSV는 external-intel.md의 공급망 조회 결과 재사용.
→ "이 저장소/패키지에 이미 보고된 보안 권고" 배지. 키 없이 동작하므로 기본 노출.

## 6. 폴백 / 접근성

- 키 미입력: AI 버튼 비활성 + "OpenRouter 키를 넣으면 의심 코드를 AI가 풀어 설명합니다" 안내.
- 호출 중: 로딩 인디케이터 + 취소(AbortController).
- AI 응답은 보조 정보다. **AI가 '안전'이라 해도 우리 룰의 danger/dangerLock을 덮지 않는다** — 안전성 도구의 보수성 유지.
