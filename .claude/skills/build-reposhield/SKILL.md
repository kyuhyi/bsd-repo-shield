---
name: build-reposhield
description: RepoShield 웹앱(GitHub 저장소 clone 전 보안 검증기 + 6개 트렌딩 사이트 3D 카드 런처)을 에이전트 팀으로 개발·확장하는 오케스트레이터. "오픈소스/깃허브 검증 도구 만들어", "RepoShield 개발/이어서/수정", "보안 검증기 만들어", "트렌딩 런처 추가", "다시 실행/재실행/업데이트/보완", "검증 룰 추가", "UI 개선" 등 이 앱 관련 모든 개발 요청에 사용. 단순 질문은 팀 없이 직접 답해도 무방.
---

# Build RepoShield — 오케스트레이터

RepoShield는 React+Vite 단일 페이지 앱이다. 백엔드 없이 브라우저에서 GitHub 공개 API로 저장소를 검증한다.
- **상단:** GitHub URL 보안 검증기 — clone 전에 API키 탈취·스미싱·악성 설치스크립트를 정적 분석해 위험을 시각화.
- **하단:** 6개 트렌딩 사이트(Product Hunt·Trendshift·GitHub Trending·Star History·GitStar Ranking·OSS Insight) 3D 카드 런처 — 빛반사·호버 모션.

## 실행 모드: 에이전트 팀 (3명)

| 에이전트 | 역할 | 타입/모델 |
|---------|------|----------|
| `security-engine-builder` | 검증 엔진(GitHub API + 탐지 + 스코어) — VerdictReport 생산 | custom / opus |
| `frontend-builder` | React UI, 결과 시각화, 3D 카드 런처 — VerdictReport 소비 | custom / opus |
| `qa-integrator` | 경계면 교차검증 + 빌드/실행 검증 | general-purpose / opus |

모든 `Agent`/팀 호출에 `model: "opus"` 명시.

## Phase 0: 컨텍스트 확인 (먼저 실행)

1. `_workspace/`, `src/`, `package.json` 존재 확인.
2. 분기:
   - 미존재 → **초기 빌드**(아래 전체 Phase).
   - 존재 + 부분 수정 요청("UI만", "룰만") → **부분 재실행**(해당 에이전트만 재호출, 계약 유지).
   - 존재 + 새 요구/대규모 변경 → **새 실행**(기존 `_workspace/`를 `_workspace_prev/`로 이동 후 진행).
3. 사용자 숙련도에 맞춰 톤 조절(비전문가면 용어 풀어 설명).

## 워크플로우 (초기 빌드)

1. **팀 구성** — `TeamCreate`로 위 3명 구성. 리더는 오케스트레이터.
2. **계약 합의** — 아래 `## 공유 데이터 계약`을 팀에 공지. 모든 에이전트가 이 VerdictReport를 단일 진실원으로 삼는다.
3. **병렬 빌드 (TaskCreate):**
   - `security-engine-builder`: `github-threat-detection` 스킬로 `src/engine/` 구현 + 샘플 VerdictReport(`_workspace/sample_verdict.json`: safe/caution/danger 3종) 생성.
   - `frontend-builder`: `secure-ui-design` 스킬로 React 앱 스캐폴드 + 결과 시각화 + 3D 런처 구현. 엔진 인터페이스에 연결.
   - 두 빌더는 계약 변경 시 `SendMessage`로 상호 통지.
4. **점진적 QA** — 각 모듈 완성 직후 `qa-integrator`가 경계면 대조(샘플 VerdictReport ↔ 프론트 props). 불일치는 담당자에게 반려.
5. **엔드투엔드** — 실제 URL로 빌드·실행 검증. 안전 저장소 1개 + 의심 패턴 테스트 케이스 1개로 회귀.
6. **종합 보고** — 리더가 결과 요약, 실행 방법(`npm run dev`) 안내.
7. **피드백 수집** — "개선/추가할 점?" 묻고, Phase 7(진화) 경로로 반영.

## 공유 데이터 계약 — `VerdictReport`

**이것이 보안엔진과 프론트의 유일한 경계면이다. 양측 합의 없이 변경 금지. QA는 이 계약을 기준으로 검증한다.**

```ts
type Verdict = 'safe' | 'caution' | 'danger';
type Severity = 'low' | 'medium' | 'high' | 'critical';
type Category = 'secret-exfiltration' | 'install-hook' | 'remote-code-exec'
             | 'obfuscation' | 'suspicious-network' | 'crypto-miner'
             | 'dependency-risk'      // 악성 패키지/타이포스쿼팅(악성 의도) — danger/dangerLock 가능
             | 'dependency-hygiene'   // 일반 의존성 CVE(공급망 위생) — 최대 caution, dangerLock 제외
             | 'source-mismatch';     // v2: GitHub ≠ 게시 패키지

interface Finding {
  id: string;
  category: Category;
  severity: Severity;
  title: string;          // 짧은 제목(한국어)
  description: string;    // "왜 위험한가" 일상어 한국어 1문장
  file: string;           // 예: "package.json"
  line: number | null;    // 모르면 null
  snippet: string;        // 코드 조각(없으면 "")
  rule: string;           // 룰 ID
}
interface TrustSignal { label: string; value: string; weight: string; } // 예: {label:"스타", value:"12.3k", weight:"+신뢰"}

interface VerdictReport {
  repo: {
    url: string; owner: string; name: string; defaultBranch: string;
    stars: number; forks: number; createdAt: string; pushedAt: string;
    license: string | null; archived: boolean;
  };
  riskScore: number;              // 0~100 종합 위험 (= scores.risk와 동기화)
  scores: {                       // 4축 점수, 각 0~100 정수. UI 원형 그래프로 표시
    trust: number;                // 신뢰도 (높을수록 좋음): 스타·포크·나이·라이선스·기여자
    stability: number;            // 안정성 (높을수록 좋음): 최근활동·이슈비율·릴리스·아카이브여부
    suitability: number;          // 적합성 (높을수록 좋음): 테스트·문서·CI·lockfile 등 코드위생
    risk: number;                 // 위험도 (높을수록 나쁨): findings 기반
  };
  verdict: Verdict;               // 신호등
  dangerLock: boolean;            // true면 UI가 전체화면 빨강 경고(깜빡임). 절대 clone 금지 수준.
  summary: string;                // 한국어 1~2문장
  findings: Finding[];            // 심각도순 정렬, 0건 가능
  signals: { trust: TrustSignal[] };
  scannedFiles: number;           // 실제 검사한 파일 수
  scanLimitedReason: string | null; // 전부 검사 못 했으면 사유, 아니면 null
  enrichment?: {                    // v2: 외부 인텔 강화(선택, 조회 실패 시 생략). 상세: github-threat-detection/references/external-intel.md
    supplyChain?: { ecosystem: string; checked: number; vulnerable: {name:string;advisory:string;severity:Severity}[]; typosquat: string[] };
    sourceMismatch?: { registry: string|null; repoMatches: boolean|null; note: string };
    forensics?: { ownerCreatedAt: string|null; contributors: number|null; flags: string[] };
    secrets?: { count: number; samples: {file:string;kind:string}[] };
    intelErrors?: string[];         // 조회 실패 소스(정직성). 있으면 UI "일부 외부조회 실패" 표기
  };
}
```

> **v2 강화(전부 개발 예정):** #1 공급망(OSV/deps.dev/npm), #2 source-mismatch, #3 커밋·소유자 포렌식, #4 엔트로피·시크릿 스캔 → `github-threat-detection/references/external-intel.md`. #5 사용자 OpenRouter 키 기반 AI 코드해설 + 보안권고 → `secure-ui-design/references/ai-explainer.md`. v1(룰 기반 코어) 완성·QA 후 v2 라운드로 추가한다. enrichment 필드는 후방호환(미지원 시 생략).

계약 불변식(QA 체크리스트):
- `verdict`/`severity`/`category`는 정의된 enum만.
- `scanLimitedReason`이 string이면 UI는 "일부 미검사" 표식 필수.
- `findings` 비어도 `verdict`가 danger일 수 있다(신뢰 신호 기반). UI는 `verdict`를 따른다.
- 숫자 필드는 number, 모르는 line은 `null`(undefined 금지).
- critical finding 존재 시 `riskScore ≥ 70`, `verdict='danger'` (스코어 모델 일관성).
- `scores`의 trust/stability/suitability는 높을수록 좋음, risk는 높을수록 나쁨(=riskScore).
- `dangerLock=true` 조건: `riskScore ≥ 85` 또는 critical finding 존재. 이때 UI는 전체화면 빨강 깜빡임 경고를 띄운다. dangerLock이면 verdict는 반드시 'danger'.

## 데이터 전달 프로토콜

- **태스크 기반**(`TaskCreate`/`TaskUpdate`): 진행/의존 관리.
- **파일 기반**(`_workspace/`): `sample_verdict.json`(엔진→프론트/QA), `qa_report.md`(QA→전체), 엔진 인터페이스 메모. 명명: `{phase}_{agent}_{artifact}.{ext}`.
- **메시지 기반**(`SendMessage`): 계약 변경·경계면 반려 등 실시간 소통.
- 최종 산출물은 `src/`(앱 코드)·루트(`package.json`,`vite.config`,`index.html`). 중간물 `_workspace/`는 보존.

## 에러 핸들링

- 에이전트 실패 → 1회 재시도, 재실패 시 해당 산출물 없이 진행하되 **최종 보고에 누락 명시**.
- 계약 충돌(두 빌더가 다른 shape 주장) → 삭제하지 말고 양측 주장 병기해 리더가 중재.
- 빌드 실패 → QA가 로그 첨부, 원인 라인 지목 후 담당자 반려.

## 테스트 시나리오

- **정상 흐름:** 유명 안전 저장소 URL 입력 → 엔진이 safe VerdictReport 생산 → 프론트가 초록 신호등+신뢰 배지 표시 → QA가 경계면·실행 통과.
- **에러 흐름:** rate limit 초과 → 엔진이 partial 결과 + `scanLimitedReason` 반환 → 프론트가 verdict + "일부 미검사" 배지 동시 표시(초록 단독 표시 금지) → QA가 "미검사를 안전으로 오인하지 않는지" 확인.

## 후속/진화

- 부분 요청은 해당 에이전트만 재호출(계약 유지). 룰 추가→`security-engine-builder`, UI→`frontend-builder`.
- 반복 피드백·반복 실패 패턴 발견 시 하네스 진화 제안. 모든 변경은 CLAUDE.md 변경 이력에 기록.
