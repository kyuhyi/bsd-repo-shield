# RepoShield

GitHub 저장소를 `git clone` 하기 **전에** 안전성을 검증하는 무료 웹 도구 + 트렌딩 사이트 런처.
React + Vite SPA. 백엔드 없음 — 브라우저에서 GitHub 공개 API로 직접 검증. 정적 호스팅 배포.

- **상단:** GitHub URL 입력 → API키 탈취/스미싱/악성 설치스크립트/원격코드실행을 정적 분석 → 위험도 신호등 시각화.
- **하단:** 6개 트렌딩 사이트(Product Hunt·Trendshift·GitHub Trending·Star History·GitStar Ranking·OSS Insight) 3D 카드 런처(빛반사·호버 모션).

---

## 하네스: 오픈소스 보안 검증 웹앱

**목표:** clone 전 정적 검증으로 스미싱/키탈취 저장소를 사용자가 비전문가여도 신호등처럼 즉시 판별하게 한다.

**에이전트 팀 (생성-검증 + 경계면 QA):**
| 에이전트 | 역할 |
|---------|------|
| `security-engine-builder` | GitHub API 클라이언트 + 악성/스미싱 탐지 룰셋 + 위험점수 엔진 (VerdictReport 생산) |
| `frontend-builder` | React+Vite UI, 검증결과 시각화, 3D 카드 런처 (VerdictReport 소비) |
| `qa-integrator` | 엔진 출력 ↔ 프론트 입력 경계면 교차검증, 빌드/실행 검증 (general-purpose) |

**스킬:**
| 스킬 | 용도 | 사용 에이전트 |
|------|------|-------------|
| `build-reposhield` | 오케스트레이터 — 팀 조율, 공유 데이터 계약(VerdictReport) 정의 | 리더 |
| `github-threat-detection` | 탐지 룰셋·GitHub API·위험점수 모델 | security-engine-builder |
| `secure-ui-design` | 3D 카드/홀로그래픽/호버 + 검증결과 시각화 패턴 | frontend-builder |

**실행 규칙:**
- RepoShield 개발/수정/확장 요청 시 `build-reposhield` 스킬로 에이전트 팀 가동.
- 단순 질문/확인은 팀 없이 직접 응답 가능.
- 모든 에이전트는 `model: "opus"` 사용.
- 경계면 단일 진실원: `build-reposhield` 스킬의 `## 공유 데이터 계약`(VerdictReport). 양측 합의 없이 변경 금지.
- 중간 산출물: `_workspace/`. 최종 코드: `src/` + 루트.
- **안전성 도구 제1원칙:** "미검사"를 "안전"으로 표시하지 않는다. `scanLimitedReason`/`verdict`를 항상 정확히 반영.

**디렉토리 구조:**
```
.claude/
├── agents/
│   ├── security-engine-builder.md
│   ├── frontend-builder.md
│   └── qa-integrator.md
└── skills/
    ├── build-reposhield/SKILL.md            (오케스트레이터 + 데이터 계약)
    ├── github-threat-detection/
    │   ├── SKILL.md
    │   └── references/ {threat-patterns, github-api, risk-scoring}.md
    └── secure-ui-design/
        ├── SKILL.md
        └── references/ {3d-card-effects, verdict-visualization}.md
```

**변경 이력:**
| 날짜 | 변경 내용 | 대상 | 사유 |
|------|----------|------|------|
| 2026-06-30 | 초기 하네스 구성 | 전체 | 빌드 하네스 신규 구축 |
| 2026-06-30 | 4축 점수(신뢰도·안정성·적합성·위험도) + dangerLock 추가 | build-reposhield 계약, risk-scoring, secure-ui-design | 원형 그래프·전체화면 빨강 경고 요구 |
| 2026-06-30 | v2 강화 사양 5종 기록(공급망·source-mismatch·포렌식·엔트로피/시크릿·AI해설) | external-intel.md, ai-explainer.md, 계약 enrichment | 쉴드 기능 강화 5가지 전부 채택, #5는 사용자 OpenRouter 키 |
| 2026-06-30 | v2 구현(엔진 intel + AI 패널) + 런처 실제 썸네일 + enrichment 접기/더보기 | src/engine/intel, src/components/ai, LauncherCard, EnrichmentPanel | 강화 5종 개발, 썸네일·정보과잉 피드백 |
| 2026-06-30 | 거짓양성 수정: 악성 의도 vs 공급망 위생 2차원 분리(`dependency-hygiene` 신설), 위생은 caution 상한·dangerLock 제외 | scorer, supplyChain, risk-scoring, 계약 Category, FindingList 위생 요약 | express/react 등 정상 저장소가 의존성 CVE로 danger 오판하던 문제 |
| 2026-06-30 | 거짓양성 수정 2건(video-use): ①악성 판정을 MAL- id/alias·명시적 malware 분류 필드로만 한정(summary/details 키워드 금지) ②secret-exfiltration을 맥락 기반 심각도로(의심목적지/광범위수집 시만 critical, 단일 명명 키→평범 https는 미탐) | supplyChain.js, rules.js, threat-patterns.md, external-intel.md, _workspace 스모크 | requests(CVE-2024-47081)가 악성 오분류, 정상 API클라(transcribe.py)가 secret-exfil critical 오판 |
