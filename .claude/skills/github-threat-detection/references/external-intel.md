# External Intelligence — 외부 데이터 기반 강화 탐지 (v2)

룰 기반 정적 분석을 넘어, 무료 공개 API로 **공급망·출처·이력**을 교차 검증한다. 모두 브라우저에서 호출(백엔드 없음). 키 불필요. CORS 미허용 시 graceful 폴백하고 `scanLimitedReason`/finding 메모에 "조회 실패"를 정직히 남긴다(미조회를 안전으로 위장 금지).

목차: 1) 공급망(OSV/deps.dev/npm/PyPI) 2) 출처 불일치 3) 커밋·소유자 포렌식 4) 엔트로피/시크릿 5) 계약 반영

---

## 1. supply-chain — 의존성 공급망 검사 (#1, 최우선)

코드가 깨끗해도 의존성이 악성이면 끝. `package.json`(deps+devDeps), `requirements.txt`, `pyproject.toml`에서 의존성 목록 추출 후:

- **OSV.dev** — 알려진 취약점/악성 패키지: `POST https://api.osv.dev/v1/query` body `{"package":{"name":"<n>","ecosystem":"npm|PyPI"}}`. 결과의 advisory를 finding으로 — 단, **악성 패키지와 일반 CVE를 엄격히 구분**한다(아래 캡 규칙).
  - **악성(malware) 인정 기준(엄격, 둘 중 하나만):** ① OSV `id` 또는 `aliases` 중 하나가 **`MAL-`로 시작**, 또는 ② OSV 레코드가 **명시적 malware 분류 필드**를 가짐(`database_specific.malicious===true`/`type`·`category`에 `malware`, 또는 `affected[].ecosystem_specific`/`affected[].database_specific`의 동일 필드).
  - **금지:** `summary`/`details` 등 **자유 텍스트에 "malicious"/"malware" 단어가 있다는 이유만으로 악성 분류 금지.** 일반 CVE 설명에 흔히 등장한다(예: `CVE-2024-47081` "Requests vulnerable to .netrc credentials leak via **malicious** URLs" — 이는 공격 URL을 묘사할 뿐 패키지가 멀웨어라는 뜻이 아니다).
  - CVE 별칭(`CVE-`/`GHSA-`)을 갖고 GitHub severity가 LOW/MODERATE/HIGH/CRITICAL인 **일반 취약점**은 전부 위생(`dependency-hygiene`)으로 강등(아래 참조).
- **npm registry** — 신뢰 신호: `GET https://registry.npmjs.org/<pkg>` → 최초 게시일(`time.created`), 최신 버전, `repository`. 신생(<30일)·아카이브·repository 없음 → 가중.
- **다운로드 수** — `GET https://api.npmjs.org/downloads/point/last-week/<pkg>` → 0~극소수면 의심 가중.
- **PyPI** — `GET https://pypi.org/pypi/<pkg>/json` 동일 취지.
- **타이포스쿼팅** — 유명 패키지 사전과 편집거리 1~2 비교(`reqeusts`, `loadsh`, `expresss`, `python-dateutil`↔`dateutil` 등).

→ **위험 2차원 분리(필수, risk-scoring.md §2.1 참조).** 악성 의도와 공급망 위생을 다른 카테고리·심각도로 매핑한다:
  - **악성 패키지**(OSV `MAL-` id/alias 또는 명시적 malware 분류 필드 — **키워드 금지**) → `dependency-risk`, **critical**. **타이포스쿼팅** → `dependency-risk`, **high**. 이들만 critical 바닥·dangerLock·danger 트리거 가능.
  - **일반 CVE/GHSA**(비-MAL-, 멀웨어 아님) → `dependency-hygiene`, **severity 캡: 기본 medium, OSV가 critical/high인 경우만 high까지**(절대 critical 금지). dangerLock·critical 바닥 트리거 안 함, 단독으로 verdict는 **최대 caution**, 누적 기여 **상한 ≈25점**. 정보는 `enrichment.supplyChain.vulnerable`에 전부 보존.

---

## 2. source-mismatch — "GitHub ≠ 설치물" (#2)

가장 교묘한 스미싱: GitHub 소스는 멀쩡한데 npm/PyPI에 게시된 패키지만 악성. 사용자는 GitHub를 보지만 실제 `install`은 레지스트리에서 받는다.

- 패키지명(package.json `name`)으로 레지스트리 조회 → `repository.url`이 **이 GitHub 저장소를 가리키는지** 확인. 불일치/부재 → finding.
- 레지스트리 최신 버전 게시 시점이 GitHub `pushed_at`보다 **늦거나 동떨어졌으면** "게시본이 소스와 다를 수 있음" 경고.
- 게시 버전 수 ≫ git 태그 수처럼 비대칭이면 가중.
- 브라우저에서 tarball 바이트 diff까지는 어렵다 → **"설치되는 코드는 이 저장소와 다를 수 있으니 게시된 패키지를 직접 확인하라"**는 경고 수준으로 정직히 표기.

→ 신규 카테고리 `source-mismatch`(medium~high). 계약 `Category`에 추가.

---

## 3. 커밋·소유자 포렌식 (#3, 신생 위장 탐지)

"최근 올라온 깃url" 사고의 핵심 신호. GitHub API:

- 소유자 계정 나이: `GET /users/{login}` → `created_at`. 계정·저장소 모두 신생 + 푸시 활발 + finding → 강한 위장 신호.
- 기여자: `GET /repos/{o}/{r}/contributors?per_page=10` → 단독 기여자/봇.
- 커밋 패턴: `GET /repos/{o}/{r}/commits?per_page=20` → 생성 직후 대량 단일 커밋, 히스토리 재작성 흔적, 비정상 타임스탬프.
- 별점 급증 의혹: 별점은 높은데 기여자·이슈·나이가 빈약한 비대칭.

→ `stability`/`trust` 점수에 포렌식 패널티/보너스 반영(risk-scoring.md의 가산 규칙과 결합).

---

## 4. 엔트로피·시크릿 스캔 (#4)

정규식 회피가 어려운 통계적 탐지:

- **Shannon 엔트로피** — 토큰/라인 단위. 고엔트로피(>4.0) 장문 문자열 + 디코드/실행 인접 → `obfuscation` 강화. 일반 데이터(이미지 base64)와 구분 위해 실행 신호 인접 여부로 가중.
- **커밋된 시크릿(gitleaks 스타일)** — AWS/GCP 키, `PRIVATE KEY`, 토큰 패턴이 **저장소에 커밋**되어 있으면 finding(저장소 위생 문제 + 공급망 위험). secret-exfiltration과 별개로 "노출된 시크릿" 표기.
- minified 원본이 빌드산출물 아닌데 소스로 커밋 → 의심 가중.

---

## 5. 계약 반영 (build-reposhield의 VerdictReport에 추가, 모두 선택/후방호환)

```ts
// Category 확장
type Category = ... | 'source-mismatch'
  | 'dependency-risk'        // 악성 패키지/타이포스쿼팅(악성 의도) — critical/high
  | 'dependency-hygiene';    // 일반 의존성 CVE(공급망 위생) — 최대 high, dangerLock 제외

// VerdictReport 추가 필드 (v2, optional — 미지원 환경/조회실패 시 생략 가능)
enrichment?: {
  supplyChain?: { ecosystem: string; checked: number; vulnerable: { name:string; advisory:string; severity:Severity; malicious?:boolean; hygiene?:boolean }[]; typosquat: string[] };
  sourceMismatch?: { registry: string|null; repoMatches: boolean|null; note: string };
  forensics?: { ownerCreatedAt: string|null; contributors: number|null; flags: string[] };
  secrets?: { count: number; samples: { file:string; kind:string }[] };
  intelErrors?: string[];   // 조회 실패한 소스(정직성). UI는 "일부 외부조회 실패" 표기
};
```

원칙: enrichment 실패는 안전 신호가 아니다. `intelErrors`가 있으면 UI에 표기하고 점수는 보수적으로.
