---
name: github-threat-detection
description: GitHub 저장소를 git clone 하기 전에 악성코드·스미싱·API키 탈취·악성 설치스크립트·원격코드실행을 브라우저 측 GitHub 공개 API + 정적 분석으로 탐지하고 위험점수를 산출하는 방법. RepoShield 보안 엔진을 만들거나, 저장소 안전성 검증 로직·악성 패턴 룰셋·위험점수 모델·GitHub API 클라이언트를 구현/수정할 때 반드시 사용. "검증 룰 추가", "탐지 강화", "거짓양성 줄여줘", "스코어링 조정" 등 후속 요청에도 사용.
---

# GitHub Threat Detection

`git clone` 전에 저장소를 검증해 사용자를 보호하는 엔진을 만드는 방법. 실제 사고 모델: 정상 오픈소스로 위장한 저장소가 설치/실행 시점에 사용자의 환경변수·API 키를 읽어 해커 서버로 실시간 전송하는 스미싱. 이걸 **clone 전에** 잡는 것이 목표다.

## 설계 원칙

- **백엔드 없음.** 브라우저에서 `api.github.com` 공개 API만 사용한다. 실제 clone/실행은 하지 않고, clone될 파일을 **정적으로** 읽어 분석한다. 코드를 절대 실행하지 않으므로 분석 행위 자체가 안전하다.
- **조합으로 판단하라.** 단일 키워드(`eval`, `fetch`, `process.env`)는 정상 코드에도 흔하다. 거짓 양성을 줄이려면 **위험 신호의 조합**(예: 환경변수 읽기 **+** 외부 도메인 전송 **+** 설치 훅)으로 심각도를 올린다. 자세한 조합 규칙은 `references/threat-patterns.md`.
- **정직하게 보고하라.** 못 읽은 파일은 "안전"이 아니라 "미검사"다. 스캔 한계를 `scanLimitedReason`에 항상 명시한다.
- **비전문가를 위해 설명하라.** 모든 finding은 "왜 위험한가"를 일상어 한국어 한 문장으로 담는다.

## 워크플로우

1. **URL 파싱** — `owner/repo`(+선택 branch) 추출. 다양한 GitHub URL 형태 허용.
2. **메타데이터 수집** — `GET /repos/{owner}/{repo}`로 스타·포크·생성일·최근푸시·라이선스·아카이브 여부 등 **신뢰 신호**를 모은다.
3. **파일 트리 수집** — `GET /repos/{owner}/{repo}/git/trees/{branch}?recursive=1`로 전체 파일 목록을 1회에 가져온다(호출 절약).
4. **우선순위 파일 선별** — 트리에서 위험이 집중되는 파일을 고른다: `package.json`, `setup.py`, `*.sh`, `Dockerfile`, `.github/workflows/*`, 진입점 스크립트, 의심 확장자. (rate limit 때문에 전부 받지 않는다.)
5. **내용 fetch & 스캔** — 선별 파일을 raw로 받아 `references/threat-patterns.md`의 룰셋으로 스캔, finding 생성.
6. **점수 산출** — `references/risk-scoring.md`의 모델로 findings + 신뢰 신호 → `riskScore`(0~100) + `verdict`.
7. **VerdictReport 출력** — 오케스트레이터 스킬의 `## 공유 데이터 계약` 형태로 반환.

## 탐지 카테고리 (요약)

| 카테고리 | 무엇을 잡나 | 기본 심각도 |
|----------|------------|------------|
| `secret-exfiltration` | env/키 파일을 읽어 외부로 전송 | critical |
| `install-hook` | package.json postinstall/preinstall, setup.py 실행 코드 | high |
| `remote-code-exec` | `curl\|bash`, 네트워크 응답을 eval/exec | critical |
| `obfuscation` | base64/hex 디코드 후 실행, 난독화된 페이로드 | high |
| `suspicious-network` | 하드코딩 IP, discord/telegram webhook 등 유출 채널 | medium~high |
| `crypto-miner` | 마이닝 풀/스트라텀 시그니처 | high |
| `dependency-risk` | 타이포스쿼팅 의심 의존성, 알 수 없는 git 의존성 (v2: OSV/npm DB 조회로 격상) | low~high |
| `source-mismatch` | (v2) GitHub 소스와 게시 패키지(npm/PyPI) 불일치 | medium~high |

각 카테고리의 정확한 패턴·정규식·조합 규칙·거짓양성 회피는 **`references/threat-patterns.md`를 읽어라.**

## 참조 파일

- `references/threat-patterns.md` — 카테고리별 탐지 패턴, 정규식, 조합 규칙, 거짓양성 관리 (룰 구현/수정 시 필독)
- `references/github-api.md` — 사용할 엔드포인트, rate limit 전략, 토큰 처리, URL 파싱
- `references/risk-scoring.md` — 위험점수 공식, 신뢰 신호 가중치, verdict 임계값

## 회귀 케이스 (반드시 통과)

- **잡아야 함:** `process.env`/`os.environ`을 읽어 외부 URL로 `fetch`/`requests.post` 하는 파일 → `secret-exfiltration` critical.
- **잡아야 함:** package.json `scripts.postinstall`에 `curl ... | bash` → `install-hook`+`remote-code-exec`.
- **놓치면 안 됨(거짓음성 금지):** base64 문자열을 디코드해 `eval`/`exec` → `obfuscation` high.
- **과잉탐지 금지:** 단순히 `fetch('/api/...')` 또는 `eval(JSON...)` 만 있는 정상 코드 → finding 없음 또는 low.
