# GitHub API — 브라우저 측 사용 가이드

목차: 1) URL 파싱 2) 엔드포인트 3) rate limit 전략 4) 토큰 처리 5) 파일 선별

---

## 1. URL 파싱

허용할 입력 형태(모두 `owner/repo[@branch]`로 정규화):
- `https://github.com/owner/repo`
- `https://github.com/owner/repo.git`
- `https://github.com/owner/repo/tree/branch`
- `git@github.com:owner/repo.git`
- `owner/repo`

브랜치 미지정 시 메타데이터의 `default_branch`를 사용.

---

## 2. 엔드포인트 (모두 공개, 인증 선택)

베이스: `https://api.github.com`

| 목적 | 엔드포인트 |
|------|-----------|
| 메타데이터/신뢰신호 | `GET /repos/{owner}/{repo}` |
| 전체 파일 트리(1회) | `GET /repos/{owner}/{repo}/git/trees/{branch}?recursive=1` |
| 파일 내용 | raw: `https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}` (API 호출수에 안 잡혀 유리) |
| 기여자 수 | `GET /repos/{owner}/{repo}/contributors?per_page=1` (헤더 Link로 추정) |
| rate 상태 | `GET /rate_limit` |

메타데이터에서 뽑을 신뢰 신호: `stargazers_count`, `forks_count`, `created_at`, `pushed_at`, `archived`, `license`, `open_issues_count`, `subscribers_count`.

응답 헤더 `X-RateLimit-Remaining`, `X-RateLimit-Reset`을 항상 읽어 UI에 남은 횟수를 노출.

---

## 3. rate limit 전략

미인증: **시간당 60회/IP**. 인증(PAT): 5,000회.

호출 최소화 설계:
1. 메타데이터 1회 + 트리 1회 = 저장소당 API 2회.
2. 파일 내용은 **raw.githubusercontent.com**으로 받는다 → REST rate limit과 별개라 큰 절약.
3. 트리가 truncated이면(거대 저장소) 우선순위 경로만 개별 조회하고 `scanLimitedReason`에 "저장소가 너무 커 일부만 검사" 기록.
4. 남은 횟수가 임계 이하이면 사용자에게 "GitHub 토큰을 넣으면 더 깊이 검사" 안내(선택 입력).

---

## 4. 토큰 처리 (보안 주의)

- 토큰은 **선택**이며 전적으로 클라이언트 메모리에만 둔다. 서버로 보내지 않는다(애초에 백엔드 없음).
- localStorage 저장은 기본 비활성. 저장 옵션을 줄 경우 "이 기기에만 저장" 명시 + 지우기 버튼.
- 요청 헤더: `Authorization: Bearer {token}`, `Accept: application/vnd.github+json`.
- **아이러니 주의:** 우리 도구는 키 유출을 막는 도구다. 우리 스스로 토큰을 새지 않도록, 토큰을 로깅/전송하는 코드를 두지 않는다.

---

## 5. 파일 선별 (rate/속도 절약)

트리에서 받아 스캔할 우선순위(상위부터):
1. `package.json`, `package-lock.json`(scripts/의존성), `setup.py`, `pyproject.toml`, `requirements.txt`
2. 루트/스크립트의 `*.sh`, `Dockerfile`, `docker-compose*.yml`, `Makefile`
3. `.github/workflows/*.yml`, `.npmrc`, `.git/hooks` 흔적
4. 진입점: `index.js`, `main.py`, `app.py`, `cli.*`, bin 스크립트
5. 그 외 소스 중 크기 작은 것 위주로 N개(설정 가능, 예: 상위 40개) — 나머지는 미검사로 명시.

이미지/바이너리/lock 외 대용량은 건너뛰되 목록엔 남긴다.
