<div align="center">

# 🛡️ RepoShield

**`git clone` 하기 _전에_ GitHub 저장소의 안전성을 검증하는 무료 웹 도구**

_Check a GitHub repo for key-stealing, smishing, and malicious install scripts — before you clone it._

[![Live Demo](https://img.shields.io/badge/▶_Live_Demo-git--v3.vercel.app-5b8cff?style=for-the-badge)](https://git-v3.vercel.app)
<br/>
[![License: MIT](https://img.shields.io/badge/License-MIT-2ecc71.svg)](./LICENSE)
[![React](https://img.shields.io/badge/React-18-61dafb.svg)](https://react.dev)
[![Vite](https://img.shields.io/badge/Vite-5-646cff.svg)](https://vitejs.dev)
[![Backend](https://img.shields.io/badge/backend-none_(static)-67748a.svg)](#-아키텍처)

by **BSD** · Business System Development

</div>

---

## 왜 만들었나

최근 정상 오픈소스로 위장한 저장소가 **설치·실행 시점에 사용자의 환경변수·API 키를 읽어 해커 서버로 실시간 전송**하는 스미싱 사고가 늘고 있습니다. 실시간으로 쏟아지는 GitHub 링크를 **클론하기 전에** 미리 검증하는 것이 무엇보다 중요해졌습니다.

RepoShield는 GitHub URL만 입력하면, **코드를 내려받지도 실행하지도 않고** 정적으로 분석해 위험을 알려줍니다. 비전문가도 3초 안에 **신호등(🟢 안전 / 🟡 주의 / 🔴 위험)** 으로 판단할 수 있습니다.

> **▶ 지금 바로 써보기: [git-v3.vercel.app](https://git-v3.vercel.app)**
> 테스트해보고 싶다면 `expressjs/express`를 넣어보세요 — 의존성에 실제 악성 패키지(`debug` 멀웨어)가 걸려 있어 **전체화면 빨강 경고**가 뜹니다.

## ✨ 기능

### 🔍 clone 전 보안 검증
GitHub 공개 API로 저장소 파일을 받아 **정적 스캔**합니다 (코드를 실행하지 않으므로 분석 자체가 안전).
- **비밀정보 유출** — env/키를 읽어 의심스러운 목적지로 전송하는 패턴
- **악성 설치 스크립트** — `postinstall`의 `curl | bash` 등 설치만 해도 실행되는 코드
- **원격 코드 실행** — 외부에서 받은 것을 `eval`/`exec`
- **난독화 페이로드 · 유출 채널** — base64 디코드 후 실행, 디스코드/텔레그램 웹훅 등

### 📊 4축 점수 + 동적 시각화
**신뢰도 · 안정성 · 적합성 · 위험도** 를 원형 그래프로 (마운트 시 카운트업 애니메이션). 신뢰 신호(스타·포크·나이·라이선스·구조)는 표로, 판정은 위험점수 게이지와 신호등으로.

### 🛰️ 외부 인텔리전스 강화
- **공급망 검사** (OSV.dev / npm / PyPI) — **악성 패키지**(멀웨어 주입)와 **일반 CVE(공급망 위생)** 를 구분
- **출처 불일치** — "GitHub 소스 ≠ 게시된 패키지" 감지
- **커밋·소유자 포렌식** — 신생 위장 저장소 신호
- **커밋된 시크릿 · 엔트로피 기반 난독화** 탐지
- **이미 보고된 보안 권고**(GitHub Advisories / OSV) 표시

### 🤖 AI 코드 해설 (선택)
본인 **OpenRouter 키**로 의심 코드가 실제 무엇을 하는지 자연어로 설명 (Opus 4.8 / Codex 5.5 / GPT-5.5 등 선택). 키는 브라우저에만 머물며 OpenRouter 외 어디로도 전송되지 않습니다.

### 🚀 트렌딩 런처
오픈소스 트렌드 사이트(Product Hunt · Trendshift · GitHub Trending · Star History · GitStar Ranking · OSS Insight)를 실제 썸네일 3D 카드로 — 무한 슬라이드.

## 🧭 설계 원칙

| 원칙 | 의미 |
|------|------|
| **안전성 제1원칙** | "검사하지 못한 것"을 "안전"으로 표시하지 않는다. 스캔 한계를 항상 정직하게 표기. |
| **양치기 소년 금지** | "의존성에 알려진 CVE가 있다"(위생)와 "이 저장소가 악성이다"(악성 의도)를 분리한다. 일반 CVE는 전체화면 경고를 띄우지 않는다. |
| **키를 새지 않는 도구** | 입력한 GitHub 토큰·AI 키는 브라우저에만 머물며 GitHub/OpenRouter 외 어디로도 전송되지 않는다. |

## 🧩 아키텍처

백엔드가 **없습니다.** 브라우저가 직접 `api.github.com` · OSV.dev · npm/PyPI를 호출해 분석하므로, 그대로 정적 호스팅(Vercel 등)에 배포됩니다.

```
React + Vite (SPA)
├─ src/engine/          보안 검증 엔진 (GitHub API · 탐지 룰 · 4축 스코어)
│  └─ intel/            공급망 · 출처 · 포렌식 · 시크릿 강화
├─ src/components/      검증 결과 시각화 · 3D 카드 런처 · AI 패널
└─ VerdictReport        엔진→UI 단일 데이터 계약
```

## 🚀 시작하기

```bash
npm install
npm run dev      # 개발 서버 → http://localhost:5173
npm run build    # 프로덕션 빌드 → dist/
npm run preview  # 빌드 미리보기
```

### GitHub 토큰 (rate limit)
미인증 GitHub API는 **시간당 60회**로 제한됩니다. 검증창에서 **권한 없는(read-only) 토큰**을 넣으면 **5,000회/시간**으로 완화됩니다. 토큰은 선택적으로 "이 기기에 저장"할 수 있고(브라우저 localStorage), 언제든 지울 수 있습니다.

## ⚠️ 면책

RepoShield의 판정은 **휴리스틱 정적 분석** 결과이며 100% 보장이 아닙니다. 위협을 놓치거나 정상을 의심할 수 있습니다. 최종 판단과 책임은 사용자에게 있습니다.

## 📄 라이선스

[MIT](./LICENSE) © 2026 BSD (Business System Development)
