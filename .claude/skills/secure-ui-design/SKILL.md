---
name: secure-ui-design
description: RepoShield 프론트엔드 UI를 만드는 방법. (1) 상단 GitHub 보안 검증 결과 시각화 — 위험점수 게이지·safe/caution/danger 신호등·finding 카드·신뢰 배지, (2) 하단 6개 트렌딩 사이트 3D 카드 런처 — 빛반사(홀로그래픽)·마우스 호버 3D tilt·모션 애니메이션. React+Vite로 보안 검증 UI, 3D 카드, 호버 애니메이션, 결과 시각화를 구현/수정할 때 반드시 사용. "카드 더 화려하게", "애니메이션 추가", "결과 화면 개선" 등 후속에도 사용.
---

# Secure UI Design

RepoShield 화면은 두 영역이다: 상단 **보안 검증기**(신뢰감), 하단 **트렌딩 런처**(화려함). 톤은 다크 베이스 + 시그널 컬러(초록/노랑/빨강), 보안 도구다운 절제된 미래감.

## 공통 디자인 토큰

CSS 변수로 관리(테마 일관성·후속 수정 용이):
- 배경: `--bg:#0a0e14` 계열 다크, 카드 `--surface:#121821`, 경계 `--border:#1f2733`
- 시그널: `--safe:#2ecc71`, `--caution:#f1c40f`, `--danger:#ff4757`, 강조 `--accent:#5b8cff`
- 모션: 호버 `cubic-bezier(.2,.8,.2,1)` 180~260ms. 과한 바운스 금지.
- 폰트: 본문 산세리프, 코드/점수 monospace.

성능 원칙: 애니메이션은 `transform`/`opacity`만(레이아웃 트리거 금지). `will-change`는 호버 대상에만. 모바일·`prefers-reduced-motion`에서 3D/빛반사 완화 폴백.

## 1. 보안 검증 결과 시각화 (상단)

입력은 오케스트레이터 계약의 `VerdictReport`. 구성 요소:

- **검증 입력창(Hero):** GitHub URL input + "검증" 버튼. 로딩 중 스캔 진행 표시(파일 N개 검사 중…).
- **신호등 verdict 배지:** `safe/caution/danger`를 색+아이콘+한국어 문구로. `scanLimitedReason` 있으면 "일부 미검사" 보조 배지 강제. **절대 "스캔 못함"을 초록으로 칠하지 않는다.**
- **위험점수 게이지:** 0~100 원형/반원 게이지, 색은 verdict와 연동. 점수는 보조, verdict가 주역.
- **finding 카드 리스트:** 각 finding을 심각도 색 테두리 카드로. 표시: 카테고리, 제목, 파일:라인, 코드 snippet(monospace, 위험 토큰 하이라이트), **"왜 위험한가" 한국어 설명**. critical/high 우선 정렬.
- **신뢰 신호 배지:** `signals.trust`를 별/나이/기여자 등 칩으로.
- **빈 상태:** findings 0건 + safe면 안도감 있는 초록 빈 상태("검사 범위 내 위협 미발견").

상세 컴포넌트 구조·상태 처리는 `references/verdict-visualization.md`.

## 2. 3D 카드 트렌딩 런처 (하단)

6개 사이트 카드 그리드. 각 카드는 클릭 시 새 탭으로 해당 사이트 이동(`target=_blank rel=noopener`).

핵심 효과(상세 구현은 `references/3d-card-effects.md`):
- **3D tilt:** 마우스 위치에 따라 `rotateX/rotateY`로 카드가 기우는 perspective tilt.
- **빛반사(홀로그래픽):** 마우스 추종 하이라이트(radial-gradient sheen) + 홀로그래픽 그라데이션 오버레이.
- **호버 모션:** 살짝 떠오르며(translateZ/scale) 그림자 강화, 내부 요소 패럴랙스.
- **글로우 경계:** 호버 시 카드 테두리 그라데이션 글로우.

각 카드 콘텐츠: 상단 **실제 사이트 썸네일 배너**(스크린샷) + 사이트 이름 + 한 줄 설명 + 외부링크 아이콘.

**썸네일 전략(백엔드 없음, 키 불필요):** 무료 스크린샷 서비스 폴백 체인 — thum.io(`image.thum.io/get/width/640/crop/440/noanimate/<url>`) → 실패 시 WordPress mShots(`s0.wp.com/mshots/v1/<encoded>?w=640&h=440`) → 둘 다 실패 시 글자+그라데이션 폴백. `<img onError>`로 다음 서비스 전환, `referrerPolicy="no-referrer"`, `loading="lazy"`. 주의: 봇 차단(Cloudflare 등) 사이트는 챌린지 화면이 캡처될 수 있음 — `sites.js`에 `thumb` 필드로 직접 URL 오버라이드 가능하게 둔다. (썸네일 서비스에 대상 공개 URL이 전달됨 — 트렌딩 공개 사이트라 민감정보 아님.)

## 6개 사이트 데이터

```js
[
 {name:'Product Hunt', url:'https://www.producthunt.com/leaderboard/monthly/2026/1', desc:'월간 신규 제품 리더보드', hue:14},
 {name:'Trendshift',   url:'https://trendshift.io/monthly', desc:'월간 급상승 오픈소스', hue:265},
 {name:'GitHub Trending', url:'https://github.com/trending', desc:'깃허브 실시간 트렌딩', hue:210},
 {name:'Star History', url:'https://star-history.com', desc:'저장소 스타 추세 그래프', hue:48},
 {name:'GitStar Ranking', url:'https://gitstar-ranking.com', desc:'깃허브 스타 랭킹', hue:150},
 {name:'OSS Insight', url:'https://ossinsight.io', desc:'오픈소스 데이터 인사이트', hue:190},
]
```

## 참조 파일

- `references/3d-card-effects.md` — perspective tilt, 홀로그래픽 sheen, 호버 모션 구현(React + CSS, JS 포인터 추종)
- `references/verdict-visualization.md` — VerdictReport 소비 컴포넌트 구조, 상태/에러/부분결과 처리, 위험 표현 정합성
- `references/ai-explainer.md` — (v2) 사용자 OpenRouter 키 입력 UX·보안, 모델 선택(Opus 4.8/Codex 5.5/GPT-5.5+커스텀), AI 코드해설 패널, 보안 권고 표시

## 함정 (반드시 피하기)

- 안전 표현 거짓: 미검사를 안전으로 표시 → 사용자 피해. verdict/scanLimitedReason을 정확히 반영.
- 성능 붕괴: 호버마다 레이아웃 리플로우 → `transform`만 쓰기. 카드 6개라도 동시에 tilt 계산 시 throttle.
- 제네릭 AI 룩: 기본 부트스트랩 카드 금지. 독창적 디테일·일관 토큰으로 신뢰감 연출.
