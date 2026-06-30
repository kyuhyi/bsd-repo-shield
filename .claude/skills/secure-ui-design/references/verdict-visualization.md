# Verdict Visualization — 검증 결과 시각화 가이드

목차: 1) 컴포넌트 트리 2) 상태 머신 3) verdict/게이지 4) finding 카드 5) 위험표현 정합성 규칙

---

## 1. 컴포넌트 트리

```
<Verifier>
  <UrlInput onSubmit/>             // URL + 검증 버튼 + (선택)토큰
  <ScanProgress/>                  // 로딩: 검사 파일 수, 남은 rate
  <VerdictPanel report>
    <VerdictBadge verdict scanLimitedReason/>   // 신호등 + 미검사 배지
    <TrustSignalTable repo signals.trust/>      // 표: 스타/포크/생성·푸시/라이선스/구조 + 평가
    <ScoreRadials scores/>                       // 4개 원형 그래프: 신뢰도·안정성·적합성·위험도
    <Summary text/>                              // 한국어 요약
    <FindingList findings/>                      // 심각도순 카드
  </VerdictPanel>
  <DangerOverlay show={report.dangerLock}/>      // 전체화면 빨강 깜빡임 경고
</Verifier>
```

---

## 2. 상태 머신

`idle → loading → (partial | success | error)`

- `idle`: 입력만.
- `loading`: 진행 표시(엔진이 파일 수/단계 콜백 주면 반영).
- `partial`: 결과 있으나 `scanLimitedReason != null`. **success로 취급하지 말 것.** verdict 표시 + 미검사 경고 동시.
- `error`: 404/비공개/네트워크/rate 초과. 사용자 메시지 + 재시도/토큰 안내. 빈 초록 화면으로 오인 금지.

---

## 3. VerdictBadge / RiskGauge

VerdictBadge:
- `safe` → 초록 ✓ "검사 범위 내 위협 미발견"
- `caution` → 노랑 ⚠ "직접 확인 후 결정 권장"
- `danger` → 빨강 ⛔ "clone 권장하지 않음"
- `scanLimitedReason` 존재 → 위 배지 옆 회색 "일부 미검사" 태그 + 툴팁에 이유. safe 문구는 "검사한 범위 내"로 한정.

RiskGauge: 반원/원형 게이지, 채움 색 = verdict 색. 숫자 monospace. 100점 척도 라벨(낮음/주의/위험 구간 눈금).

---

## 4. finding 카드

```
[심각도색 좌측 보더]
 CATEGORY · severity 뱃지        파일경로:라인
 제목(한 줄)
 ┌ snippet (monospace, 위험 토큰 강조) ┐
 └─────────────────────────────────────┘
 💡 왜 위험한가: {한국어 설명}
 (rule: {ruleId})  ← 작게
```

- 정렬: critical→high→medium→low.
- 접기/펼치기: snippet 길면 기본 접힘.
- 0건이면 `<EmptyState>`: 초록 체크 + "검사한 N개 파일에서 위협 미발견" + (미검사 있으면) 범위 한정 문구.

---

## 4b. 신뢰 신호 표 (TrustSignalTable)

`report.repo` + `signals.trust`를 표로. 채팅에서 사용자가 좋아한 형식 그대로:

| 신뢰 신호 | 값 | 평가 |
|----------|-----|------|
| ⭐ 스타 | 46,602 | 매우 높음 (+신뢰) |
| 🍴 포크 | 3,681 | 활발 (+신뢰) |
| 📅 생성 / 최근 푸시 | 2026-02-24 / 2026-06-29 | 4개월, 활발 (+신뢰) |
| 📄 라이선스 | MIT | 양호 (+신뢰) |
| 🗂 구조 | 표준 프로젝트 | 정상 |

- 평가 칸은 신호 강도에 따라 색 칩(+신뢰=초록, 중립=회색, 위험=빨강).
- 숫자는 천단위 콤마/축약(46.6k). 날짜는 상대표현 병기("4개월, 활발").

## 4c. 4축 원형 그래프 (ScoreRadials)

`scores.{trust, stability, suitability, risk}` 4개를 원형 게이지로. **동적**: 마운트 시 0→목표값으로 애니메이션(`stroke-dashoffset` 트랜지션 or requestAnimationFrame 카운트업).

- SVG `<circle>` 2겹(트랙 + 진행). 진행 호를 `stroke-dasharray`로 채움.
- 색 의미: **신뢰도·안정성·적합성은 높을수록 좋음**(낮으면 빨강, 높으면 초록 그라데이션). **위험도는 반대**(높을수록 빨강).
- 중앙에 점수 숫자 카운트업, 아래 라벨(신뢰도/안정성/적합성/위험도).
- `prefers-reduced-motion`이면 애니메이션 없이 즉시 최종값.

```jsx
function Radial({label, value, invert}){           // invert=true → 위험도(높을수록 빨강)
  const r=46, c=2*Math.PI*r;
  const [v,setV]=useState(0);
  useEffect(()=>{ const id=requestAnimationFrame(()=>setV(value)); return ()=>cancelAnimationFrame(id); },[value]);
  const good = invert ? 100-value : value;          // 0(나쁨)~100(좋음)
  const hue = good*1.2;                             // 0=빨강 → 120=초록
  return (
    <div className="radial">
      <svg viewBox="0 0 110 110">
        <circle cx="55" cy="55" r={r} className="radial__track"/>
        <circle cx="55" cy="55" r={r} className="radial__bar"
          style={{stroke:`hsl(${hue} 80% 55%)`, strokeDasharray:c,
                  strokeDashoffset:c*(1-v/100), transition:'stroke-dashoffset 1s ease, stroke .6s'}}/>
        <text x="55" y="60" className="radial__num">{Math.round(v)}</text>
      </svg>
      <span className="radial__label">{label}</span>
    </div>
  );
}
// 사용: <Radial label="위험도" value={scores.risk} invert/> 외 3개는 invert 없음
```

## 4d. 전체화면 빨강 경고 (DangerOverlay)

`report.dangerLock === true`일 때만 렌더. "절대 clone 금지" 수준 경고.

- `position:fixed; inset:0; z-index:9999`. 빨강 반투명 오버레이가 **깜빡임**.
- 큰 ⛔ 아이콘 + "위험: 이 저장소를 clone하지 마세요" + 핵심 사유 1~2줄 + [무시하고 닫기] 버튼(접근성).
- 깜빡임은 `opacity` 키프레임(레이아웃 트리거 금지). `prefers-reduced-motion`이면 깜빡임 대신 정적 빨강 + 강한 보더.

```css
@keyframes danger-flash { 0%,100%{opacity:.86} 50%{opacity:.55} }
.danger-overlay{ position:fixed; inset:0; z-index:9999;
  background:radial-gradient(circle at 50% 40%, rgba(255,40,55,.9), rgba(120,0,10,.95));
  animation: danger-flash .7s ease-in-out infinite;
  display:flex; flex-direction:column; align-items:center; justify-content:center; text-align:center; }
.danger-overlay h1{ color:#fff; font-size:clamp(1.6rem,5vw,3rem); letter-spacing:.02em; }
@media (prefers-reduced-motion: reduce){ .danger-overlay{ animation:none; box-shadow:inset 0 0 0 8px #ff2837; } }
```

- 키보드 `Esc`로 닫기 가능. 닫아도 verdict 패널의 danger 상태는 유지(영구 무시 아님).

## 5. 위험 표현 정합성 규칙 (QA가 검증하는 핵심)

1. 색/아이콘/문구는 **반드시** `report.verdict`에서 파생. 하드코딩·낙관 기본값 금지.
2. `scanLimitedReason`이 truthy면 어떤 verdict든 "일부 미검사" 표식이 보여야 한다.
3. `findings`가 비어도 `verdict`가 danger일 수 있다(메타/신뢰 신호 기반). findings 0 = safe라고 가정 금지 — `verdict`를 따른다.
4. `riskScore`와 `verdict`는 함께 움직인다. 둘이 모순되면(예: score 80인데 safe) 렌더 전 콘솔 경고 + verdict 우선.
5. enum 외 값(미래 확장)이 오면 가장 보수적(위험 쪽)으로 폴백 표시.

이 규칙들이 엔진 출력과 어긋나면 사용자가 위험을 안전으로 오인한다 — `qa-integrator`가 엔진 코드와 이 컴포넌트를 동시에 읽어 대조한다.
