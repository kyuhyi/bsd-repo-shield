# Risk Scoring — 위험점수 모델

목차: 1) 출력 목표 2) finding 점수 3) 신뢰 신호 보정 4) 합산·verdict 5) 예시

---

## 1. 출력 목표

`riskScore` 0~100 (높을수록 위험) + `verdict ∈ {safe, caution, danger}`.

설계 의도: 비전문가가 신호등처럼 즉시 이해. 점수는 보조, verdict가 주역.

---

## 2. finding 점수 (위험 누적)

심각도별 기본 가중치:

| severity | 점수 기여 |
|----------|----------|
| critical | 45 |
| high | 22 |
| medium | 9 |
| low | 3 |

규칙:
- 같은 카테고리의 중복 finding은 체감 합산(2번째부터 50%)해 한 패턴 도배로 100이 되는 걸 방지.
- **악성 의도(malice) `critical`**이 1개라도 있으면 `riskScore`는 **최소 70**으로 바닥을 올린다(아래 신뢰 보정으로도 70 미만으로 못 내림). ↓ 2.1의 차원 분리 참조.
- 누적 점수는 0~100으로 클램프.

---

## 2.1. 위험의 2차원 분리 — 악성 의도 vs 공급망 위생 (필수)

**핵심 원칙:** "의존성에 알려진 CVE가 있다"(공급망 위생)와 "이 저장소가 키를 훔치는 악성 코드다"(악성 의도)는 **전혀 다른 위험**이다. 거의 모든 실세계 저장소(express, react 등 완전 정상 저장소 포함)는 의존성에 알려진 CVE를 갖는다. 일반 CVE에 "절대 clone 금지" 전체화면 경고(dangerLock)를 띄우면 도구가 양치기 소년이 된다 — 하네스 원칙 "근거 없는 공포 조장 금지" 위배. 따라서 위험을 두 차원으로 분리한다.

### 차원 1 — 악성 의도(malice): 강처벌, dangerLock/critical 바닥 트리거 가능
다음 카테고리만 critical 바닥(70)·`dangerLock`·danger를 트리거할 수 있다:
- `secret-exfiltration`, `remote-code-exec`, `install-hook`(실행 동반), `crypto-miner`, `obfuscation`(실행 인접), `source-mismatch`(실제 불일치)
- 공급망 중 **악성 패키지**: OSV `MAL-` advisory 또는 summary에 malware/malicious가 명시된 항목(예: npm 계정 탈취로 멀웨어 주입된 패키지). category=`dependency-risk`, severity=`critical`.
- **타이포스쿼팅** 사칭 의존성. category=`dependency-risk`, severity=`high`.

### 차원 2 — 공급망 위생(hygiene): 약하게만 반영, danger/dangerLock 제외
의존성의 **일반 CVE/GHSA(비-MAL-, 멀웨어 아님)** 취약점. category=`dependency-hygiene`. 규칙:
- finding severity를 OSV CVSS 그대로 critical로 올리지 않는다. **기본 medium, 아주 심각한 건만 high까지** 캡(절대 critical 금지).
- **critical 바닥(70)·`dangerLock`을 절대 트리거하지 않는다.**
- 이것들만으로는 verdict가 **최대 `caution`**. 100건이 쌓여도 danger(≥60)에 못 가도록 누적 기여에 **상한(cap ≈ 25점)**을 둔다.
- 정보는 잃지 않는다 → `enrichment.supplyChain.vulnerable`에 전부 보존해 UI가 "알려진 취약 의존성 N건"으로 표기.

즉 `critical 바닥`과 `dangerLock`은 **악성 의도 critical에만** 적용한다. 일반 의존성 CVE는 두 산출에서 제외한다.

---

## 3. 신뢰 신호 보정 (위험 완화, 단 상한 존재)

정상 저장소일수록 약한 신호의 노이즈를 깎는다. **완화는 high 이하에만 적용**, critical에는 적용하지 않는다(유명 저장소도 침해 가능).

완화 점수(합산 후 빼기, 최대 -25):
- 스타 ≥ 5,000: -10 / ≥ 1,000: -6 / ≥ 200: -3
- 저장소 나이 ≥ 2년: -4
- 최근 90일 내 푸시(활발): -3
- OSI 라이선스 존재: -2
- 기여자 ≥ 10명: -4

가산(위험 가중, 최대 +15):
- 생성 7일 이내 + 푸시 활발 + 의심 finding: +8 (신규 위장 저장소 패턴)
- 스타 0 + 포크 0 + finding 존재: +5
- 아카이브됨인데 설치훅 활성: +3

---

## 4. 합산·verdict

```
raw = Σ(악성 의도 finding 가중, 체감합산) + min(Σ(위생 finding 가중, 체감합산), 25)  // 위생 총기여 상한 25
raw = max(raw, hasMaliceCritical ? 70 : 0)   // 바닥은 "악성 의도" critical에만
score = clamp(raw - mitigation + aggravation, 0, 100)
```

verdict 임계값:
- `score ≥ 60` 또는 `악성 의도 critical 1개+` → **danger** (빨강. "clone 권장하지 않음")
- `25 ≤ score < 60` 또는 `(위생 아닌) high 1개+` 또는 `위생 finding 존재` → **caution** (노랑. "직접 코드 확인 후 결정")
- `score < 25` 그리고 (악성)critical/high·위생 finding 모두 없음 → **safe** (초록. "명백한 위협 미발견")

> 공급망 위생(`dependency-hygiene`)은 critical로 격상되지 않으며, 단독으로는 verdict를 **최대 caution**까지만 올린다. 일반 의존성 CVE가 아무리 많아도 danger가 되지 않는다(§2.1).

**중요 단서:** `scanLimitedReason`이 있으면 verdict 옆에 항상 "일부 미검사" 배지를 강제 노출. safe라도 "검사한 범위 내 안전"으로 문구를 한정한다. 절대 "100% 안전"이라 말하지 않는다.

---

## 5. summary 문구 가이드

`summary`는 한국어 1~2문장. 예:
- danger: "환경변수를 외부로 전송하는 코드가 발견되었습니다. clone 및 설치를 권장하지 않습니다."
- caution: "설치 시 자동 실행되는 스크립트가 있습니다. 아래 항목을 직접 확인한 뒤 결정하세요."
- safe: "검사한 범위에서 명백한 위협은 발견되지 않았습니다. 다만 모든 파일을 검사한 것은 아닙니다."

`signals.trust`에는 사용자에게 보여줄 신뢰 신호를 `{label, value, weight}`로 담는다(예: `{label:"스타", value:"12.3k", weight:"+신뢰"}`).

---

## 6. 4축 점수 (`scores`) — 원형 그래프용

UI가 4개 원형 게이지로 보여줄 점수. 각 0~100 정수. **trust/stability/suitability는 높을수록 좋음, risk는 높을수록 나쁨.**

### trust (신뢰도) — 평판
```
trust = clamp(
  log-scaled(stars)        // 0★→0, 200★→40, 1k★→60, 5k★→80, 50k★→95
  + forks 보정(최대 +10)
  + 나이≥2년 +5 / ≥1년 +3
  + 기여자≥10 +8 / ≥3 +4
  + OSI 라이선스 +5
, 0, 100)
```

### stability (안정성) — 유지보수 건강도
```
기본 50.
+ 최근 30일 푸시 +25 / 90일 +15 / 1년 +5 / 1년 초과 -15
+ open_issues/stars 비율 양호 +10
- archived(보관됨) -30
+ 릴리스/태그 존재 +10
clamp(0,100)
```

### suitability (적합성) — 코드 위생/프로덕션 적합도
저장소 구조에서 "제대로 만든 프로젝트" 신호. 트리에서 존재 확인:
```
기본 40. 각 +가산:
  README +10, 라이선스 파일 +8, 테스트 디렉토리(test/tests/__tests__) +12,
  CI(.github/workflows) +10, lockfile(package-lock/yarn.lock/poetry.lock) +8,
  CONTRIBUTING/SECURITY.md +6, 타입설정(tsconfig/pyproject) +6
clamp(0,100)
```

### risk (위험도) — 위협
```
risk = riskScore  // 섹션 1~4의 종합 위험점수 그대로 사용
```

**dangerLock 산출:** `dangerLock = (riskScore >= 85) || hasMaliceCriticalFinding`. true면 verdict='danger' 강제, UI 전체화면 경고. **일반 의존성 CVE(`dependency-hygiene`)는 dangerLock 산출에서 제외**한다(§2.1). 즉 dangerLock을 켤 수 있는 critical은 악성 의도 카테고리뿐이다.

> 4축은 서로 독립적 관점이다. 예: 스타 높은 유명 저장소(trust↑, stability↑, suitability↑)라도 **침해되어 악성 의도 critical**(키 유출/멀웨어 주입 패키지 등)이 있으면 risk↑ → dangerLock. 신뢰가 위험을 덮지 않는다.
> 반대로, 유명 저장소가 의존성에 일반 CVE를 수십 건 갖는 건 정상적 공급망 위생 문제다 → 최대 caution, dangerLock 없음. 위생을 악성으로 오인해 공포를 조장하지 않는다.
