// scorer.js — risk-scoring.md 모델로 4축 점수·riskScore·verdict·dangerLock·summary 산출
//
// 입력: { meta, tree, findings, scannedFiles, scanLimitedReason }
// 출력: VerdictReport(공유 데이터 계약). repo/url 등은 index.js에서 합성하므로
//       여기서는 scores/riskScore/verdict/dangerLock/summary/signals 를 산출해 반환.

import { treeHas } from './githubClient.js';

const SEV_WEIGHT = { critical: 45, high: 22, medium: 9, low: 3 };

// 공급망 위생(일반 의존성 CVE) 카테고리. 악성 의도와 분리해 약하게만 반영하고,
// critical 바닥·dangerLock·danger 승격에서 제외한다(risk-scoring.md 2차원 분리).
const HYGIENE_CATEGORIES = new Set(['dependency-hygiene']);
// 의존성-CVE(위생) findings가 riskScore에 더할 수 있는 총기여 상한.
// 100건이 쌓여도 이 점수를 넘지 못해 단독으로는 danger(>=60)에 도달할 수 없다.
const HYGIENE_CONTRIB_CAP = 25;

function isHygieneFinding(f) {
  return f && HYGIENE_CATEGORIES.has(f.category);
}

// 악성 의도(malice) critical: dangerLock/critical 바닥을 트리거할 수 있는 진짜 위험.
// 공급망 위생 findings는 (설령 어떤 이유로 critical이라도) 제외한다.
function hasMaliceCritical(findings) {
  return findings.some((f) => f.severity === 'critical' && !isHygieneFinding(f));
}

function clamp(n, lo, hi) {
  return Math.max(lo, Math.min(hi, n));
}

function daysSince(iso) {
  if (!iso) return Infinity;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return Infinity;
  return (Date.now() - t) / (1000 * 60 * 60 * 24);
}

// ── 2. finding 누적 점수(체감 합산) ──────────────────────────────────────────
// 악성 의도 findings만 본 누적에 들어간다. 공급망 위생(일반 CVE)은 별도 누적·상한.
function accumulateFindingScore(findings) {
  // 카테고리별 등장 횟수로 체감 합산(2번째부터 50%)
  const countByCat = {};
  let raw = 0;
  for (const f of findings) {
    if (isHygieneFinding(f)) continue; // 위생은 별도 처리(아래 hygieneContribution)
    const w = SEV_WEIGHT[f.severity] || 0;
    const c = countByCat[f.category] || 0;
    const factor = c === 0 ? 1 : 0.5; // 같은 카테고리 2번째부터 절반
    raw += w * factor;
    countByCat[f.category] = c + 1;
  }
  return raw;
}

// ── 2b. 공급망 위생(일반 의존성 CVE) 별도 누적 + 상한 ─────────────────────────
// 의존성에 알려진 CVE가 많다는 건 거의 모든 실세계 저장소의 정상적 위생 문제이지
// "이 저장소가 악성"이라는 신호가 아니다. 따라서:
//   - 약하게만(체감 합산) 누적하고,
//   - 총기여를 HYGIENE_CONTRIB_CAP으로 제한해 단독으로는 danger에 도달 못 하게 한다.
function hygieneContribution(findings) {
  let raw = 0;
  let count = 0;
  for (const f of findings) {
    if (!isHygieneFinding(f)) continue;
    const w = SEV_WEIGHT[f.severity] || 0;
    // 2번째부터 체감(절반)해 다수의 CVE가 점수를 과하게 부풀리지 않도록.
    raw += w * (count === 0 ? 1 : 0.5);
    count++;
  }
  return Math.min(raw, HYGIENE_CONTRIB_CAP);
}

// ── 3. 신뢰 신호 보정 ────────────────────────────────────────────────────────
function mitigation(meta, contributorsCount) {
  let m = 0;
  const stars = meta.stars || 0;
  if (stars >= 5000) m += 10;
  else if (stars >= 1000) m += 6;
  else if (stars >= 200) m += 3;

  const ageDays = daysSince(meta.createdAt);
  if (ageDays >= 365 * 2) m += 4;

  if (daysSince(meta.pushedAt) <= 90) m += 3;
  if (meta.license) m += 2;
  if ((contributorsCount || 0) >= 10) m += 4;

  return Math.min(m, 25);
}

function aggravation(meta, findings) {
  let a = 0;
  const hasFinding = findings.length > 0;
  const ageDays = daysSince(meta.createdAt);
  const recentlyPushed = daysSince(meta.pushedAt) <= 30;

  // 신규 위장 저장소 패턴
  if (ageDays <= 7 && recentlyPushed && hasFinding) a += 8;
  // 무명 + finding
  if ((meta.stars || 0) === 0 && (meta.forks || 0) === 0 && hasFinding) a += 5;
  // 아카이브인데 설치훅 활성
  const hasInstallHook = findings.some((f) => f.category === 'install-hook');
  if (meta.archived && hasInstallHook) a += 3;

  return Math.min(a, 15);
}

// ── riskScore 종합 (§4) ──────────────────────────────────────────────────────
export function computeRiskScore(meta, findings, contributorsCount) {
  // critical 바닥은 "악성 의도" critical에만 적용한다.
  const maliceCritical = hasMaliceCritical(findings);
  let raw = accumulateFindingScore(findings) + hygieneContribution(findings);
  raw = Math.max(raw, maliceCritical ? 70 : 0);
  const score = clamp(raw - mitigation(meta, contributorsCount) + aggravation(meta, findings), 0, 100);
  // 악성 의도 critical이 있을 때만 70 미만으로 내려가지 않도록 바닥 보장.
  const floored = maliceCritical ? Math.max(score, 70) : score;
  return Math.round(floored);
}

// ── verdict (§4) ─────────────────────────────────────────────────────────────
export function computeVerdict(riskScore, findings) {
  const maliceCritical = hasMaliceCritical(findings);
  // high도 위생 카테고리는 danger 후보가 아니지만, high는 어차피 caution까지만 올린다.
  const hasNonHygieneHigh = findings.some(
    (f) => f.severity === 'high' && !isHygieneFinding(f)
  );
  // danger는 악성 의도 critical 또는 riskScore가 충분히 높을 때만.
  if (maliceCritical || riskScore >= 60) return 'danger';
  if (riskScore >= 25 || hasNonHygieneHigh) return 'caution';
  // 위생-high만 있어도 caution까지.
  if (findings.some(isHygieneFinding)) return 'caution';
  return 'safe';
}

// ── dangerLock (§6) ──────────────────────────────────────────────────────────
// dangerLock = (riskScore>=85) ∨ (악성 의도 critical).
// 일반 의존성 CVE(위생)는 dangerLock 산출에서 제외한다.
export function computeDangerLock(riskScore, findings) {
  return riskScore >= 85 || hasMaliceCritical(findings);
}

// ── 4축 점수 (§6) ────────────────────────────────────────────────────────────

// trust — log-scaled stars + 보정
function logScaledStars(stars) {
  // 0→0, 200→40, 1k→60, 5k→80, 50k→95 (구간 보간)
  if (stars <= 0) return 0;
  const points = [
    [0, 0],
    [200, 40],
    [1000, 60],
    [5000, 80],
    [50000, 95],
  ];
  if (stars >= 50000) return 95;
  for (let i = 1; i < points.length; i++) {
    const [x1, y1] = points[i - 1];
    const [x2, y2] = points[i];
    if (stars <= x2) {
      // log 보간
      const lx = Math.log10(Math.max(stars, 1));
      const lx1 = Math.log10(Math.max(x1, 1));
      const lx2 = Math.log10(Math.max(x2, 1));
      const ratio = lx2 === lx1 ? 0 : (lx - lx1) / (lx2 - lx1);
      return y1 + ratio * (y2 - y1);
    }
  }
  return 95;
}

export function computeTrust(meta, contributorsCount) {
  let t = logScaledStars(meta.stars || 0);
  // forks 보정(최대 +10)
  t += Math.min(10, Math.log10((meta.forks || 0) + 1) * 4);
  const ageDays = daysSince(meta.createdAt);
  if (ageDays >= 365 * 2) t += 5;
  else if (ageDays >= 365) t += 3;
  if ((contributorsCount || 0) >= 10) t += 8;
  else if ((contributorsCount || 0) >= 3) t += 4;
  if (meta.license) t += 5;
  return Math.round(clamp(t, 0, 100));
}

export function computeStability(meta, tree) {
  let s = 50;
  const pushed = daysSince(meta.pushedAt);
  if (pushed <= 30) s += 25;
  else if (pushed <= 90) s += 15;
  else if (pushed <= 365) s += 5;
  else s -= 15;

  // open_issues/stars 비율 양호(+10): 이슈가 스타 대비 과하지 않음
  const stars = meta.stars || 0;
  if (stars > 0 && (meta.openIssues || 0) / stars < 0.1) s += 10;

  if (meta.archived) s -= 30;

  // 릴리스/태그 존재 추정: 트리에 CHANGELOG 또는 tags 흔적
  const hasReleaseSignal = treeHas(tree, (p) => /changelog|release/i.test(p));
  if (hasReleaseSignal) s += 10;

  return Math.round(clamp(s, 0, 100));
}

export function computeSuitability(tree) {
  let s = 40;
  if (treeHas(tree, (p) => /(?:^|\/)readme(\.md|\.rst|\.txt)?$/i.test(p))) s += 10;
  if (treeHas(tree, (p) => /(?:^|\/)licen[cs]e(\.[a-z]+)?$/i.test(p))) s += 8;
  if (treeHas(tree, (p) => /(?:^|\/)(?:test|tests|__tests__|spec)(?:\/|$)/i.test(p))) s += 12;
  if (treeHas(tree, (p) => p.startsWith('.github/workflows/'))) s += 10;
  if (treeHas(tree, (p) => /(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock)$/i.test(p))) s += 8;
  if (treeHas(tree, (p) => /(?:contributing|security)\.md$/i.test(p))) s += 6;
  if (treeHas(tree, (p) => /(?:tsconfig\.json|pyproject\.toml)$/i.test(p))) s += 6;
  return Math.round(clamp(s, 0, 100));
}

// ── 신뢰 신호 표시용(§5) ─────────────────────────────────────────────────────
function formatStars(n) {
  if (n >= 1000) return (n / 1000).toFixed(n >= 10000 ? 0 : 1) + 'k';
  return String(n);
}

export function buildTrustSignals(meta, contributorsCount) {
  const signals = [];
  signals.push({
    label: '스타',
    value: formatStars(meta.stars || 0),
    weight: (meta.stars || 0) >= 200 ? '+신뢰' : '중립',
  });
  signals.push({
    label: '포크',
    value: formatStars(meta.forks || 0),
    weight: (meta.forks || 0) >= 50 ? '+신뢰' : '중립',
  });
  const ageDays = daysSince(meta.createdAt);
  signals.push({
    label: '저장소 나이',
    value: Number.isFinite(ageDays) ? `${Math.floor(ageDays / 365)}년 ${Math.floor((ageDays % 365) / 30)}개월` : '알 수 없음',
    weight: ageDays >= 365 * 2 ? '+신뢰' : ageDays <= 7 ? '-주의(신규)' : '중립',
  });
  const pushedDays = daysSince(meta.pushedAt);
  signals.push({
    label: '최근 푸시',
    value: Number.isFinite(pushedDays) ? `${Math.floor(pushedDays)}일 전` : '알 수 없음',
    weight: pushedDays <= 90 ? '+신뢰(활발)' : '중립',
  });
  signals.push({
    label: '라이선스',
    value: meta.license || '없음',
    weight: meta.license ? '+신뢰' : '-주의',
  });
  if (typeof contributorsCount === 'number') {
    signals.push({
      label: '기여자',
      value: contributorsCount >= 30 ? '30+' : String(contributorsCount),
      weight: contributorsCount >= 10 ? '+신뢰' : '중립',
    });
  }
  if (meta.archived) {
    signals.push({ label: '보관됨', value: '예', weight: '-주의' });
  }
  return signals;
}

// ── summary 문구(§5) ─────────────────────────────────────────────────────────
export function buildSummary(verdict, findings, scanLimitedReason) {
  let base;
  if (verdict === 'danger') {
    const crit = findings.find((f) => f.severity === 'critical');
    if (crit && crit.category === 'secret-exfiltration') {
      base = '환경변수/API 키를 외부로 전송하는 코드가 발견되었습니다. clone 및 설치를 권장하지 않습니다.';
    } else if (crit) {
      base = '외부 코드를 내려받아 실행하는 등 치명적 위험 패턴이 발견되었습니다. clone을 권장하지 않습니다.';
    } else {
      base = '여러 위험 신호가 누적되어 위험으로 판정했습니다. clone을 권장하지 않습니다.';
    }
  } else if (verdict === 'caution') {
    const hook = findings.find((f) => f.category === 'install-hook');
    const nonHygiene = findings.filter((f) => !isHygieneFinding(f));
    const hygieneCount = findings.length - nonHygiene.length;
    if (hook) {
      base = '설치 시 자동 실행되는 스크립트가 있습니다. 아래 항목을 직접 확인한 뒤 결정하세요.';
    } else if (hygieneCount > 0 && nonHygiene.length === 0) {
      // 공급망 위생 문제만 있는 경우 — 악성 신호 아님. 근거 없는 공포 조장 금지.
      base = `의존성에 알려진 취약점(CVE) ${hygieneCount}건이 있습니다. 이는 거의 모든 활성 저장소에 존재하는 공급망 위생 문제로, 저장소 자체가 악성이라는 뜻은 아닙니다. 의존성을 안전한 버전으로 업데이트하는 것을 권장합니다.`;
    } else {
      base = '주의가 필요한 신호가 있습니다. 아래 발견 항목을 직접 확인한 뒤 결정하세요.';
    }
  } else {
    base = '검사한 범위에서 명백한 위협은 발견되지 않았습니다. 다만 모든 파일을 검사한 것은 아닙니다.';
  }
  if (scanLimitedReason) {
    base += ' (일부 파일은 검사하지 못했습니다.)';
  }
  return base;
}

// ── 종합: scores 객체 + 파생값 ───────────────────────────────────────────────
// forensicAdjust(v2, optional): { trust, stability } — intel/forensics 보정. 미지정 시 0.
export function score({ meta, tree, findings, scanLimitedReason, contributorsCount, forensicAdjust }) {
  const riskScore = computeRiskScore(meta, findings, contributorsCount);
  const verdict = computeVerdict(riskScore, findings);
  const dangerLock = computeDangerLock(riskScore, findings);

  const adj = forensicAdjust || { trust: 0, stability: 0 };
  const scores = {
    trust: Math.round(clamp(computeTrust(meta, contributorsCount) + (adj.trust || 0), 0, 100)),
    stability: Math.round(clamp(computeStability(meta, tree) + (adj.stability || 0), 0, 100)),
    suitability: computeSuitability(tree),
    risk: riskScore,
  };

  return {
    riskScore,
    scores,
    verdict: dangerLock ? 'danger' : verdict, // dangerLock이면 danger 강제
    dangerLock,
    summary: buildSummary(dangerLock ? 'danger' : verdict, findings, scanLimitedReason),
    signals: { trust: buildTrustSignals(meta, contributorsCount) },
  };
}
