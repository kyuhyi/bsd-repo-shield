// intel/forensics.js — #3 커밋·소유자 포렌식 (신생 위장 탐지)
//
// "최근 올라온 깃url" 사고의 핵심 신호. GitHub API:
//   - 소유자 계정 나이(/users/{login} created_at)
//   - 기여자(/repos/.../contributors) — 단독/봇
//   - 최근 커밋 패턴(/repos/.../commits) — 생성 직후 대량 단일 커밋, 비정상 타임스탬프
//   - 별점 급증 의혹: 별점 높은데 기여자·나이 빈약한 비대칭
//
// 산출: enrichment.forensics(+flags), 그리고 scorer가 trust/stability 보정에 쓸
//        forensicAdjust(보너스/패널티). findings는 만들지 않고 "신호"만 제공(거짓공포 방지).
//
// 안전성: 각 조회 실패는 throw 금지 → intelErrors에 사유. 미조회를 안전으로 위장하지 않음.

import { fetchOwnerInfo, fetchContributors, fetchRecentCommits } from '../githubClient.js';

function daysSince(iso) {
  if (!iso) return Infinity;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return Infinity;
  return (Date.now() - t) / (1000 * 60 * 60 * 24);
}

/**
 * 포렌식 분석.
 * @param {{ owner:string, repo:string, branch:string, meta:object }} input
 * @param {{ token?:string, onProgress?:Function }} [opts]
 * @returns {Promise<{enrichment:object, intelErrors:string[], forensicAdjust:{trust:number,stability:number}, flags:string[]}>}
 */
export async function runForensics(input, opts = {}) {
  const { owner, repo, branch, meta } = input || {};
  const token = opts.token;
  const intelErrors = [];
  const flags = [];
  let ownerCreatedAt = null;
  let contributors = null;
  let trustAdj = 0;
  let stabilityAdj = 0;

  function progress(done, total) {
    if (typeof opts.onProgress === 'function') {
      try {
        opts.onProgress({ phase: 'intel-forensics', scanned: done, total });
      } catch {
        /* noop */
      }
    }
  }
  progress(0, 3);

  // 1) 소유자 계정 나이
  const ownerInfo = await fetchOwnerInfo(owner, token);
  if (ownerInfo.ok) {
    ownerCreatedAt = ownerInfo.createdAt;
  } else {
    intelErrors.push(`소유자 계정 정보 조회 실패(${ownerInfo.reason})`);
  }
  progress(1, 3);

  // 2) 기여자
  const contrib = await fetchContributors(owner, repo, token, 10);
  let botOnly = false;
  let soloContributor = false;
  if (contrib.ok) {
    contributors = contrib.count;
    if (contrib.count <= 1) soloContributor = true;
    if (contrib.count > 0 && contrib.bots >= contrib.count) botOnly = true;
  } else {
    intelErrors.push(`기여자 조회 실패(${contrib.reason})`);
  }
  progress(2, 3);

  // 3) 최근 커밋 패턴
  const commitsRes = await fetchRecentCommits(owner, repo, branch, token, 20);
  let burstCommit = false;
  let abnormalTimestamps = false;
  if (commitsRes.ok && commitsRes.commits.length) {
    const dates = commitsRes.commits.map((c) => Date.parse(c.date)).filter((t) => !Number.isNaN(t));
    if (dates.length >= 2) {
      const span = Math.abs(Math.max(...dates) - Math.min(...dates)) / (1000 * 60 * 60); // 시간 단위
      // 20개 커밋이 1시간 이내 → 생성 직후 대량 단일 커밋(import) 의심
      if (commitsRes.commits.length >= 10 && span <= 1) burstCommit = true;
    }
    // 미래 타임스탬프 또는 매우 과거인데 계정은 신생 등
    const now = Date.now();
    if (dates.some((t) => t > now + 1000 * 60 * 60 * 24)) abnormalTimestamps = true;
  } else if (!commitsRes.ok) {
    intelErrors.push(`커밋 조회 실패(${commitsRes.reason})`);
  }
  progress(3, 3);

  // ── 신호 종합 ──
  const ownerAgeDays = daysSince(ownerCreatedAt);
  const repoAgeDays = daysSince(meta && meta.createdAt);
  const recentlyPushed = daysSince(meta && meta.pushedAt) <= 30;
  const stars = (meta && meta.stars) || 0;

  const ownerIsNew = Number.isFinite(ownerAgeDays) && ownerAgeDays <= 30;
  const repoIsNew = Number.isFinite(repoAgeDays) && repoAgeDays <= 14;

  if (ownerIsNew) {
    flags.push('소유자 계정이 30일 이내에 생성된 신생 계정입니다.');
    trustAdj -= 8;
  }
  if (repoIsNew && recentlyPushed) {
    flags.push('저장소가 매우 최근에 생성되었고 활발히 푸시되고 있습니다(신생 위장 가능성).');
    stabilityAdj -= 6;
  }
  if (ownerIsNew && repoIsNew) {
    flags.push('계정과 저장소가 모두 신생입니다 — 일회성 위장 저장소의 전형적 패턴입니다.');
    trustAdj -= 6;
  }
  if (soloContributor) {
    flags.push('기여자가 사실상 1명뿐입니다(단독 작성).');
    trustAdj -= 3;
  }
  if (botOnly) {
    flags.push('기여자가 봇 계정뿐입니다.');
    trustAdj -= 4;
  }
  if (burstCommit) {
    flags.push('초기 커밋이 짧은 시간에 몰려 있습니다(코드 일괄 import 흔적).');
    stabilityAdj -= 4;
  }
  if (abnormalTimestamps) {
    flags.push('비정상적인(미래) 커밋 타임스탬프가 있습니다.');
    stabilityAdj -= 4;
  }
  // 별점 급증 의혹: 별점은 높은데 나이/기여자가 빈약한 비대칭
  if (stars >= 500 && ownerIsNew && (contributors == null || contributors <= 1)) {
    flags.push(`별점(${stars})에 비해 계정 나이·기여자가 빈약합니다(별점 급증/구매 의혹).`);
    trustAdj -= 6;
  }

  // 긍정 신호(오래된 계정·다수 기여자)는 약한 보너스
  if (Number.isFinite(ownerAgeDays) && ownerAgeDays >= 365 * 3) trustAdj += 3;
  if (typeof contributors === 'number' && contributors >= 5) trustAdj += 3;

  const enrichment = {
    forensics: {
      ownerCreatedAt: ownerCreatedAt || null,
      contributors: typeof contributors === 'number' ? contributors : null,
      flags,
    },
  };

  return {
    enrichment,
    intelErrors,
    forensicAdjust: { trust: trustAdj, stability: stabilityAdj },
    flags,
  };
}
