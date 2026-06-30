// index.js — RepoShield 보안 엔진 공개 API
//
// 프론트가 이 시그니처 그대로 import한다(고정):
//   export async function verifyRepo(input, opts = {}) -> VerdictReport
//
// 순수 브라우저 환경(ESM, fetch만). Node 전용 API 절대 사용 금지.
// 하드 실패는 throw new Error(msg) 하되 err.code ∈ {'invalid_url','not_found','rate_limit','network'}.
// 부분 검사 시 VerdictReport를 반환하고 scanLimitedReason을 채운다.
// 안전성 제1원칙: 못 읽은 파일을 "안전"으로 처리하지 않는다 — scanLimitedReason에 정직히 명시.

import {
  parseRepoInput,
  fetchMetadata,
  fetchTree,
  fetchRawFile,
  selectPriorityFiles,
  engineError,
} from './githubClient.js';
import { scanFiles, mergeFindings } from './scanner.js';
import { score } from './scorer.js';
import { runIntel } from './intel/index.js';

const RATE_WARN_THRESHOLD = 8; // 남은 호출 임계

// onProgress 안전 호출
function emit(onProgress, payload) {
  if (typeof onProgress === 'function') {
    try {
      onProgress(payload);
    } catch {
      /* 진행 콜백 오류는 무시 */
    }
  }
}

/**
 * GitHub 저장소를 clone 전에 검증한다.
 * @param {string} input - GitHub URL 또는 "owner/repo"
 * @param {{ token?: string, onProgress?: (p:{phase:string,scanned:number,total:number,rateRemaining:number|null})=>void, maxFiles?: number }} [opts]
 * @returns {Promise<VerdictReport>}
 */
export async function verifyRepo(input, opts = {}) {
  const token = opts.token || undefined;
  const onProgress = opts.onProgress;
  const maxFiles = opts.maxFiles || 40;

  // ── 1. URL 파싱 ──
  emit(onProgress, { phase: 'parse', scanned: 0, total: 0, rateRemaining: null });
  const { owner, repo, branch: requestedBranch } = parseRepoInput(input);

  // ── 2. 메타데이터 ──
  emit(onProgress, { phase: 'metadata', scanned: 0, total: 0, rateRemaining: null });
  const { meta, rate: metaRate } = await fetchMetadata(owner, repo, token);
  let rateRemaining = metaRate.rateRemaining;
  const branch = requestedBranch || meta.defaultBranch;

  emit(onProgress, { phase: 'metadata', scanned: 0, total: 0, rateRemaining });

  // ── 3. 파일 트리 ──
  let tree = [];
  let truncated = false;
  let treeFailed = false;
  emit(onProgress, { phase: 'tree', scanned: 0, total: 0, rateRemaining });
  try {
    const res = await fetchTree(owner, repo, branch, token);
    tree = res.tree;
    truncated = res.truncated;
    if (res.rate.rateRemaining != null) rateRemaining = res.rate.rateRemaining;
  } catch (e) {
    // 메타데이터는 받았으나 트리를 못 받음.
    if (e.code === 'rate_limit') {
      // 부분 결과: 트리/파일 검사 불가 → 신뢰 신호만으로 보고
      treeFailed = true;
    } else if (e.code === 'not_found') {
      // 브랜치 트리 없음 → 메타데이터만으로 부분 보고
      treeFailed = true;
    } else {
      // 네트워크 등도 부분 보고로 강등(메타는 확보됨)
      treeFailed = true;
    }
  }

  // ── 4. 우선순위 파일 선별 ──
  let scanLimitedReasons = [];
  if (truncated) {
    scanLimitedReasons.push('저장소가 너무 커 파일 트리 일부만 받았습니다(우선순위 파일만 검사).');
  }
  if (treeFailed) {
    scanLimitedReasons.push(
      '파일 트리를 가져오지 못해 코드 내용은 검사하지 못했습니다(저장소 평판 신호만 평가). GitHub 토큰을 입력하면 더 깊이 검사할 수 있습니다.'
    );
  }

  const { selected, skippedForLimit } = treeFailed
    ? { selected: [], skippedForLimit: 0 }
    : selectPriorityFiles(tree, { maxFiles });

  if (skippedForLimit > 0) {
    scanLimitedReasons.push(`스캔 한도(${maxFiles}개) 초과로 ${skippedForLimit}개 파일은 검사하지 못했습니다.`);
  }

  // ── 5. 내용 fetch & 스캔 ──
  const total = selected.length;
  const files = [];
  let scanned = 0;
  let fetchFailures = 0;
  emit(onProgress, { phase: 'scan', scanned: 0, total, rateRemaining });

  for (const path of selected) {
    // rate limit이 매우 낮아도 raw는 REST limit과 별개라 계속 진행 가능.
    const content = await fetchRawFile(owner, repo, branch, path, { maxBytes: 512 * 1024 });
    if (content == null) {
      fetchFailures++;
    } else {
      files.push({ path, content });
    }
    scanned++;
    emit(onProgress, { phase: 'scan', scanned, total, rateRemaining });
  }

  if (fetchFailures > 0) {
    scanLimitedReasons.push(`${fetchFailures}개 파일은 내용을 가져오지 못해 검사하지 못했습니다(미검사).`);
  }
  if (rateRemaining != null && rateRemaining <= RATE_WARN_THRESHOLD) {
    scanLimitedReasons.push(
      `GitHub API 잔여 호출이 적습니다(${rateRemaining}회). 토큰을 입력하면 한도가 늘어납니다.`
    );
  }

  // ── 6. 스캔 실행 ──
  emit(onProgress, { phase: 'scan-done', scanned, total, rateRemaining });
  let findings = scanFiles(files);

  // ── 6.5 v2 외부 인텔 강화 (#1~#4) ──
  // 후방호환: enrichment는 optional. 실패해도 throw하지 않고 intelErrors에 사유를 남긴다.
  // opts.enableIntel === false 면 v1 동작과 100% 동일(인텔 스킵).
  let enrichment; // undefined면 보고서에서 생략 → v1 후방호환
  let forensicAdjust = { trust: 0, stability: 0 };
  let contributorsCount; // 포렌식이 채우면 신호/점수에 반영
  if (opts.enableIntel !== false) {
    emit(onProgress, { phase: 'intel', scanned, total, rateRemaining });
    try {
      const intel = await runIntel(
        { owner, repo, branch, meta, tree, files },
        { token, onProgress, maxDeps: opts.maxDeps || 25 }
      );
      // 인텔 findings를 기존 findings에 병합(중복 제거·재정렬)
      findings = mergeFindings(findings, intel.findings || []);
      enrichment =
        intel.enrichment && Object.keys(intel.enrichment).length ? intel.enrichment : undefined;
      forensicAdjust = intel.forensicAdjust || forensicAdjust;
      if (
        enrichment &&
        enrichment.forensics &&
        typeof enrichment.forensics.contributors === 'number'
      ) {
        contributorsCount = enrichment.forensics.contributors;
      }
    } catch (e) {
      // runIntel은 내부적으로 실패를 흡수하지만, 만약을 대비한 최종 가드.
      enrichment = { intelErrors: ['외부 인텔 강화 단계에서 예기치 못한 오류가 발생했습니다.'] };
    }
  }

  const scanLimitedReason = scanLimitedReasons.length ? scanLimitedReasons.join(' ') : null;

  // ── 7. 점수 산출 ──
  emit(onProgress, { phase: 'score', scanned, total, rateRemaining });
  const scored = score({
    meta,
    tree,
    findings,
    scanLimitedReason,
    contributorsCount,
    forensicAdjust,
  });

  emit(onProgress, { phase: 'done', scanned, total, rateRemaining });

  // ── 8. VerdictReport 조립 (공유 데이터 계약) ──
  const report = {
    repo: {
      url: meta.htmlUrl || `https://github.com/${owner}/${repo}`,
      owner,
      name: repo,
      defaultBranch: meta.defaultBranch,
      stars: meta.stars,
      forks: meta.forks,
      createdAt: meta.createdAt || '',
      pushedAt: meta.pushedAt || '',
      license: meta.license,
      archived: meta.archived,
    },
    riskScore: scored.riskScore,
    scores: scored.scores,
    verdict: scored.verdict,
    dangerLock: scored.dangerLock,
    summary: scored.summary,
    findings,
    signals: scored.signals,
    scannedFiles: files.length,
    scanLimitedReason,
  };

  // v2: enrichment는 있을 때만 부착(후방호환 — 미지원/조회실패 시 키 자체를 생략).
  if (enrichment) {
    report.enrichment = enrichment;
  }

  return report;
}

// 보조 export (테스트/디버깅용)
export { parseRepoInput, engineError };
