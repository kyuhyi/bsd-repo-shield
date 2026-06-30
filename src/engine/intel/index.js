// intel/index.js — v2 외부 인텔 오케스트레이터
//
// verifyRepo가 이 단일 진입점을 호출한다. 4종 강화(#1~#4)를 실행해:
//   - 새 findings[]를 모아 반환(호출자가 기존 findings에 병합)
//   - enrichment 객체를 조립(supplyChain/sourceMismatch/forensics/secrets/intelErrors)
//   - scorer가 쓸 forensicAdjust(trust/stability 보정) 반환
//
// 안전성 원칙(필수):
//   - 어떤 외부 조회 실패도 throw하지 않는다. 각 모듈이 intelErrors[]에 사유를 남긴다.
//   - enrichment는 optional — 전부 실패해도 호출자의 후방호환을 깨지 않는다.
//   - intelErrors가 비어있지 않으면 "미조회"이지 "안전"이 아니다(UI가 표기).

import { extractAllDeps } from './util.js';
import { runSupplyChain } from './supplyChain.js';
import { runSourceMismatch, detectPublishedPackage } from './sourceMismatch.js';
import { runForensics } from './forensics.js';
import { runSecrets } from './secrets.js';

/**
 * @param {{
 *   owner:string, repo:string, branch:string, meta:object, tree:Array,
 *   files:Array<{path,content}>
 * }} ctx
 * @param {{ token?:string, onProgress?:Function, maxDeps?:number }} [opts]
 * @returns {Promise<{ findings:Array, enrichment:object, forensicAdjust:{trust:number,stability:number} }>}
 */
export async function runIntel(ctx, opts = {}) {
  const { owner, repo, branch, meta, tree, files } = ctx;
  const token = opts.token;
  const onProgress = opts.onProgress;

  const fileMap = {};
  for (const f of files || []) {
    if (f && typeof f.content === 'string') fileMap[f.path] = f.content;
  }

  const findings = [];
  const enrichment = {};
  const intelErrors = [];
  let forensicAdjust = { trust: 0, stability: 0 };

  // 의존성 추출(로컬). 매니페스트별로 finding의 file을 채울 수 있도록 manifest 부착.
  const { deps, manifests } = extractAllDeps(fileMap);
  // 각 dep에 가장 그럴듯한 매니페스트 경로 부착(생태계 매칭)
  for (const d of deps) {
    if (!d.manifest) {
      const want = d.ecosystem === 'npm' ? 'package.json' : null;
      d.manifest =
        manifests.find((m) => (want ? m.toLowerCase().endsWith(want) : true)) || manifests[0] || null;
    }
  }

  // git 태그 수는 트리에서 직접 알 수 없으므로 0으로 둠(비대칭 검사는 보수적으로만 동작).
  const tagCount = undefined;

  // 게시 패키지명/생태계 탐지(로컬).
  const published = detectPublishedPackage(fileMap);

  // ── 병렬 실행(독립적) ──
  // 각 모듈은 자체적으로 실패를 흡수하므로 Promise.allSettled로 한 번 더 보호.
  const tasks = [];

  // #1 supply-chain (의존성이 있을 때만)
  if (deps.length) {
    tasks.push(
      runSupplyChain(
        { deps, manifests },
        { maxDeps: opts.maxDeps || 25, concurrency: 5, onProgress }
      ).then((r) => ({ kind: 'supply', r }))
    );
  }

  // #2 source-mismatch (게시 패키지명이 있을 때만 의미 있음; 없으면 note만)
  tasks.push(
    runSourceMismatch(
      {
        owner,
        repo,
        pushedAt: meta && meta.pushedAt,
        packageName: published.packageName,
        ecosystem: published.ecosystem,
        tagCount,
      },
      { onProgress }
    ).then((r) => ({ kind: 'mismatch', r }))
  );

  // #3 forensics (GitHub API)
  tasks.push(
    runForensics({ owner, repo, branch, meta }, { token, onProgress }).then((r) => ({
      kind: 'forensics',
      r,
    }))
  );

  // #4 secrets/entropy (로컬, 동기지만 통일성 위해 Promise화)
  tasks.push(
    Promise.resolve(runSecrets(files || [], { onProgress })).then((r) => ({ kind: 'secrets', r }))
  );

  const settled = await Promise.allSettled(tasks);
  for (const s of settled) {
    if (s.status !== 'fulfilled' || !s.value) {
      intelErrors.push('외부 인텔 모듈 실행 중 예기치 못한 오류가 발생했습니다.');
      continue;
    }
    const { kind, r } = s.value;
    if (r.findings) findings.push(...r.findings);
    if (r.enrichment) Object.assign(enrichment, r.enrichment);
    if (Array.isArray(r.intelErrors)) intelErrors.push(...r.intelErrors);
    if (kind === 'forensics' && r.forensicAdjust) forensicAdjust = r.forensicAdjust;
  }

  if (intelErrors.length) enrichment.intelErrors = intelErrors;

  return { findings, enrichment, forensicAdjust };
}
