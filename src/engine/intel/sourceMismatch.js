// intel/sourceMismatch.js — #2 "GitHub ≠ 게시된 패키지"
//
// 가장 교묘한 스미싱: GitHub 소스는 멀쩡한데 npm/PyPI에 게시된 패키지만 악성.
// 사용자는 GitHub를 보지만 실제 install은 레지스트리에서 받는다.
//
// 검사:
//   - package.json `name`(또는 pyproject project.name)으로 레지스트리 조회
//   - repository.url이 이 GitHub 저장소를 가리키는지 확인 → 불일치/부재면 finding
//   - 레지스트리 최신 게시 시점이 GitHub pushed_at보다 늦거나 동떨어졌으면 경고
//   - 게시 버전 수 ≫ git 태그 수 비대칭이면 가중
//
// 브라우저에서 tarball 바이트 diff는 어렵다 → "설치되는 코드는 이 저장소와 다를 수 있으니
// 게시된 패키지를 직접 확인하라"는 경고 수준으로 정직히 표기.
//
// 산출: findings[] (category 'source-mismatch'), enrichment.sourceMismatch, intelErrors[]

import { fetchJson } from './util.js';

const NPM_REGISTRY = 'https://registry.npmjs.org';
const PYPI_BASE = 'https://pypi.org/pypi';

const PUBLISH_GAP_DAYS = 180; // 레지스트리 게시본이 소스보다 이만큼 동떨어지면 경고

// repository.url 등에서 owner/repo 추출. 다양한 형태 정규화.
function parseRepoFromUrl(url) {
  if (!url || typeof url !== 'string') return null;
  // git+https://github.com/owner/repo.git, git://, ssh, github:owner/repo 등
  let s = url.trim();
  const ghShort = s.match(/^github:([\w.-]+)\/([\w.-]+)$/i);
  if (ghShort) return { owner: ghShort[1].toLowerCase(), repo: ghShort[2].replace(/\.git$/i, '').toLowerCase() };
  const m = s.match(/github\.com[:/]([\w.-]+)\/([\w.-]+?)(?:\.git)?(?:[/#?].*)?$/i);
  if (m) return { owner: m[1].toLowerCase(), repo: m[2].replace(/\.git$/i, '').toLowerCase() };
  return null;
}

function daysBetween(isoA, isoB) {
  const a = Date.parse(isoA);
  const b = Date.parse(isoB);
  if (Number.isNaN(a) || Number.isNaN(b)) return null;
  return Math.abs(a - b) / (1000 * 60 * 60 * 24);
}

// npm 패키지명 + 메타 조회.
async function lookupNpm(name) {
  const r = await fetchJson(`${NPM_REGISTRY}/${encodeURIComponent(name).replace('%40', '@')}`, {
    timeoutMs: 7000,
  });
  if (!r.ok) return { error: r.reason };
  const j = r.json || {};
  let repoUrl = null;
  if (j.repository) repoUrl = typeof j.repository === 'string' ? j.repository : j.repository.url || null;
  const time = j.time || {};
  const latest = (j['dist-tags'] && j['dist-tags'].latest) || null;
  return {
    registry: 'npm',
    repoUrl,
    latestVersion: latest,
    latestPublishedAt: latest && time[latest] ? time[latest] : time.modified || null,
    versionCount: j.versions ? Object.keys(j.versions).length : 0,
  };
}

async function lookupPyPI(name) {
  const r = await fetchJson(`${PYPI_BASE}/${encodeURIComponent(name)}/json`, { timeoutMs: 7000 });
  if (!r.ok) return { error: r.reason };
  const j = r.json || {};
  const info = j.info || {};
  let repoUrl = null;
  const purls = info.project_urls || {};
  for (const k of Object.keys(purls)) {
    if (/source|repository|github|code|homepage/i.test(k)) {
      const cand = purls[k];
      if (parseRepoFromUrl(cand)) {
        repoUrl = cand;
        break;
      }
      if (!repoUrl) repoUrl = cand;
    }
  }
  // 최신 버전 게시 시각
  const releases = j.releases || {};
  const latest = info.version || null;
  let latestPublishedAt = null;
  if (latest && Array.isArray(releases[latest]) && releases[latest][0]) {
    latestPublishedAt = releases[latest][0].upload_time_iso_8601 || null;
  }
  return {
    registry: 'PyPI',
    repoUrl,
    latestVersion: latest,
    latestPublishedAt,
    versionCount: Object.keys(releases).length,
  };
}

/**
 * source-mismatch 검사.
 * @param {{ owner:string, repo:string, pushedAt:string, packageName:string|null, ecosystem:'npm'|'PyPI'|null, tagCount?:number }} input
 * @param {{ onProgress?:Function }} [opts]
 * @returns {Promise<{findings:Array, enrichment:object, intelErrors:string[]}>}
 */
export async function runSourceMismatch(input, opts = {}) {
  const findings = [];
  const intelErrors = [];
  const { owner, repo, pushedAt, packageName, ecosystem } = input || {};

  if (typeof opts.onProgress === 'function') {
    try {
      opts.onProgress({ phase: 'intel-sourcematch', scanned: 0, total: 1 });
    } catch {
      /* noop */
    }
  }

  // 패키지명이 없으면 검사 불가(예: 라이브러리 아님). 정직히 note만.
  if (!packageName) {
    return {
      findings,
      enrichment: {
        sourceMismatch: {
          registry: null,
          repoMatches: null,
          note: '게시 패키지명을 확인할 수 없어 레지스트리 대조를 건너뜀(라이브러리가 아니거나 name 미지정).',
        },
      },
      intelErrors,
    };
  }

  const eco = ecosystem === 'PyPI' ? 'PyPI' : 'npm';
  const meta = eco === 'PyPI' ? await lookupPyPI(packageName) : await lookupNpm(packageName);

  if (typeof opts.onProgress === 'function') {
    try {
      opts.onProgress({ phase: 'intel-sourcematch', scanned: 1, total: 1 });
    } catch {
      /* noop */
    }
  }

  if (meta.error) {
    if (meta.error === 'not-found') {
      // 레지스트리에 같은 이름이 없음 — 미게시 라이브러리. mismatch는 아님.
      return {
        findings,
        enrichment: {
          sourceMismatch: {
            registry: eco,
            repoMatches: null,
            note: `"${packageName}" 이름의 패키지가 ${eco} 레지스트리에 없습니다(아직 미게시일 수 있음).`,
          },
        },
        intelErrors,
      };
    }
    intelErrors.push(`${eco} 레지스트리 조회 실패(${meta.error})`);
    return {
      findings,
      enrichment: {
        sourceMismatch: {
          registry: eco,
          repoMatches: null,
          note: '레지스트리 조회에 실패해 게시본-소스 대조를 완료하지 못했습니다.',
        },
      },
      intelErrors,
    };
  }

  // repository.url이 이 저장소를 가리키는가?
  const parsed = parseRepoFromUrl(meta.repoUrl);
  let repoMatches = null;
  const notes = [];
  if (!meta.repoUrl) {
    repoMatches = false;
    notes.push('게시된 패키지에 소스 저장소 링크가 없습니다.');
    findings.push({
      category: 'source-mismatch',
      severity: 'medium',
      title: '게시 패키지에 소스 저장소 정보 없음',
      description: `${eco}에 게시된 "${packageName}" 패키지에는 GitHub 저장소 링크가 없습니다. 설치되는 코드가 이 저장소와 같다고 보장할 수 없습니다.`,
      file: eco === 'PyPI' ? 'pyproject.toml' : 'package.json',
      line: null,
      snippet: `${eco}: ${packageName} (repository 미지정)`,
      rule: 'intel-mismatch-norepo',
    });
  } else if (parsed) {
    repoMatches = parsed.owner === String(owner).toLowerCase() && parsed.repo === String(repo).toLowerCase();
    if (!repoMatches) {
      notes.push(`게시 패키지가 가리키는 저장소(${parsed.owner}/${parsed.repo})가 검사 대상(${owner}/${repo})과 다릅니다.`);
      findings.push({
        category: 'source-mismatch',
        severity: 'high',
        title: '게시 패키지가 다른 저장소를 가리킴',
        description: `${eco}에 게시된 "${packageName}" 의 소스 링크가 이 저장소가 아니라 "${parsed.owner}/${parsed.repo}" 를 가리킵니다. 보고 있는 코드와 실제 설치되는 코드가 다를 수 있습니다.`,
        file: eco === 'PyPI' ? 'pyproject.toml' : 'package.json',
        line: null,
        snippet: `${eco} repository: ${meta.repoUrl}`,
        rule: 'intel-mismatch-repo',
      });
    } else {
      notes.push('게시 패키지의 저장소 링크가 이 저장소와 일치합니다.');
    }
  } else {
    repoMatches = false;
    notes.push(`게시 패키지의 저장소 링크(${meta.repoUrl})를 GitHub 저장소로 해석할 수 없습니다.`);
  }

  // 게시 시점 vs pushed_at 비대칭
  if (meta.latestPublishedAt && pushedAt) {
    const gap = daysBetween(meta.latestPublishedAt, pushedAt);
    const publishedLater = Date.parse(meta.latestPublishedAt) > Date.parse(pushedAt);
    if (gap != null && gap > PUBLISH_GAP_DAYS) {
      notes.push(`게시 시점과 소스 마지막 푸시가 약 ${Math.floor(gap)}일 차이.`);
      findings.push({
        category: 'source-mismatch',
        severity: publishedLater ? 'medium' : 'low',
        title: '게시본과 소스 시점 불일치',
        description: publishedLater
          ? `${eco}의 최신 게시본이 이 저장소 마지막 푸시보다 ${Math.floor(gap)}일 뒤에 올라왔습니다. 설치되는 코드가 저장소보다 새 버전(혹은 다른 코드)일 수 있습니다.`
          : `${eco} 게시본과 저장소 활동 시점이 ${Math.floor(gap)}일이나 동떨어져 있습니다. 게시된 패키지를 직접 확인하세요.`,
        file: eco === 'PyPI' ? 'pyproject.toml' : 'package.json',
        line: null,
        snippet: `게시: ${meta.latestPublishedAt} / 소스 push: ${pushedAt}`,
        rule: 'intel-mismatch-time',
      });
    }
  }

  // 버전 수 ≫ git 태그 수 비대칭
  if (typeof input.tagCount === 'number' && meta.versionCount > 0) {
    if (input.tagCount === 0 && meta.versionCount >= 3) {
      notes.push(`레지스트리에 ${meta.versionCount}개 버전이 게시되었으나 git 태그가 없습니다.`);
      findings.push({
        category: 'source-mismatch',
        severity: 'low',
        title: '게시 버전 수와 git 태그 비대칭',
        description: `${eco}에 ${meta.versionCount}개 버전이 게시됐지만 이 저장소에는 릴리스 태그가 없습니다. 게시 과정이 저장소 밖에서 이뤄졌을 수 있습니다.`,
        file: eco === 'PyPI' ? 'pyproject.toml' : 'package.json',
        line: null,
        snippet: `게시 버전 ${meta.versionCount}개 / git 태그 ${input.tagCount}개`,
        rule: 'intel-mismatch-versions',
      });
    }
  }

  // 항상 정직한 경고 note 추가(설치본은 직접 확인 권고)
  const note =
    notes.join(' ') +
    ' (참고: 설치되는 코드는 이 저장소와 다를 수 있으니, 게시된 패키지를 직접 확인하세요.)';

  return {
    findings,
    enrichment: {
      sourceMismatch: {
        registry: eco,
        repoMatches,
        note: note.trim(),
      },
    },
    intelErrors,
  };
}

// 매니페스트에서 패키지명/생태계 추출(브라우저, 외부 호출 없음).
export function detectPublishedPackage(fileMap) {
  for (const [path, content] of Object.entries(fileMap || {})) {
    if (typeof content !== 'string') continue;
    const base = path.toLowerCase().split('/').pop();
    if (base === 'package.json') {
      try {
        const j = JSON.parse(content);
        if (j && typeof j.name === 'string' && j.name && !j.private) {
          return { packageName: j.name, ecosystem: 'npm' };
        }
      } catch {
        /* ignore */
      }
    }
  }
  // pyproject.toml의 project.name 또는 poetry name
  for (const [path, content] of Object.entries(fileMap || {})) {
    if (typeof content !== 'string') continue;
    const base = path.toLowerCase().split('/').pop();
    if (base === 'pyproject.toml') {
      const m = content.match(/(?:^|\n)\s*name\s*=\s*["']([A-Za-z0-9._-]+)["']/);
      if (m) return { packageName: m[1], ecosystem: 'PyPI' };
    }
  }
  return { packageName: null, ecosystem: null };
}

export { parseRepoFromUrl };
