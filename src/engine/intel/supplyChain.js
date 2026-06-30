// intel/supplyChain.js — #1 의존성 공급망 검사 (v2 최우선)
//
// 의존성 목록(package.json/requirements.txt/pyproject.toml)에서 추출한 패키지를
// 무료 공개 API로 교차 검증:
//   - OSV.dev (POST /v1/query)            : 알려진 취약점/악성 패키지
//   - npm registry (registry.npmjs.org)   : 최초 게시일/저장소/최신버전
//   - npm downloads (api.npmjs.org)        : 주간 다운로드 수
//   - PyPI (pypi.org/pypi/<pkg>/json)      : 게시 정보
//   - 타이포스쿼팅(레벤슈타인)            : 유명 패키지 오타 사칭
//
// 위험의 2차원 분리(중요 — risk-scoring.md 참조):
//   1) 악성 의도(malice)  → category 'dependency-risk'
//        · OSV 악성 패키지 = severity 'critical'
//          (악성 인정 기준: OSV id/aliases가 `MAL-`로 시작하거나, OSV 레코드가
//           명시적 malware 분류 필드를 가질 때만. summary/details의 "malicious"/
//           "malware" 단어 매칭은 사용하지 않는다 — 일반 CVE 설명에 흔히 등장하므로.)
//        · 타이포스쿼팅 사칭             = severity 'high'
//      이들은 critical 바닥(70)·dangerLock·danger를 트리거할 수 있다(기존대로 강처벌).
//   2) 공급망 위생(hygiene) → category 'dependency-hygiene'
//        · 의존성의 일반 CVE/GHSA(비-MAL-) 취약점.
//      거의 모든 실세계 저장소가 가진 정상적 위생 문제이므로:
//        · OSV CVSS가 critical이어도 finding severity는 최대 'high'로 캡(대개 'medium').
//        · critical 바닥(70)·dangerLock을 절대 트리거하지 않는다.
//        · scorer가 별도 누적 + 상한을 적용해 verdict를 danger로 못 올린다(최대 caution).
//      정보는 잃지 않는다 → enrichment.supplyChain.vulnerable 에 전부 보존(UI 표기).
//
// 산출:
//   - findings[]              : category 'dependency-risk'(악성) | 'dependency-hygiene'(일반 CVE)
//   - enrichment.supplyChain  : { ecosystem, checked, vulnerable[], typosquat[] }
//   - intelErrors[]           : 조회 실패 사유(정직성)
//
// 안전성: 외부 조회 실패는 throw 금지 → intelErrors에 누적. 미조회를 안전으로 위장하지 않음.

import {
  fetchJson,
  mapWithConcurrency,
  typosquatCheck,
  mapOsvSeverity,
} from './util.js';

const OSV_URL = 'https://api.osv.dev/v1/query';
const NPM_REGISTRY = 'https://registry.npmjs.org';
const NPM_DOWNLOADS = 'https://api.npmjs.org/downloads/point/last-week';
const PYPI_BASE = 'https://pypi.org/pypi';

const NEW_PACKAGE_DAYS = 30;
const LOW_DOWNLOAD_THRESHOLD = 50; // 주간 다운로드가 이보다 낮으면 의심 가중

// ── 악성(malware) 판정 — 엄격 ────────────────────────────────────────────────
// 패키지를 "악성"(critical, dangerLock 트리거 가능)으로 인정하는 기준을 좁힌다.
// 자유 텍스트(summary/details)에 "malicious"/"malware" 단어가 있다는 이유만으로는
// 악성으로 보지 않는다 — 일반 CVE 설명(예: "...via malicious URLs")에 흔히 등장하기 때문.
//
// 악성으로 인정하는 경우(둘 중 하나):
//   (1) OSV id 또는 aliases 중 하나가 `MAL-`로 시작(OSV의 malware 데이터베이스 식별자).
//   (2) OSV 레코드가 명시적 malware 분류 필드를 가짐:
//        - database_specific.malicious === true / type/category가 'malware'
//        - affected[].ecosystem_specific(.malicious / .type==='malware')
//        - affected[].database_specific(.malicious / .type==='malware')
//   ※ summary/details의 단어 매칭은 사용하지 않는다.
function startsWithMal(id) {
  return /^MAL-/i.test(String(id || '').trim());
}

function looksLikeMalwareField(obj) {
  if (!obj || typeof obj !== 'object') return false;
  if (obj.malicious === true || obj.malware === true) return true;
  const typeStr = String(obj.type || obj.category || obj.classification || obj.severity || '')
    .toLowerCase();
  return typeStr.includes('malware');
}

function isMalwareAdvisory(v) {
  if (!v || typeof v !== 'object') return false;
  // (1) MAL- id / alias
  const ids = [v.id, ...((Array.isArray(v.aliases) && v.aliases) || [])].filter(Boolean);
  if (ids.some(startsWithMal)) return true;
  // (2) 명시적 malware 분류 필드
  if (looksLikeMalwareField(v.database_specific)) return true;
  if (Array.isArray(v.affected)) {
    for (const a of v.affected) {
      if (!a || typeof a !== 'object') continue;
      if (looksLikeMalwareField(a.ecosystem_specific)) return true;
      if (looksLikeMalwareField(a.database_specific)) return true;
    }
  }
  return false;
}

function daysSince(iso) {
  if (!iso) return Infinity;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return Infinity;
  return (Date.now() - t) / (1000 * 60 * 60 * 24);
}

// OSV 단건 조회. {vulns:[{id,summary,severity}]} 또는 null.
async function queryOsv(name, ecosystem) {
  const r = await fetchJson(OSV_URL, {
    method: 'POST',
    body: { package: { name, ecosystem } },
    timeoutMs: 7000,
  });
  if (!r.ok) return { error: r.reason };
  const vulns = Array.isArray(r.json && r.json.vulns) ? r.json.vulns : [];
  return { vulns };
}

// npm registry 메타 조회.
async function queryNpmRegistry(name) {
  const r = await fetchJson(`${NPM_REGISTRY}/${encodeURIComponent(name).replace('%40', '@')}`, {
    timeoutMs: 7000,
  });
  if (!r.ok) return { error: r.reason };
  const j = r.json || {};
  const time = j.time || {};
  const latest = (j['dist-tags'] && j['dist-tags'].latest) || null;
  let repoUrl = null;
  if (j.repository) {
    repoUrl = typeof j.repository === 'string' ? j.repository : j.repository.url || null;
  }
  return {
    created: time.created || null,
    modified: time.modified || null,
    latest,
    repoUrl,
    versions: j.versions ? Object.keys(j.versions).length : 0,
  };
}

// npm 주간 다운로드.
async function queryNpmDownloads(name) {
  const r = await fetchJson(`${NPM_DOWNLOADS}/${encodeURIComponent(name).replace('%40', '@')}`, {
    timeoutMs: 6000,
  });
  if (!r.ok) return { error: r.reason };
  return { downloads: typeof r.json.downloads === 'number' ? r.json.downloads : null };
}

// PyPI 메타.
async function queryPyPI(name) {
  const r = await fetchJson(`${PYPI_BASE}/${encodeURIComponent(name)}/json`, { timeoutMs: 7000 });
  if (!r.ok) return { error: r.reason };
  const j = r.json || {};
  const info = j.info || {};
  const releases = j.releases || {};
  // 최초 릴리스 시각 추정
  let earliest = null;
  for (const ver of Object.keys(releases)) {
    const files = releases[ver];
    if (Array.isArray(files) && files[0] && files[0].upload_time_iso_8601) {
      const t = files[0].upload_time_iso_8601;
      if (!earliest || t < earliest) earliest = t;
    }
  }
  let repoUrl = null;
  const purls = info.project_urls || {};
  for (const k of Object.keys(purls)) {
    if (/source|repository|github|code/i.test(k)) {
      repoUrl = purls[k];
      break;
    }
  }
  if (!repoUrl && info.home_page) repoUrl = info.home_page;
  return {
    created: earliest,
    latest: info.version || null,
    repoUrl,
    versions: Object.keys(releases).length,
  };
}

/**
 * 공급망 검사 실행.
 * @param {{deps:Array, ecosystemHint?:string}} input
 * @param {{ maxDeps?:number, concurrency?:number, onProgress?:Function }} [opts]
 * @returns {Promise<{findings:Array, enrichment:object, intelErrors:string[]}>}
 */
export async function runSupplyChain(input, opts = {}) {
  const maxDeps = opts.maxDeps || 25;
  const concurrency = opts.concurrency || 5;
  const onProgress = opts.onProgress;
  const allDeps = (input && input.deps) || [];
  const findings = [];
  const intelErrors = [];
  const vulnerable = [];
  const typosquat = [];

  // 검사 대상 상위 N개(앱 의존성 우선, dev는 뒤로)
  const ordered = allDeps.slice().sort((a, b) => (a.dev === b.dev ? 0 : a.dev ? 1 : -1));
  const targets = ordered.slice(0, maxDeps);
  const ecosystems = new Set(targets.map((d) => d.ecosystem));
  const ecosystem = ecosystems.size === 1 ? [...ecosystems][0] : 'mixed';

  // 오프라인/조회 없이도 가능한 타이포스쿼팅 먼저(네트워크 불필요).
  for (const d of targets) {
    const ts = typosquatCheck(d.name);
    if (ts.suspect) {
      typosquat.push(d.name);
      findings.push({
        category: 'dependency-risk',
        severity: 'high',
        title: '타이포스쿼팅 의심 의존성',
        description: `의존성 "${d.name}" 이(가) 유명 패키지 "${ts.target}"와 매우 비슷합니다(편집거리 ${ts.distance}). 오타를 노린 가짜 악성 패키지일 수 있습니다.`,
        file: d.manifest || (input.manifests && input.manifests[0]) || 'package.json',
        line: null,
        snippet: `"${d.name}": "${d.version || '*'}"`,
        rule: 'intel-typosquat',
      });
    }
  }

  // 네트워크 조회(동시성 제한).
  const errSeen = new Set();
  function noteError(source, reason) {
    const key = `${source}:${reason}`;
    if (errSeen.has(key)) return;
    errSeen.add(key);
    intelErrors.push(`${source} 조회 실패(${reason})`);
  }

  let checked = 0;
  await mapWithConcurrency(
    targets,
    concurrency,
    async (d) => {
      const eco = d.ecosystem === 'PyPI' ? 'PyPI' : 'npm';
      // OSV (모든 생태계)
      const osv = await queryOsv(d.name, eco);
      if (osv.error) {
        noteError('OSV', osv.error);
      } else if (osv.vulns && osv.vulns.length) {
        for (const v of osv.vulns) {
          const rawSeverity = mapOsvSeverity(v);
          // advisory id: MAL- 식별자가 있으면 그것을 우선 표기(악성 근거 명시).
          const malAlias =
            (startsWithMal(v.id) && v.id) ||
            ((v.aliases || []).find(startsWithMal)) ||
            null;
          const advisoryId = malAlias || v.id || (v.aliases && v.aliases[0]) || 'unknown';
          // 악성 판정은 MAL- 식별자 또는 명시적 malware 분류 필드만 인정(자유 텍스트 금지).
          const isMalware = isMalwareAdvisory(v);
          if (isMalware) {
            // ── 악성 패키지: 악성 의도 → critical 유지(강처벌, dangerLock 가능) ──
            vulnerable.push({ name: d.name, advisory: advisoryId, severity: 'critical', malicious: true });
            findings.push({
              category: 'dependency-risk',
              severity: 'critical',
              title: '악성으로 알려진 의존성',
              description: `의존성 "${d.name}" 은(는) 악성 패키지로 보고된 이력이 있습니다(${advisoryId}). 설치하지 마세요.`,
              file: d.manifest || 'package.json',
              line: null,
              snippet: `"${d.name}": "${d.version || '*'}" — ${advisoryId}${v.summary ? ': ' + String(v.summary).slice(0, 120) : ''}`,
              rule: 'intel-osv-malicious',
            });
          } else {
            // ── 일반 CVE/GHSA: 공급망 위생 → severity 캡 ──
            // 절대 critical로 올리지 않는다(dangerLock/critical 바닥 트리거 금지).
            // 기본 medium. OSV가 critical/high로 평가한 아주 심각한 건만 high까지 허용.
            const hygieneSeverity =
              rawSeverity === 'critical' || rawSeverity === 'high' ? 'high' : 'medium';
            vulnerable.push({ name: d.name, advisory: advisoryId, severity: rawSeverity, hygiene: true });
            findings.push({
              category: 'dependency-hygiene',
              severity: hygieneSeverity,
              title: '알려진 취약점이 있는 의존성',
              description: `의존성 "${d.name}" 에 공개된 보안 취약점이 있습니다(${advisoryId}). 공급망 위생 문제로, 안전한 버전으로 업데이트를 권장합니다. (악성 의도가 아닌 일반 CVE입니다.)`,
              file: d.manifest || 'package.json',
              line: null,
              snippet: `"${d.name}": "${d.version || '*'}" — ${advisoryId}${v.summary ? ': ' + String(v.summary).slice(0, 120) : ''}`,
              rule: 'intel-osv-vuln',
            });
          }
        }
      }

      // 레지스트리 신뢰 신호
      if (eco === 'npm') {
        const reg = await queryNpmRegistry(d.name);
        if (reg.error) {
          if (reg.error !== 'not-found') noteError('npm', reg.error);
          else {
            // 레지스트리에 존재하지 않는 의존성(외부 URL/스코프 등) — 정상일 수 있어 finding 안 만듦
          }
        } else {
          const ageDays = daysSince(reg.created);
          const dl = await queryNpmDownloads(d.name);
          if (dl.error && dl.error !== 'not-found') noteError('npm-downloads', dl.error);
          const downloads = dl.downloads;
          const isNew = Number.isFinite(ageDays) && ageDays < NEW_PACKAGE_DAYS;
          const lowDl = typeof downloads === 'number' && downloads < LOW_DOWNLOAD_THRESHOLD;
          if (isNew && lowDl) {
            findings.push({
              category: 'dependency-risk',
              severity: 'medium',
              title: '신생·저다운로드 의존성',
              description: `의존성 "${d.name}" 은(는) 게시된 지 ${Math.floor(ageDays)}일밖에 안 됐고 주간 다운로드가 ${downloads}회로 매우 적습니다. 검증되지 않은 신규 패키지일 수 있습니다.`,
              file: d.manifest || 'package.json',
              line: null,
              snippet: `"${d.name}": 게시 ${Math.floor(ageDays)}일 전, 주간 다운로드 ${downloads}`,
              rule: 'intel-npm-newlowdl',
            });
          } else if (isNew) {
            findings.push({
              category: 'dependency-risk',
              severity: 'low',
              title: '최근 게시된 신생 의존성',
              description: `의존성 "${d.name}" 은(는) 게시된 지 ${Math.floor(ageDays)}일밖에 되지 않았습니다. 신뢰성이 충분히 검증되지 않았을 수 있습니다.`,
              file: d.manifest || 'package.json',
              line: null,
              snippet: `"${d.name}": 게시 ${Math.floor(ageDays)}일 전`,
              rule: 'intel-npm-new',
            });
          }
        }
      } else {
        const py = await queryPyPI(d.name);
        if (py.error) {
          if (py.error !== 'not-found') noteError('PyPI', py.error);
        } else {
          const ageDays = daysSince(py.created);
          if (Number.isFinite(ageDays) && ageDays < NEW_PACKAGE_DAYS) {
            findings.push({
              category: 'dependency-risk',
              severity: 'low',
              title: '최근 게시된 신생 의존성(PyPI)',
              description: `의존성 "${d.name}" 은(는) PyPI에 게시된 지 ${Math.floor(ageDays)}일밖에 되지 않았습니다. 신뢰성 검증이 부족할 수 있습니다.`,
              file: d.manifest || 'requirements.txt',
              line: null,
              snippet: `"${d.name}": 게시 ${Math.floor(ageDays)}일 전`,
              rule: 'intel-pypi-new',
            });
          }
        }
      }
    },
    (done, total) => {
      checked = done;
      if (typeof onProgress === 'function') {
        try {
          onProgress({ phase: 'intel-supplychain', scanned: done, total });
        } catch {
          /* noop */
        }
      }
    }
  );

  const enrichment = {
    supplyChain: {
      ecosystem,
      checked: targets.length,
      vulnerable,
      typosquat,
    },
  };

  return { findings, enrichment, intelErrors };
}

// 테스트/디버깅용 export(런타임 동작 변경 없음): 악성 판정 단위 검증에 사용.
export { isMalwareAdvisory as _isMalwareAdvisory };
