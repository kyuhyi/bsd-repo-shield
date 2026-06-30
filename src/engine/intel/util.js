// intel/util.js — v2 외부 인텔 공용 유틸 (순수 브라우저 ESM, fetch만)
//
// 책임:
//  - 타임아웃·1회 재시도가 붙은 안전한 JSON/텍스트 fetch (CORS/네트워크 실패를 throw 대신 표준화)
//  - 동시성 제한 풀(mapWithConcurrency)
//  - Shannon 엔트로피
//  - 레벤슈타인 거리 / 타이포스쿼팅 판정
//  - 의존성 추출 파서(package.json / requirements.txt / pyproject.toml)
//
// 안전성 원칙: 외부 조회 실패는 throw 하지 않는다. {ok,false, reason} 형태로 돌려
//             호출자가 enrichment.intelErrors[]에 정직히 누적하게 한다.

const DEFAULT_TIMEOUT = 7000;

// AbortController 기반 타임아웃 fetch. 네트워크/타임아웃/CORS 차단을 모두 흡수.
async function timedFetch(url, options = {}, timeoutMs = DEFAULT_TIMEOUT) {
  // AbortController가 없는 환경 대비
  const hasAbort = typeof AbortController !== 'undefined';
  const controller = hasAbort ? new AbortController() : null;
  let timer = null;
  if (controller) {
    timer = setTimeout(() => {
      try {
        controller.abort();
      } catch {
        /* noop */
      }
    }, timeoutMs);
  }
  try {
    const res = await fetch(url, {
      ...options,
      ...(controller ? { signal: controller.signal } : {}),
    });
    return res;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

// JSON GET/POST. 성공 시 {ok:true, status, json}, 실패 시 {ok:false, status, reason}.
// CORS·네트워크·타임아웃은 throw가 아니라 ok:false로 반환된다.
export async function fetchJson(url, opts = {}) {
  const { method = 'GET', body, headers = {}, timeoutMs = DEFAULT_TIMEOUT, retry = true } = opts;
  const init = { method, headers: { Accept: 'application/json', ...headers } };
  if (body !== undefined) {
    init.body = typeof body === 'string' ? body : JSON.stringify(body);
    if (!init.headers['Content-Type']) init.headers['Content-Type'] = 'application/json';
  }

  let lastReason = 'unknown';
  const attempts = retry ? 2 : 1;
  for (let i = 0; i < attempts; i++) {
    let res;
    try {
      res = await timedFetch(url, init, timeoutMs);
    } catch (e) {
      // AbortError(타임아웃) 또는 TypeError(CORS/네트워크 차단)
      lastReason =
        e && e.name === 'AbortError' ? 'timeout' : 'network-or-cors';
      continue; // 재시도
    }
    if (res.status === 404) {
      return { ok: false, status: 404, reason: 'not-found' };
    }
    if (res.status === 429) {
      return { ok: false, status: 429, reason: 'rate-limited' };
    }
    if (!res.ok) {
      return { ok: false, status: res.status, reason: `http-${res.status}` };
    }
    let json;
    try {
      json = await res.json();
    } catch {
      return { ok: false, status: res.status, reason: 'bad-json' };
    }
    return { ok: true, status: res.status, json };
  }
  return { ok: false, status: 0, reason: lastReason };
}

// 동시성 제한 map. items 각각에 worker(item, idx)를 적용하되 동시에 limit개만 실행.
// onEach(optional)는 각 항목 완료마다 (doneCount, total) 보고.
export async function mapWithConcurrency(items, limit, worker, onEach) {
  const results = new Array(items.length);
  let next = 0;
  let done = 0;
  const total = items.length;
  const n = Math.max(1, Math.min(limit, total || 1));

  async function runner() {
    while (true) {
      const idx = next++;
      if (idx >= total) return;
      try {
        results[idx] = await worker(items[idx], idx);
      } catch (e) {
        results[idx] = { __error: true, reason: (e && e.message) || 'worker-error' };
      }
      done++;
      if (typeof onEach === 'function') {
        try {
          onEach(done, total);
        } catch {
          /* noop */
        }
      }
    }
  }

  const runners = [];
  for (let i = 0; i < n; i++) runners.push(runner());
  await Promise.all(runners);
  return results;
}

// ── Shannon 엔트로피 (bits/char) ─────────────────────────────────────────────
export function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = Object.create(null);
  for (let i = 0; i < str.length; i++) {
    const c = str[i];
    freq[c] = (freq[c] || 0) + 1;
  }
  const len = str.length;
  let H = 0;
  for (const c in freq) {
    const p = freq[c] / len;
    H -= p * Math.log2(p);
  }
  return H;
}

// ── 레벤슈타인 거리 ──────────────────────────────────────────────────────────
export function levenshtein(a, b) {
  a = String(a);
  b = String(b);
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  // 1차원 DP (메모리 절약)
  let prev = new Array(n + 1);
  let curr = new Array(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;
  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
    }
    const tmp = prev;
    prev = curr;
    curr = tmp;
  }
  return prev[n];
}

// 유명 패키지 사전(npm + PyPI 혼합). 타이포스쿼팅 비교 기준.
export const POPULAR_PACKAGES = [
  // npm
  'react', 'react-dom', 'lodash', 'express', 'axios', 'chalk', 'commander',
  'webpack', 'next', 'vue', 'typescript', 'eslint', 'jest', 'mocha', 'colors',
  'moment', 'dotenv', 'uuid', 'bluebird', 'async', 'request', 'cross-env',
  'node-fetch', 'underscore', 'jquery', 'babel-core', 'rimraf', 'glob',
  // PyPI
  'requests', 'urllib3', 'numpy', 'pandas', 'flask', 'django', 'setuptools',
  'pillow', 'beautifulsoup4', 'python-dateutil', 'pyyaml', 'cryptography',
  'boto3', 'scipy', 'matplotlib', 'pytest', 'click', 'jinja2', 'colorama',
];

// 편집거리 1~2 + 길이 유사 → 타이포스쿼팅 후보. 정확히 유명 패키지면 false.
// 반환: { suspect:boolean, target:string|null, distance:number }
export function typosquatCheck(name) {
  const n = String(name || '').toLowerCase().trim();
  if (!n) return { suspect: false, target: null, distance: 0 };
  for (const known of POPULAR_PACKAGES) {
    if (n === known) return { suspect: false, target: null, distance: 0 };
  }
  let best = null;
  let bestDist = Infinity;
  for (const known of POPULAR_PACKAGES) {
    // 길이 차가 2 초과면 스킵(빠른 컷)
    if (Math.abs(n.length - known.length) > 2) continue;
    const d = levenshtein(n, known);
    if (d < bestDist) {
      bestDist = d;
      best = known;
    }
  }
  // 너무 짧은 이름(<=3)은 거리1도 흔하므로 제외(거짓양성 방지)
  if (best && n.length >= 4 && (bestDist === 1 || (bestDist === 2 && n.length >= 6))) {
    return { suspect: true, target: best, distance: bestDist };
  }
  return { suspect: false, target: best, distance: bestDist };
}

// ── 의존성 추출 ──────────────────────────────────────────────────────────────
// 반환: [{ name, version, ecosystem: 'npm'|'PyPI', dev:boolean }]

export function extractNpmDeps(packageJsonText) {
  const out = [];
  let pkg;
  try {
    pkg = JSON.parse(packageJsonText);
  } catch {
    return out;
  }
  const groups = [
    [pkg.dependencies, false],
    [pkg.devDependencies, true],
    [pkg.optionalDependencies, false],
    [pkg.peerDependencies, false],
  ];
  const seen = new Set();
  for (const [grp, dev] of groups) {
    if (!grp || typeof grp !== 'object') continue;
    for (const [name, version] of Object.entries(grp)) {
      if (seen.has(name)) continue;
      seen.add(name);
      out.push({ name, version: String(version), ecosystem: 'npm', dev });
    }
  }
  return out;
}

export function extractRequirementsTxt(text) {
  const out = [];
  const seen = new Set();
  const lines = String(text || '').split(/\r?\n/);
  for (let raw of lines) {
    let line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith('-')) continue; // -r, -e, --hash 등 스킵
    // 인라인 주석 제거
    const hashIdx = line.indexOf(' #');
    if (hashIdx >= 0) line = line.slice(0, hashIdx).trim();
    // 환경마커/엑스트라 제거: pkg[extra]; marker
    line = line.split(';')[0].trim();
    // name (==|>=|<=|~=|!=|<|>|===) version  또는 그냥 name
    const m = line.match(/^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(?:(==|>=|<=|~=|!=|===|<|>)\s*([A-Za-z0-9._*+!-]+))?/);
    if (!m) continue;
    const name = m[1];
    const version = m[3] || '';
    if (seen.has(name.toLowerCase())) continue;
    seen.add(name.toLowerCase());
    out.push({ name, version, ecosystem: 'PyPI', dev: false });
  }
  return out;
}

// pyproject.toml 의존성 추출(정규식 기반 — 완전한 TOML 파서 없이 핵심만).
// PEP 621 [project] dependencies = [...], 그리고 [tool.poetry.dependencies] 둘 다 처리.
export function extractPyproject(text) {
  const out = [];
  const seen = new Set();
  const src = String(text || '');

  function pushDep(name, version, dev) {
    const key = String(name || '').toLowerCase();
    if (!name || key === 'python' || seen.has(key)) return;
    seen.add(key);
    out.push({ name, version: version || '', ecosystem: 'PyPI', dev: !!dev });
  }

  // PEP 621: dependencies = [ "requests>=2.0", "flask", ... ]
  const depArrayMatch = src.match(/(?:^|\n)\s*dependencies\s*=\s*\[([\s\S]*?)\]/);
  if (depArrayMatch) {
    const items = depArrayMatch[1].match(/["']([^"']+)["']/g) || [];
    for (const it of items) {
      const spec = it.replace(/["']/g, '').trim();
      const mm = spec.match(/^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(.*)$/);
      if (mm) pushDep(mm[1], mm[2] ? mm[2].split(';')[0].trim() : '', false);
    }
  }

  // optional-dependencies / project.optional-dependencies 그룹들
  const optBlocks = src.match(/\[\s*([\w.-]+\.)?optional-dependencies\s*\][\s\S]*?(?=\n\[|$)/g) || [];
  for (const block of optBlocks) {
    const items = block.match(/["']([^"'=<>~!]+(?:[=<>~!][^"']*)?)["']/g) || [];
    for (const it of items) {
      const spec = it.replace(/["']/g, '').trim();
      const mm = spec.match(/^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(.*)$/);
      if (mm && mm[1]) pushDep(mm[1], mm[2] ? mm[2].split(';')[0].trim() : '', true);
    }
  }

  // Poetry: [tool.poetry.dependencies] 와 .dev-dependencies / .group.*.dependencies
  const poetryBlocks = src.match(/\[\s*tool\.poetry(?:\.[\w.-]+)?\.(?:dev-)?dependencies\s*\][\s\S]*?(?=\n\[|$)/g) || [];
  for (const block of poetryBlocks) {
    const isDev = /dev-dependencies|\.dev\./.test(block.split('\n')[0]);
    const lines = block.split(/\r?\n/).slice(1);
    for (const line of lines) {
      const lm = line.match(/^\s*([A-Za-z0-9._-]+)\s*=\s*(.+)$/);
      if (!lm) continue;
      let ver = lm[2].trim();
      // version = { version = "^1.0" } 형태에서 버전만 추출
      const inner = ver.match(/version\s*=\s*["']([^"']+)["']/);
      if (inner) ver = inner[1];
      else ver = ver.replace(/["'{}]/g, '').trim();
      pushDep(lm[1], ver, isDev);
    }
  }

  return out;
}

// 트리/파일맵에서 의존성 매니페스트를 찾아 통합 추출.
// fileMap: { path -> content }. 반환: { deps:[...], manifests:[paths] }
export function extractAllDeps(fileMap) {
  const deps = [];
  const manifests = [];
  for (const [path, content] of Object.entries(fileMap || {})) {
    if (typeof content !== 'string') continue;
    const base = path.toLowerCase().split('/').pop();
    if (base === 'package.json') {
      const d = extractNpmDeps(content);
      if (d.length) {
        deps.push(...d);
        manifests.push(path);
      }
    } else if (base === 'requirements.txt') {
      const d = extractRequirementsTxt(content);
      if (d.length) {
        deps.push(...d);
        manifests.push(path);
      }
    } else if (base === 'pyproject.toml') {
      const d = extractPyproject(content);
      if (d.length) {
        deps.push(...d);
        manifests.push(path);
      }
    }
  }
  // 중복 제거(name+ecosystem)
  const seen = new Set();
  const unique = [];
  for (const d of deps) {
    const key = `${d.ecosystem}:${d.name.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(d);
  }
  return { deps: unique, manifests };
}

// OSV severity → 계약 Severity 매핑.
export function mapOsvSeverity(advisory) {
  // CVSS score가 있으면 그걸로, 없으면 database_specific.severity 문자열로.
  let score = null;
  if (Array.isArray(advisory.severity)) {
    for (const s of advisory.severity) {
      if (s && typeof s.score === 'string') {
        const m = s.score.match(/CVSS:3\.[01]\/.*$/);
        // score 문자열이 CVSS 벡터인 경우 숫자 추출 어려움 → database_specific 우선
      }
    }
  }
  const ds = advisory.database_specific || {};
  const sevStr = String(ds.severity || ds.cvss_severity || '').toUpperCase();
  if (sevStr.includes('CRITICAL')) return 'critical';
  if (sevStr.includes('HIGH')) return 'high';
  if (sevStr.includes('MODERATE') || sevStr.includes('MEDIUM')) return 'medium';
  if (sevStr.includes('LOW')) return 'low';
  // 악성 패키지(MAL-) ID는 critical로 격상
  const ids = [advisory.id, ...(advisory.aliases || [])].filter(Boolean);
  if (ids.some((id) => /^MAL-/i.test(id))) return 'critical';
  return 'medium'; // 기본: 알려진 취약점은 최소 medium
}
