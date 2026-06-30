// githubClient.js — 브라우저 측 GitHub 공개 API 클라이언트
// 백엔드 없음. fetch만 사용. Node 전용 API(fs 등) 절대 사용 금지.
//
// 책임:
//  - 다양한 형태의 GitHub URL/owner-repo 입력 파싱
//  - api.github.com 메타데이터·트리 조회
//  - raw.githubusercontent.com 파일 raw 조회(REST rate limit과 별개)
//  - rate limit 헤더 처리
//  - 우선순위 파일 선별

const API_BASE = 'https://api.github.com';
const RAW_BASE = 'https://raw.githubusercontent.com';
const NUL = String.fromCharCode(0);

// code 필드를 가진 에러 생성 헬퍼. code ∈ {'invalid_url','not_found','rate_limit','network'}
export function engineError(message, code) {
  const err = new Error(message);
  err.code = code;
  return err;
}

// ── 1. URL 파싱 ─────────────────────────────────────────────────────────────
// 허용 입력(모두 {owner, repo, branch|null}로 정규화):
//   https://github.com/owner/repo
//   https://github.com/owner/repo.git
//   https://github.com/owner/repo/tree/branch
//   https://github.com/owner/repo/blob/branch/path...
//   git@github.com:owner/repo.git
//   owner/repo
//   owner/repo@branch
export function parseRepoInput(input) {
  if (typeof input !== 'string' || !input.trim()) {
    throw engineError('GitHub 저장소 URL 또는 "owner/repo" 형식을 입력하세요.', 'invalid_url');
  }
  let s = input.trim();

  // git@github.com:owner/repo.git  →  owner/repo
  const scpMatch = s.match(/^git@github\.com:([^/]+)\/(.+?)(?:\.git)?$/i);
  if (scpMatch) {
    return normalizeOwnerRepo(scpMatch[1], scpMatch[2], null);
  }

  // URL 형태 (github.com 포함)
  if (/github\.com/i.test(s)) {
    // 프로토콜 없는 github.com/... 도 허용
    if (!/^https?:\/\//i.test(s)) s = 'https://' + s.replace(/^\/+/, '');
    let u;
    try {
      u = new URL(s);
    } catch {
      throw engineError('올바른 GitHub URL이 아닙니다.', 'invalid_url');
    }
    if (!/(^|\.)github\.com$/i.test(u.hostname)) {
      throw engineError('github.com 도메인의 저장소만 검사할 수 있습니다.', 'invalid_url');
    }
    const parts = u.pathname.split('/').filter(Boolean);
    if (parts.length < 2) {
      throw engineError('URL에서 owner/repo를 찾을 수 없습니다.', 'invalid_url');
    }
    const owner = parts[0];
    const repo = parts[1].replace(/\.git$/i, '');
    let branch = null;
    // /tree/<branch> 또는 /blob/<branch>/...
    if ((parts[2] === 'tree' || parts[2] === 'blob') && parts[3]) {
      branch = decodeURIComponent(parts[3]);
    }
    return normalizeOwnerRepo(owner, repo, branch);
  }

  // owner/repo[@branch]  (단순 형태)
  const simple = s.match(/^([^/\s]+)\/([^/\s@]+)(?:@(.+))?$/);
  if (simple) {
    return normalizeOwnerRepo(simple[1], simple[2].replace(/\.git$/i, ''), simple[3] || null);
  }

  throw engineError(
    '입력을 GitHub 저장소로 해석할 수 없습니다. 예: owner/repo 또는 https://github.com/owner/repo',
    'invalid_url'
  );
}

function normalizeOwnerRepo(owner, repo, branch) {
  owner = (owner || '').trim();
  repo = (repo || '').trim().replace(/\.git$/i, '');
  if (!owner || !repo) {
    throw engineError('owner/repo를 해석할 수 없습니다.', 'invalid_url');
  }
  // GitHub 식별자 허용 문자만(러프 검증)
  if (!/^[A-Za-z0-9._-]+$/.test(owner) || !/^[A-Za-z0-9._-]+$/.test(repo)) {
    throw engineError('owner/repo에 허용되지 않는 문자가 있습니다.', 'invalid_url');
  }
  return { owner, repo, branch: branch || null };
}

// ── 헤더 구성 ────────────────────────────────────────────────────────────────
function buildHeaders(token) {
  const headers = { Accept: 'application/vnd.github+json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

// rate limit 헤더 추출
function readRateHeaders(res) {
  const remaining = res.headers.get('X-RateLimit-Remaining');
  const reset = res.headers.get('X-RateLimit-Reset');
  return {
    rateRemaining: remaining == null ? null : Number(remaining),
    rateReset: reset == null ? null : Number(reset),
  };
}

// 네트워크 1회 재시도 래퍼. 네트워크 자체 실패만 재시도(HTTP 상태는 호출자가 판단).
async function fetchOnceWithRetry(url, options) {
  try {
    return await fetch(url, options);
  } catch {
    try {
      return await fetch(url, options);
    } catch {
      throw engineError('네트워크 요청에 실패했습니다. 연결을 확인하세요.', 'network');
    }
  }
}

// ── 2. 메타데이터 조회 ───────────────────────────────────────────────────────
// 반환: { meta, rate }
export async function fetchMetadata(owner, repo, token) {
  const url = `${API_BASE}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;
  const res = await fetchOnceWithRetry(url, { headers: buildHeaders(token) });
  const rate = readRateHeaders(res);

  if (res.status === 404) {
    throw engineError('저장소를 찾을 수 없거나 비공개입니다.', 'not_found');
  }
  if (res.status === 403 && rate.rateRemaining === 0) {
    throw engineError(
      'GitHub API 요청 한도를 초과했습니다. 잠시 후 다시 시도하거나 GitHub 토큰을 입력하세요.',
      'rate_limit'
    );
  }
  if (!res.ok) {
    throw engineError(`저장소 메타데이터 조회 실패 (HTTP ${res.status}).`, 'network');
  }

  let json;
  try {
    json = await res.json();
  } catch {
    throw engineError('메타데이터 응답을 해석할 수 없습니다.', 'network');
  }

  const meta = {
    owner: json.owner ? json.owner.login : owner,
    name: json.name || repo,
    defaultBranch: json.default_branch || 'main',
    stars: json.stargazers_count || 0,
    forks: json.forks_count || 0,
    createdAt: json.created_at || null,
    pushedAt: json.pushed_at || null,
    license:
      json.license && json.license.spdx_id && json.license.spdx_id !== 'NOASSERTION'
        ? json.license.spdx_id
        : (json.license && json.license.name) || null,
    archived: !!json.archived,
    openIssues: json.open_issues_count || 0,
    subscribers: json.subscribers_count || 0,
    htmlUrl: json.html_url || `https://github.com/${owner}/${repo}`,
  };
  return { meta, rate };
}

// ── 3. 파일 트리 조회 ────────────────────────────────────────────────────────
// 반환: { tree: [{path, type, size}], truncated, rate }
export async function fetchTree(owner, repo, branch, token) {
  const url =
    `${API_BASE}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}` +
    `/git/trees/${encodeURIComponent(branch)}?recursive=1`;
  const res = await fetchOnceWithRetry(url, { headers: buildHeaders(token) });
  const rate = readRateHeaders(res);

  if (res.status === 404) {
    throw engineError('지정한 브랜치의 파일 트리를 찾을 수 없습니다.', 'not_found');
  }
  if (res.status === 403 && rate.rateRemaining === 0) {
    throw engineError('GitHub API 요청 한도를 초과했습니다.', 'rate_limit');
  }
  if (!res.ok) {
    throw engineError(`파일 트리 조회 실패 (HTTP ${res.status}).`, 'network');
  }

  let json;
  try {
    json = await res.json();
  } catch {
    throw engineError('파일 트리 응답을 해석할 수 없습니다.', 'network');
  }

  const tree = Array.isArray(json.tree)
    ? json.tree
        .filter((n) => n && n.path)
        .map((n) => ({ path: n.path, type: n.type, size: n.size || 0 }))
    : [];
  return { tree, truncated: !!json.truncated, rate };
}

// ── 4. raw 파일 조회 ─────────────────────────────────────────────────────────
// raw.githubusercontent.com — REST rate limit과 별개. 토큰 불필요(공개).
// 반환: 텍스트 내용 또는 null(실패/대용량/바이너리)
export async function fetchRawFile(owner, repo, branch, path, opts = {}) {
  const maxBytes = opts.maxBytes || 512 * 1024; // 512KB 상한
  const encodedPath = path.split('/').map(encodeURIComponent).join('/');
  const url = `${RAW_BASE}/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/${encodeURIComponent(
    branch
  )}/${encodedPath}`;
  let res;
  try {
    res = await fetchOnceWithRetry(url, { headers: { Accept: 'text/plain' } });
  } catch {
    return null; // 개별 파일 실패는 치명적이지 않음 — 미검사로 처리
  }
  if (!res || !res.ok) return null;

  // 바이너리 추정 컨텐츠 타입 스킵
  const ctype = res.headers.get('Content-Type') || '';
  if (/image\/|application\/octet-stream|application\/zip|font\//i.test(ctype)) {
    return null;
  }
  const lenHeader = res.headers.get('Content-Length');
  if (lenHeader && Number(lenHeader) > maxBytes) return null;

  let text;
  try {
    text = await res.text();
  } catch {
    return null;
  }
  if (text.length > maxBytes) text = text.slice(0, maxBytes);
  // NUL 바이트가 있으면 바이너리로 간주하고 스킵
  if (text.indexOf(NUL) !== -1) return null;
  return text;
}

// ── 5. 우선순위 파일 선별 ────────────────────────────────────────────────────
// github-api.md §5의 우선순위에 따라 스캔 대상 파일을 정렬·선별한다.
// 반환: { selected: [path...], skippedForLimit: number }
export function selectPriorityFiles(tree, opts = {}) {
  const maxFiles = opts.maxFiles || 40;
  const maxBytes = opts.maxBytes || 512 * 1024;
  const blobs = tree.filter((n) => n.type === 'blob');

  // 우선순위 점수(낮을수록 먼저). github-api.md §5 순서 반영.
  function priority(path) {
    const lower = path.toLowerCase();
    const base = lower.split('/').pop();

    // 1군: 매니페스트/설치 정의
    if (/^(package\.json|package-lock\.json|setup\.py|pyproject\.toml|requirements\.txt|setup\.cfg)$/.test(base))
      return 0;
    // 2군: 셸/도커/메이크
    if (/\.sh$/.test(base) || base === 'dockerfile' || /^docker-compose.*\.ya?ml$/.test(base) || base === 'makefile')
      return 1;
    // 3군: CI 워크플로 / npmrc / git hooks
    if (lower.startsWith('.github/workflows/') && /\.ya?ml$/.test(base)) return 2;
    if (base === '.npmrc' || lower.includes('.git/hooks')) return 2;
    // 4군: 진입점
    if (/^(index\.(js|ts|mjs|cjs)|main\.py|app\.py|cli\.(js|ts|py)|server\.(js|ts|py))$/.test(base)) return 3;
    if (lower.startsWith('bin/')) return 3;
    // 5군: 일반 소스(작은 것 우선)
    if (/\.(js|jsx|ts|tsx|mjs|cjs|py|rb|go|rs|php|ps1|bat|cmd)$/.test(base)) return 5;
    // 그 외(문서/이미지 등)
    return 9;
  }

  const SCANNABLE_MAX = 7; // 9 미만만 스캔 후보
  const candidates = blobs
    .map((b) => ({ ...b, prio: priority(b.path) }))
    .filter((b) => b.prio < SCANNABLE_MAX)
    // 큰 파일은 raw 조회 단계에서 어차피 잘리므로 선별에서 제외(트리 목록엔 남음)
    .filter((b) => b.size <= maxBytes);

  candidates.sort((a, b) => {
    if (a.prio !== b.prio) return a.prio - b.prio;
    return a.size - b.size; // 같은 군에서는 작은 파일 우선
  });

  const selected = candidates.slice(0, maxFiles).map((b) => b.path);
  const skippedForLimit = Math.max(0, candidates.length - selected.length);
  return { selected, skippedForLimit };
}

// 트리에 특정 경로/패턴이 존재하는지 — suitability 산출용
export function treeHas(tree, predicate) {
  return tree.some((n) => predicate(n.path.toLowerCase(), n));
}

// ── 6. v2 포렌식 보조 조회 ────────────────────────────────────────────────────
// 모두 실패해도 throw 하지 않고 { ok:false, reason } 형태로 돌려준다(인텔 정직성).
// 인증 없이도 호출 가능하나 rate limit(60/h)을 공유하므로 호출자가 신중히 사용.

async function safeApiJson(url, token, timeoutMs = 7000) {
  const hasAbort = typeof AbortController !== 'undefined';
  const controller = hasAbort ? new AbortController() : null;
  let timer = null;
  if (controller) timer = setTimeout(() => { try { controller.abort(); } catch { /* noop */ } }, timeoutMs);
  let res;
  try {
    res = await fetch(url, {
      headers: buildHeaders(token),
      ...(controller ? { signal: controller.signal } : {}),
    });
  } catch (e) {
    if (timer) clearTimeout(timer);
    return { ok: false, reason: e && e.name === 'AbortError' ? 'timeout' : 'network-or-cors' };
  }
  if (timer) clearTimeout(timer);
  const rate = readRateHeaders(res);
  if (res.status === 404) return { ok: false, reason: 'not-found', rate };
  if (res.status === 403 && rate.rateRemaining === 0) return { ok: false, reason: 'rate-limited', rate };
  if (!res.ok) return { ok: false, reason: `http-${res.status}`, rate };
  let json;
  try {
    json = await res.json();
  } catch {
    return { ok: false, reason: 'bad-json', rate };
  }
  return { ok: true, json, rate };
}

// 소유자 계정 정보: created_at 등. 반환 { ok, createdAt, type } 또는 { ok:false, reason }
export async function fetchOwnerInfo(owner, token) {
  const url = `${API_BASE}/users/${encodeURIComponent(owner)}`;
  const r = await safeApiJson(url, token);
  if (!r.ok) return r;
  return { ok: true, createdAt: r.json.created_at || null, type: r.json.type || null, rate: r.rate };
}

// 기여자 목록(상위 N). 반환 { ok, count, bots, top } 또는 { ok:false, reason }
export async function fetchContributors(owner, repo, token, perPage = 10) {
  const url = `${API_BASE}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contributors?per_page=${perPage}&anon=0`;
  const r = await safeApiJson(url, token);
  if (!r.ok) return r;
  const arr = Array.isArray(r.json) ? r.json : [];
  const bots = arr.filter((c) => c && (c.type === 'Bot' || /\[bot\]$/i.test(c.login || ''))).length;
  return {
    ok: true,
    count: arr.length,
    bots,
    top: arr.slice(0, perPage).map((c) => ({ login: c.login, contributions: c.contributions })),
    rate: r.rate,
  };
}

// 최근 커밋(상위 N). 반환 { ok, commits:[{date, author, login}] } 또는 { ok:false, reason }
export async function fetchRecentCommits(owner, repo, branch, token, perPage = 20) {
  const url =
    `${API_BASE}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/commits` +
    `?per_page=${perPage}${branch ? `&sha=${encodeURIComponent(branch)}` : ''}`;
  const r = await safeApiJson(url, token);
  if (!r.ok) return r;
  const arr = Array.isArray(r.json) ? r.json : [];
  const commits = arr.map((c) => {
    const commit = c.commit || {};
    const author = commit.author || {};
    return {
      date: author.date || null,
      author: author.name || null,
      login: (c.author && c.author.login) || null,
    };
  });
  return { ok: true, commits, rate: r.rate };
}
