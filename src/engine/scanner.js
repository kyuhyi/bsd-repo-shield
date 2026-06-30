// scanner.js — 선별 파일에 룰을 적용해 findings[]를 생성한다.
//
// 책임:
//  - 각 파일 내용에 일반 룰(RULES) + 파일타입 전용 룰(package.json/setup.py/workflow) 적용
//  - 테스트/예제/문서 경로 매치는 심각도 1단계 완화(threat-patterns.md §9)
//    단, secret-exfiltration은 완화 폭을 작게(critical→high까지만, 그 이하로 안 내림은 정책상 유지)
//  - finding을 계약(Finding) 형태로 정규화하고 안정적 id 부여

import {
  RULES,
  analyzePackageJson,
  analyzeSetupPy,
  analyzeWorkflow,
  SEVERITY,
} from './rules.js';

// 완화 대상 경로(테스트/예제/문서)
function isLeniencyPath(path) {
  const p = path.toLowerCase();
  return (
    /(?:^|\/)(?:test|tests|__tests__|spec|__mocks__|examples?|sample|samples|fixtures?|docs?)(?:\/|$)/.test(p) ||
    /\.(?:test|spec)\.[a-z]+$/.test(p) ||
    /\.md$/.test(p)
  );
}

function downgrade(severity, steps) {
  const idx = SEVERITY.indexOf(severity);
  if (idx < 0) return severity;
  return SEVERITY[Math.max(0, idx - steps)];
}

// 파일 타입별 전용 룰 라우팅
function fileTypeRules(path, text) {
  const base = path.toLowerCase().split('/').pop();
  const lower = path.toLowerCase();
  const out = [];
  if (base === 'package.json') {
    out.push(...analyzePackageJson(text, path));
  } else if (base === 'setup.py') {
    out.push(...analyzeSetupPy(text, path));
  } else if (lower.startsWith('.github/workflows/') && /\.ya?ml$/.test(base)) {
    out.push(...analyzeWorkflow(text, path));
  }
  return out;
}

// 단일 파일 스캔
function scanFile(path, text) {
  const raw = [];

  // 1) 일반 룰
  for (const rule of RULES) {
    let hits = [];
    try {
      hits = rule.match(text) || [];
    } catch {
      hits = [];
    }
    for (const h of hits) raw.push({ ...h, _file: path });
  }

  // 2) 파일타입 전용 룰
  raw.push(...fileTypeRules(path, text));

  // 3) 경로 완화 적용
  const lenient = isLeniencyPath(path);
  return raw.map((f) => {
    let severity = f.severity;
    if (lenient) {
      // secret-exfiltration / remote-code-exec(critical)은 1단계만 약하게, 그 외는 1단계
      if (f.category === 'secret-exfiltration') {
        // 완화 폭 작게: critical 유지, high 이하만 1단계 내림
        if (severity !== 'critical') severity = downgrade(severity, 1);
      } else {
        severity = downgrade(severity, 1);
      }
    }
    return {
      category: f.category,
      severity,
      title: f.title,
      description: f.description,
      file: f._file || path,
      line: typeof f.line === 'number' ? f.line : null,
      snippet: typeof f.snippet === 'string' ? f.snippet : '',
      rule: f.ruleId,
      _lenient: lenient,
    };
  });
}

// 안정적 finding id 부여
function makeId(f, seq) {
  return `f-${seq}-${f.rule}`;
}

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

// 여러 파일을 스캔해 정렬된 findings[] 반환
// files: [{ path, content|null }]  (content가 null이면 미검사 — 호출자가 별도 집계)
export function scanFiles(files) {
  const findings = [];
  let seq = 0;
  for (const f of files) {
    if (!f || typeof f.content !== 'string') continue;
    const fileFindings = scanFile(f.path, f.content);
    for (const ff of fileFindings) {
      findings.push({
        id: makeId(ff, seq++),
        category: ff.category,
        severity: ff.severity,
        title: ff.title,
        description: ff.description,
        file: ff.file,
        line: ff.line,
        snippet: ff.snippet,
        rule: ff.rule,
      });
    }
  }

  // 중복 제거: 같은 (rule, file, line) 은 1건만
  const seen = new Set();
  const deduped = [];
  for (const f of findings) {
    const key = `${f.rule}|${f.file}|${f.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(f);
  }

  // 심각도순 정렬(critical 먼저), 동급은 카테고리/파일 순
  deduped.sort(sortFindings);

  return deduped;
}

function sortFindings(a, b) {
  const s = (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9);
  if (s !== 0) return s;
  if (a.category !== b.category) return a.category.localeCompare(b.category);
  return a.file.localeCompare(b.file);
}

// v2: 외부 인텔이 만든 findings를 기존 findings에 병합.
// - 인텔 finding은 id가 없을 수 있으므로 안정적 id를 부여
// - (rule, file, line) 중복 제거(기존 룰 결과와도 대조)
// - 심각도순 재정렬
// 반환: 병합·정렬된 새 배열(입력 비파괴)
export function mergeFindings(base, extra) {
  const out = [];
  const seen = new Set();
  let seq = 0;

  function add(f, idPrefix) {
    if (!f || !f.category || !f.severity) return;
    const line = typeof f.line === 'number' ? f.line : null;
    const key = `${f.rule}|${f.file}|${line}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({
      id: f.id || `${idPrefix}-${seq++}-${f.rule || 'rule'}`,
      category: f.category,
      severity: f.severity,
      title: f.title || '',
      description: f.description || '',
      file: f.file || '',
      line,
      snippet: typeof f.snippet === 'string' ? f.snippet : '',
      rule: f.rule || '',
    });
  }

  for (const f of base || []) add(f, 'f');
  for (const f of extra || []) add(f, 'fi');

  out.sort(sortFindings);
  return out;
}
