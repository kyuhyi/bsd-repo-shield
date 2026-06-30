// intel/secrets.js — #4 엔트로피·시크릿 스캔
//
// 정규식 회피가 어려운 통계적 + 시그니처 탐지(외부 네트워크 불필요 — 로컬 분석).
//
//   - 커밋된 시크릿(gitleaks 스타일): AWS/GCP 키, PRIVATE KEY, 토큰 패턴이
//     저장소에 커밋되어 있으면 finding(저장소 위생 + 공급망 위험).
//   - Shannon 엔트로피: 고엔트로피(>4.0) 장문 문자열 + 디코드/실행 인접 → obfuscation 강화.
//     일반 데이터(이미지 base64)와 구분 위해 실행 신호 인접 여부로 가중.
//   - minified 원본이 빌드산출물 아닌데 소스로 커밋 → 의심 가중.
//
// 산출: findings[] (category 'secret-exfiltration' 노출 시크릿 / 'obfuscation' 고엔트로피),
//        enrichment.secrets { count, samples }.
// 네트워크 없음 → intelErrors 없음.

import { shannonEntropy } from './util.js';

// 커밋된 시크릿 시그니처. kind는 사람이 읽는 분류.
const SECRET_SIGNATURES = [
  { kind: 'AWS Access Key', re: /\bAKIA[0-9A-Z]{16}\b/, sev: 'high' },
  { kind: 'AWS Secret Key', re: /\baws_secret_access_key\s*[=:]\s*['"]?[A-Za-z0-9/+]{40}['"]?/i, sev: 'high' },
  { kind: 'GitHub Token', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/, sev: 'high' },
  { kind: 'GitHub PAT (classic)', re: /\b[0-9a-f]{40}\b(?=.*github)/i, sev: 'medium' },
  { kind: 'Google API Key', re: /\bAIza[0-9A-Za-z\-_]{35}\b/, sev: 'high' },
  { kind: 'GCP Service Account', re: /"type"\s*:\s*"service_account"/, sev: 'high' },
  { kind: 'Slack Token', re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/, sev: 'high' },
  { kind: 'Stripe Secret Key', re: /\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b/, sev: 'high' },
  { kind: 'OpenAI Key', re: /\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/, sev: 'high' },
  { kind: 'Private Key Block', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/, sev: 'high' },
  { kind: 'Generic API Secret', re: /(?:api[_-]?key|secret|token|password)\s*[=:]\s*['"][A-Za-z0-9_\-]{24,}['"]/i, sev: 'medium' },
];

// 디코드/실행 신호(엔트로피 가중용)
const DECODE_NEAR = /\b(?:atob|b64decode|fromCharCode|unescape|Buffer\.from)\b|base64/i;
const EXEC_NEAR = /\b(?:eval|exec|Function|child_process|subprocess|os\.system|spawn)\b/;

// 고엔트로피 후보 토큰(긴 영숫자/base64/hex 리터럴)
const TOKEN_RE = /['"`]([A-Za-z0-9+/=_-]{40,})['"`]/g;

// 시크릿이 placeholder/예시인지 가벼운 판별(거짓양성 완화)
function looksLikePlaceholder(s) {
  return /your[-_ ]?(?:key|token|secret)|example|xxxx+|placeholder|<[a-z_]+>|\bdummy\b|\bfake\b|0000000000/i.test(s);
}

// 라인이 주석인지 가벼운 판별
function isComment(line) {
  const t = line.trim();
  return t.startsWith('//') || t.startsWith('#') || t.startsWith('*');
}

// minified 추정: 한 줄이 매우 길고 세미콜론/중괄호 밀도 높음. 소스로 커밋된 .min.js가 아닌 경우.
function looksMinified(text, path) {
  const lines = text.split(/\r?\n/);
  const longLines = lines.filter((l) => l.length > 500);
  if (longLines.length === 0) return false;
  const isBuildArtifactName = /\.min\.(?:js|css)$|\bdist\/|\bbuild\/|\bvendor\//i.test(path);
  // .min.js 같은 빌드산출물 이름이면 정상으로 간주
  if (isBuildArtifactName) return false;
  // 일반 소스(.js/.ts)인데 500자+ 라인이 다수면 의심
  return /\.(?:js|ts|mjs|cjs)$/i.test(path) && longLines.length >= 1;
}

/**
 * 단일 파일 시크릿/엔트로피 스캔.
 * @returns {{ findings:Array, secrets:Array<{file,kind}> }}
 */
function scanFileSecrets(path, text) {
  const findings = [];
  const secrets = [];
  const lines = text.split(/\r?\n/);

  // 1) 커밋된 시크릿 시그니처
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (isComment(line)) continue;
    for (const sig of SECRET_SIGNATURES) {
      if (sig.re.test(line)) {
        if (looksLikePlaceholder(line)) continue;
        secrets.push({ file: path, kind: sig.kind });
        findings.push({
          category: 'secret-exfiltration',
          severity: sig.sev,
          title: `노출된 시크릿: ${sig.kind}`,
          description: `저장소에 ${sig.kind} 형태의 자격증명이 그대로 커밋되어 있습니다. 노출된 키는 즉시 폐기·교체해야 하며, 이런 위생 문제는 공급망 위험 신호이기도 합니다.`,
          file: path,
          line: i + 1,
          // 스니펫은 키 일부를 마스킹해서 노출 최소화
          snippet: maskSecret(line.trim().slice(0, 200)),
          rule: 'intel-committed-secret',
        });
        break; // 라인당 1건
      }
    }
  }

  // 2) Shannon 엔트로피 — 고엔트로피 장문 + 디코드/실행 인접
  const hasDecodeNear = DECODE_NEAR.test(text);
  const hasExecNear = EXEC_NEAR.test(text);
  let m;
  TOKEN_RE.lastIndex = 0;
  let highEntropyReported = false;
  while ((m = TOKEN_RE.exec(text)) !== null) {
    const token = m[1];
    const H = shannonEntropy(token);
    if (H > 4.0 && token.length >= 60) {
      // 일반 데이터(이미지 등)와 구분: 디코드/실행 인접 시에만 obfuscation finding
      if ((hasDecodeNear || hasExecNear) && !highEntropyReported) {
        // 라인 번호 추정
        const upto = text.slice(0, m.index);
        const lineNo = upto.split(/\r?\n/).length;
        findings.push({
          category: 'obfuscation',
          severity: hasExecNear && hasDecodeNear ? 'high' : 'medium',
          title: '고엔트로피 난독화 페이로드 의심',
          description:
            hasExecNear && hasDecodeNear
              ? '무작위에 가까운(고엔트로피) 긴 문자열이 디코드·실행 코드와 함께 있습니다. 숨겨둔 악성 페이로드일 가능성이 높습니다.'
              : '무작위에 가까운 긴 문자열을 디코드하는 코드가 있습니다. 정상 코드라면 굳이 숨길 이유가 없어 의심됩니다.',
          file: path,
          line: lineNo,
          snippet: `엔트로피 ${H.toFixed(2)} bits/char, 길이 ${token.length}: ${token.slice(0, 48)}…`,
          rule: 'intel-entropy-payload',
        });
        highEntropyReported = true; // 파일당 1건으로 제한(스팸 방지)
      }
    }
  }

  // 3) minified 소스 커밋 의심(엔트로피·실행 인접 시에만 가중)
  if (looksMinified(text, path) && (hasDecodeNear || hasExecNear)) {
    findings.push({
      category: 'obfuscation',
      severity: 'medium',
      title: '난독화/압축된 소스 커밋',
      description:
        '빌드 산출물이 아닌 위치에 압축(minified)된 코드가 커밋되어 있고 디코드/실행 신호가 함께 있습니다. 사람이 읽기 어렵게 만든 의도가 의심됩니다.',
      file: path,
      line: null,
      snippet: '(minified source — 한 줄에 압축된 코드)',
      rule: 'intel-minified-source',
    });
  }

  return { findings, secrets };
}

// 시크릿 값 마스킹: 긴 토큰의 가운데를 가린다.
function maskSecret(s) {
  return s.replace(/([A-Za-z0-9/+_-]{6})[A-Za-z0-9/+_-]{8,}([A-Za-z0-9/+_-]{4})/g, '$1…$2');
}

/**
 * 여러 파일에 대한 시크릿/엔트로피 스캔.
 * @param {Array<{path,content}>} files
 * @param {{ onProgress?:Function }} [opts]
 * @returns {{ findings:Array, enrichment:object, intelErrors:string[] }}
 */
export function runSecrets(files, opts = {}) {
  const allFindings = [];
  const allSecrets = [];
  const list = Array.isArray(files) ? files : [];
  let done = 0;
  for (const f of list) {
    if (!f || typeof f.content !== 'string') {
      done++;
      continue;
    }
    const { findings, secrets } = scanFileSecrets(f.path, f.content);
    allFindings.push(...findings);
    allSecrets.push(...secrets);
    done++;
    if (typeof opts.onProgress === 'function') {
      try {
        opts.onProgress({ phase: 'intel-secrets', scanned: done, total: list.length });
      } catch {
        /* noop */
      }
    }
  }

  return {
    findings: allFindings,
    enrichment: {
      secrets: {
        count: allSecrets.length,
        samples: allSecrets.slice(0, 10),
      },
    },
    intelErrors: [],
  };
}

export { scanFileSecrets, maskSecret };
