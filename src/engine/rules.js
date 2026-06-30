// rules.js — 정적 위협 탐지 룰셋
// threat-patterns.md의 7개 카테고리 룰을 조합 기반으로 구현한다.
//
// 핵심 철학(threat-patterns.md §1):
//  - 단일 시그널의 심각도는 낮다(false positive 多). 시그널이 결합되면 심각도가 급상승.
//  - 읽기+전송 = secret-exfiltration(critical), 다운로드+실행 = remote-code-exec(critical),
//    난독화+실행 = obfuscation(high).
//
// 각 룰: { id, category, severity, title, describe(ctx), match(text, fileCtx) -> [matchInfo] }
//  - match는 finding 후보(라인/스니펫 포함)를 0개 이상 반환. scanner가 카테고리·완화·점수를 처리.
//
// 모든 정규식은 'g' 플래그로 라인 위치를 잡는다. lastIndex 상태 누수를 막기 위해
// 매 호출마다 새 RegExp를 만들거나 exec 루프 후 lastIndex를 0으로 되돌린다.

export const SEVERITY = ['low', 'medium', 'high', 'critical'];
export const CATEGORIES = [
  'secret-exfiltration',
  'install-hook',
  'remote-code-exec',
  'obfuscation',
  'suspicious-network',
  'crypto-miner',
  'dependency-risk',
];

// ── 시그널 정규식 (조합 판단의 원자) ─────────────────────────────────────────

// 읽기 신호: 비밀/민감정보를 읽는 코드
const READ_SIGNALS = [
  /process\.env(?:\.[A-Z0-9_]+)?/,
  /os\.environ(?:\.get)?/,
  /os\.getenv\s*\(/,
  /fs\.readFileSync\s*\([^)]*(?:\.npmrc|\.env|id_rsa|\.aws|credentials|\.netrc)/i,
  /open\s*\([^)]*(?:\.env|\.aws|id_rsa|\.netrc|credentials)/i,
  /localStorage(?:\.getItem)?/,
  /document\.cookie/,
  /\$HOME\/\.(?:aws|ssh|npmrc|config)/,
  /\bcat\s+[^\n]*(?:\.env|id_rsa|credentials)/i,
  /\b(?:AWS_SECRET(?:_ACCESS_KEY)?|OPENAI_API_KEY|GITHUB_TOKEN|PRIVATE_KEY|MNEMONIC|SEED_PHRASE)\b/,
];

// 전송 신호: 외부로 데이터를 보내는 코드(외부 절대 URL/네트워크 호출)
const SEND_SIGNALS = [
  /fetch\s*\(\s*['"`]https?:\/\//i,
  /axios\s*\.\s*(?:post|get|put|request)\s*\(\s*['"`]?https?:\/\//i,
  /requests\s*\.\s*(?:post|get|put)\s*\(/i,
  /urllib(?:\.request)?\.urlopen\s*\(/i,
  /http\.client\.HTTPS?Connection\s*\(/i,
  /socket\s*\.\s*connect\s*\(/i,
  /\bcurl\s+[^\n]*(?:-d\b|--data|-X\s*POST|-F\b)/i,
  /\bwget\s+[^\n]*--post/i,
  /\bnc\s+[-0-9a-z. ]+\d{2,5}/i,
];

// 다운로드 신호: 외부에서 코드를 받아오는 코드
const DOWNLOAD_SIGNALS = [
  /\bcurl\s+[^\n|]*https?:\/\//i,
  /\bwget\s+[^\n|]*https?:\/\//i,
  /requests\s*\.\s*get\s*\([^)]*\)\s*\.\s*(?:text|content)/i,
  /urllib(?:\.request)?\.urlopen\s*\(/i,
  /fetch\s*\(\s*['"`]https?:\/\//i,
];

// 실행 신호: 받은/숨긴 것을 실행하는 코드
const EXEC_SIGNALS = [
  /\beval\s*\(/,
  /new\s+Function\s*\(/,
  /\bexec\s*\(/,
  /child_process|require\(['"`]child_process['"`]\)/,
  /subprocess\.(?:run|call|Popen|check_output)/,
  /os\.system\s*\(/,
];

// 난독화 디코드 신호
const DECODE_SIGNALS = [
  /\batob\s*\(/,
  /Buffer\.from\s*\([^)]*,\s*['"`]base64['"`]\s*\)/i,
  /base64\.b64decode\s*\(/i,
  /\bunescape\s*\(/,
  /String\.fromCharCode\s*\(/,
];

// 긴 base64/hex 리터럴(난독화 페이로드 후보)
const LONG_B64 = /['"`][A-Za-z0-9+/]{120,}={0,2}['"`]/;
const HEX_ESCAPE_SPAM = /(?:\\x[0-9a-fA-F]{2}){12,}/;

// ── secret-exfiltration 맥락 신호 ────────────────────────────────────────────
// "env 읽기 + 외부 https 전송"만으로는 critical을 매기지 않는다(정상 API 클라이언트가
// 흔히 이 형태다 — 예: ELEVENLABS_API_KEY를 api.elevenlabs.io로 인증 헤더로 전송).
// critical(danger/dangerLock)로 올리는 건 아래 추가 의심 신호가 있을 때만.

// (A) 의심스러운 목적지: 하드코딩 IP, 메신저/웹훅, 단축URL/pastebin.
const SUSPICIOUS_DEST_SIGNALS = [
  // 메신저/웹훅 — 탈취 데이터 유출 흔한 통로
  /discord(?:app)?\.com\/api\/webhooks\//i,
  /api\.telegram\.org\/bot/i,
  /hooks\.slack\.com\/services\//i,
  // 단축 URL / pastebin / 익명 업로드
  /https?:\/\/(?:bit\.ly|t\.co|tinyurl\.com|is\.gd|goo\.gl|ngrok\.io|trycloudflare\.com)\//i,
  /https?:\/\/(?:[a-z0-9-]+\.)?(?:pastebin\.com|paste\.ee|pastes\.io|hastebin\.com|transfer\.sh|0x0\.st|file\.io|requestbin|webhook\.site|pipedream\.net|interact\.sh|oast\.|burpcollaborator)/i,
  // http(s)://1.2.3.4(:port) 하드코딩 IP 목적지
  /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d{2,5})?/i,
  // nc(netcat)로 raw 전송
  /\bnc\s+[-0-9a-z. ]+\d{2,5}/i,
];

// (B) 광범위 수집: 환경변수 전체 직렬화/통째 전송, 또는 다수 시크릿 파일 읽기.
const BROAD_ENV_SIGNALS = [
  // process.env 통째 직렬화/전개/전송
  /JSON\.stringify\s*\(\s*process\.env\s*\)/i,
  /\.\.\.\s*process\.env\b/,
  /Object\.(?:entries|keys|values|assign)\s*\(\s*process\.env\s*\)/i,
  /\bbody\s*[:=]\s*process\.env\b/i,
  // os.environ 통째(파이썬): dict(os.environ) / json.dumps(os.environ) / os.environ.copy()
  /(?:json\.dumps|dict|str)\s*\(\s*os\.environ\b/i,
  /os\.environ\.copy\s*\(\s*\)/i,
  /\bdata\s*=\s*os\.environ\b/i,
];

// 다수 시크릿 파일(.aws/credentials, id_rsa, .npmrc, .ssh, .netrc) — 한 파일에서 여러 개면 광범위 수집.
const SECRET_FILE_SIGNALS = [
  /\.aws\/credentials/i,
  /\bid_rsa\b/i,
  /\.npmrc\b/i,
  /\.ssh\//i,
  /\.netrc\b/i,
  /\.config\/gcloud/i,
  /\.kube\/config/i,
];

// 단일 명명 키만 읽는지(정상 API 클라이언트 신호). *_API_KEY / *_TOKEN 등 명시적 단일 키.
const NAMED_KEY_READ = [
  /process\.env\.[A-Z0-9_]+/,
  /os\.environ(?:\.get)?\s*[(\[]\s*['"][A-Z0-9_]+['"]/,
  /os\.getenv\s*\(\s*['"][A-Z0-9_]+['"]/,
];

function countMatches(text, regexes) {
  let n = 0;
  for (const re of regexes) {
    if (new RegExp(re.source, re.flags.includes('i') ? 'i' : '').test(text)) n++;
  }
  return n;
}

// ── 헬퍼: 텍스트에서 정규식 배열 중 매치되는 모든 라인 수집 ──────────────────
function findLines(text, regexes) {
  const lines = text.split(/\r?\n/);
  const hits = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const re of regexes) {
      const r = new RegExp(re.source, re.flags.includes('i') ? 'i' : '');
      if (r.test(line)) {
        hits.push({ line: i + 1, text: line.trim().slice(0, 240) });
        break; // 한 라인에 여러 패턴이어도 1건만
      }
    }
  }
  return hits;
}

function anyMatch(text, regexes) {
  return regexes.some((re) => new RegExp(re.source, re.flags.includes('i') ? 'i' : '').test(text));
}

// 라인이 주석/문서 안인지 가벼운 판별(거짓양성 완화 — threat-patterns.md §9)
function looksLikeComment(lineText) {
  const t = lineText.trim();
  return (
    t.startsWith('//') ||
    t.startsWith('#') ||
    t.startsWith('*') ||
    t.startsWith('/*') ||
    t.startsWith('>') || // markdown quote
    t.startsWith('- ') // markdown list
  );
}

// ── 룰 정의 ──────────────────────────────────────────────────────────────────
// 각 룰의 match()는 finding 후보 배열을 반환:
//   { ruleId, category, severity, title, description, line, snippet }
// scanner가 경로 기반 완화/중복 처리를 추가로 수행한다.

export const RULES = [
  // 2. secret-exfiltration — 읽기 + 전송 결합(같은 파일)
  {
    id: 'secret-exfiltration-combo',
    category: 'secret-exfiltration',
    severity: 'critical',
    match(text) {
      const readHits = findLines(text, READ_SIGNALS).filter((h) => !looksLikeComment(h.text));
      const sendHits = findLines(text, SEND_SIGNALS).filter((h) => !looksLikeComment(h.text));
      if (readHits.length === 0 || sendHits.length === 0) return [];

      // ── 맥락 기반 심각도 결정(거짓양성 방지) ──
      // "env 읽기 + 외부 https 전송"만으로는 critical 금지. 정상 API 클라이언트가
      // 흔히 이 형태다(단일 API 키를 평범한 https 호스트에 인증 헤더로 전송).
      // critical은 (A) 의심 목적지 또는 (B) 광범위 수집 신호가 있을 때만.
      const hasSuspiciousDest = anyMatch(text, SUSPICIOUS_DEST_SIGNALS);
      const hasBroadEnv = anyMatch(text, BROAD_ENV_SIGNALS);
      const secretFileCount = countMatches(text, SECRET_FILE_SIGNALS);
      const hasMultiSecretFiles = secretFileCount >= 2;
      // 난독화 인접(전송 코드 근처에 인코딩/디코드 페이로드) → 의심 가중
      const hasObfuscation =
        (LONG_B64.test(text) || HEX_ESCAPE_SPAM.test(text)) && anyMatch(text, DECODE_SIGNALS);

      const escalate = hasSuspiciousDest || hasBroadEnv || hasMultiSecretFiles || hasObfuscation;

      const r = readHits[0];
      const s = sendHits[0];
      const snippet = `L${r.line}: ${r.text}\nL${s.line}: ${s.text}`;

      if (!escalate) {
        // 추가 의심 신호 없음 = 정상 API 사용일 가능성이 높다.
        // 단일 명명 키만 읽고(예: *_API_KEY) 평범한 https 호스트로 보내는 경우는
        // 노이즈이므로 미탐(권장). 그 외 모호한 경우만 low 정보 수준으로 남긴다.
        const readsOnlyNamedKey =
          anyMatch(text, NAMED_KEY_READ) &&
          !anyMatch(text, [
            /process\.env\b(?!\s*\.)/, // process.env 통째 참조
            /os\.environ\b(?!\s*[.[(])/, // os.environ 통째 참조
          ]);
        if (readsOnlyNamedKey) {
          // 정상 API 클라이언트(예: ELEVENLABS_API_KEY → api.elevenlabs.io) → 미탐.
          return [];
        }
        return [
          {
            ruleId: 'secret-exfiltration-combo',
            category: 'secret-exfiltration',
            severity: 'low',
            title: '환경변수 읽기 + 외부 전송(맥락 확인 필요)',
            description:
              '환경변수를 읽어 외부 서버로 보내는 코드가 있습니다. 다만 의심스러운 목적지나 환경변수 통째 수집 같은 추가 신호는 없어, 정상적인 API 호출일 가능성이 높습니다. 보내는 대상과 보내는 값이 정당한 서비스인지 한 번 확인하세요.',
            line: r.line,
            snippet,
          },
        ];
      }

      // ── 추가 의심 신호 있음 → critical 유지 ──
      let why;
      if (hasSuspiciousDest) why = '의심스러운 목적지(메신저 웹훅/하드코딩 IP/단축URL·pastebin 등)로';
      else if (hasBroadEnv) why = '환경변수를 통째로';
      else if (hasMultiSecretFiles) why = '여러 시크릿 파일(.aws/credentials·id_rsa 등)을';
      else why = '난독화와 함께';
      return [
        {
          ruleId: 'secret-exfiltration-combo',
          category: 'secret-exfiltration',
          severity: 'critical',
          title: '환경변수/시크릿 외부 유출 의심',
          description: `이 파일은 당신의 환경변수/시크릿을 읽어 ${why} 외부로 전송합니다. 정상적인 라이브러리에는 거의 없는 동작으로, 키 탈취 패턴입니다.`,
          line: r.line,
          snippet,
        },
      ];
    },
  },

  // 4. remote-code-exec — curl|bash 류
  {
    id: 'rce-pipe-shell',
    category: 'remote-code-exec',
    severity: 'critical',
    match(text) {
      const re = /\b(?:curl|wget)\s+[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b/gi;
      const out = [];
      const lines = text.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        if (looksLikeComment(lines[i])) continue;
        if (new RegExp(re.source, 'i').test(lines[i])) {
          out.push({
            ruleId: 'rce-pipe-shell',
            category: 'remote-code-exec',
            severity: 'critical',
            title: '외부 스크립트 즉시 실행(curl | bash)',
            description:
              '인터넷에서 스크립트를 내려받아 그 자리에서 바로 실행합니다. 내용이 언제든 악성으로 바뀔 수 있어 매우 위험합니다.',
            line: i + 1,
            snippet: lines[i].trim().slice(0, 240),
          });
        }
      }
      return out;
    },
  },

  // 4. remote-code-exec — 다운로드 + 실행 결합
  {
    id: 'rce-download-exec',
    category: 'remote-code-exec',
    severity: 'critical',
    match(text) {
      const dl = findLines(text, DOWNLOAD_SIGNALS).filter((h) => !looksLikeComment(h.text));
      const ex = findLines(text, EXEC_SIGNALS).filter((h) => !looksLikeComment(h.text));
      if (dl.length === 0 || ex.length === 0) return [];
      const d = dl[0];
      const e = ex[0];
      return [
        {
          ruleId: 'rce-download-exec',
          category: 'remote-code-exec',
          severity: 'critical',
          title: '원격에서 받은 코드를 실행',
          description:
            '외부에서 받아온 데이터를 eval/exec 등으로 실행합니다. 공격자가 임의 코드를 당신의 PC에서 돌릴 수 있습니다.',
          line: d.line,
          snippet: `L${d.line}: ${d.text}\nL${e.line}: ${e.text}`,
        },
      ];
    },
  },

  // 5. obfuscation — 긴 base64/hex + 디코드 + (실행 가능성)
  {
    id: 'obfuscation-decode-exec',
    category: 'obfuscation',
    severity: 'high',
    match(text) {
      const hasLongPayload = LONG_B64.test(text) || HEX_ESCAPE_SPAM.test(text);
      const hasDecode = anyMatch(text, DECODE_SIGNALS);
      const hasExec = anyMatch(text, EXEC_SIGNALS);
      if (!(hasLongPayload && hasDecode)) return [];
      const severity = hasExec ? 'critical' : 'high';
      // 대표 라인: 디코드 호출 위치
      const decodeHit = findLines(text, DECODE_SIGNALS)[0];
      return [
        {
          ruleId: 'obfuscation-decode-exec',
          category: 'obfuscation',
          severity,
          title: hasExec ? '난독화된 페이로드 디코드 후 실행' : '난독화된 페이로드 디코드',
          description: hasExec
            ? '숨겨둔(인코딩된) 코드를 풀어서 실행합니다. 코드를 일부러 숨겼다는 것 자체가 강한 위험 신호입니다.'
            : '인코딩으로 숨겨진 긴 데이터를 디코드합니다. 정상 코드라면 굳이 숨길 이유가 없어 의심됩니다.',
          line: decodeHit ? decodeHit.line : null,
          snippet: decodeHit ? decodeHit.text : '',
        },
      ];
    },
  },

  // 6. suspicious-network — discord/telegram/slack webhook
  {
    id: 'suspicious-webhook',
    category: 'suspicious-network',
    severity: 'high',
    match(text) {
      const re = /(?:discord(?:app)?\.com\/api\/webhooks\/|api\.telegram\.org\/bot|hooks\.slack\.com\/services\/)/i;
      const lines = text.split(/\r?\n/);
      const out = [];
      for (let i = 0; i < lines.length; i++) {
        if (looksLikeComment(lines[i])) continue;
        if (new RegExp(re.source, 'i').test(lines[i])) {
          out.push({
            ruleId: 'suspicious-webhook',
            category: 'suspicious-network',
            severity: 'high',
            title: '메신저 웹훅으로 데이터 전송',
            description:
              '디스코드/텔레그램/슬랙 웹훅으로 데이터를 보냅니다 — 탈취한 정보를 빼돌리는 흔한 통로입니다.',
            line: i + 1,
            snippet: lines[i].trim().slice(0, 240),
          });
        }
      }
      return out;
    },
  },

  // 6. suspicious-network — 하드코딩 공인 IP + 포트
  {
    id: 'suspicious-hardcoded-ip',
    category: 'suspicious-network',
    severity: 'medium',
    match(text) {
      const re = /\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b(?::\d{2,5})?/g;
      const lines = text.split(/\r?\n/);
      const out = [];
      for (let i = 0; i < lines.length; i++) {
        if (looksLikeComment(lines[i])) continue;
        const r = new RegExp(re.source, 'g');
        let m;
        while ((m = r.exec(lines[i])) !== null) {
          const a = Number(m[1]);
          const b = Number(m[2]);
          // 사설/로컬/예약 대역 제외
          const isPrivate =
            a === 10 ||
            a === 127 ||
            a === 0 ||
            (a === 192 && b === 168) ||
            (a === 172 && b >= 16 && b <= 31) ||
            a >= 224; // 멀티캐스트/예약
          const valid = a <= 255 && b <= 255 && Number(m[3]) <= 255 && Number(m[4]) <= 255;
          const hasPort = /:\d{2,5}$/.test(m[0]);
          if (valid && !isPrivate && hasPort) {
            out.push({
              ruleId: 'suspicious-hardcoded-ip',
              category: 'suspicious-network',
              severity: 'medium',
              title: '하드코딩된 외부 IP:포트',
              description:
                '코드에 외부 서버 IP와 포트가 직접 박혀 있습니다. 도메인 대신 IP를 쓰는 것은 추적을 피하려는 의도일 수 있습니다.',
              line: i + 1,
              snippet: lines[i].trim().slice(0, 240),
            });
            break; // 라인당 1건
          }
        }
      }
      return out;
    },
  },

  // 6. suspicious-network — 단축 URL로 스크립트 다운로드
  {
    id: 'suspicious-shortener',
    category: 'suspicious-network',
    severity: 'medium',
    match(text) {
      const re = /https?:\/\/(?:bit\.ly|t\.co|tinyurl\.com|is\.gd|goo\.gl)\//i;
      const lines = text.split(/\r?\n/);
      const out = [];
      for (let i = 0; i < lines.length; i++) {
        if (looksLikeComment(lines[i])) continue;
        if (new RegExp(re.source, 'i').test(lines[i])) {
          out.push({
            ruleId: 'suspicious-shortener',
            category: 'suspicious-network',
            severity: 'medium',
            title: '단축 URL 사용',
            description:
              '단축 URL은 실제 목적지를 가립니다. 다운로드/실행과 함께 쓰이면 악성 스크립트 은폐에 악용됩니다.',
            line: i + 1,
            snippet: lines[i].trim().slice(0, 240),
          });
        }
      }
      return out;
    },
  },

  // 7. crypto-miner
  {
    id: 'crypto-miner',
    category: 'crypto-miner',
    severity: 'high',
    match(text) {
      const re = /(?:stratum\+tcp:\/\/|xmrig|minerd|coinhive|cryptonight|--donate-level|nicehash|nanopool|supportxmr)/i;
      const lines = text.split(/\r?\n/);
      const out = [];
      for (let i = 0; i < lines.length; i++) {
        if (looksLikeComment(lines[i])) continue;
        if (new RegExp(re.source, 'i').test(lines[i])) {
          out.push({
            ruleId: 'crypto-miner',
            category: 'crypto-miner',
            severity: 'high',
            title: '암호화폐 채굴 코드',
            description:
              '당신의 컴퓨터 자원을 몰래 써서 암호화폐를 채굴하는 코드입니다. 전기/성능을 도둑맞게 됩니다.',
            line: i + 1,
            snippet: lines[i].trim().slice(0, 240),
          });
        }
      }
      return out;
    },
  },
];

// ── package.json 전용 룰 (구조 파싱 기반) ────────────────────────────────────
// install-hook(§3), dependency-risk(§8). JSON 파싱이 가능하면 정밀 분석.
const KNOWN_PACKAGES = [
  'react', 'express', 'lodash', 'axios', 'request', 'requests', 'chalk', 'commander',
  'webpack', 'next', 'vue', 'typescript', 'eslint', 'jest', 'mocha', 'colors',
  'moment', 'dotenv', 'uuid', 'bluebird', 'async',
];
// 흔한 타이포스쿼팅 변형 사전(정확 일치 시 의심)
const TYPOSQUAT = new Set([
  'reqeusts', 'requets', 'loadsh', 'lodahs', 'expresss', 'expres', 'momnet',
  'chalk-pkg', 'corss-env', 'crossenv', 'event-stream2', 'electron-native-notify',
]);

export function analyzePackageJson(text, filePath) {
  const out = [];
  let pkg;
  try {
    pkg = JSON.parse(text);
  } catch {
    return out; // 파싱 불가 시 일반 룰만 적용
  }

  // install-hook: preinstall/install/postinstall 스크립트
  const scripts = pkg.scripts || {};
  for (const hook of ['preinstall', 'install', 'postinstall']) {
    const val = scripts[hook];
    if (!val || typeof val !== 'string') continue;
    const hasExec = /\b(?:node|curl|wget|python3?|sh|bash|\.sh\b|chmod|eval)\b/i.test(val);
    if (!hasExec) continue;
    const isRce = /\b(?:curl|wget)\s+[^\n|]*\|\s*(?:sh|bash)/i.test(val);
    out.push({
      ruleId: isRce ? 'install-hook-rce' : 'install-hook-exec',
      category: isRce ? 'remote-code-exec' : 'install-hook',
      severity: isRce ? 'critical' : 'high',
      title: isRce ? '설치 훅에서 외부 스크립트 실행' : '설치 시 자동 실행 스크립트',
      description: isRce
        ? '이 패키지는 설치하는 순간 외부에서 코드를 내려받아 실행합니다. 코드를 보기도 전에 트리거됩니다.'
        : '이 패키지는 설치하는 순간 스크립트를 자동 실행합니다. 무엇을 하는지 설치 전에 반드시 확인해야 합니다.',
      line: null,
      snippet: `"${hook}": ${JSON.stringify(val)}`,
    });
  }

  // dependency-risk: 타이포스쿼팅 / git·tarball 의존성
  const deps = Object.assign({}, pkg.dependencies, pkg.devDependencies, pkg.optionalDependencies);
  for (const [name, ver] of Object.entries(deps)) {
    if (TYPOSQUAT.has(name) || isLikelyTyposquat(name)) {
      out.push({
        ruleId: 'dep-typosquat',
        category: 'dependency-risk',
        severity: 'medium',
        title: '타이포스쿼팅 의심 의존성',
        description: `의존성 "${name}" 이(가) 유명 패키지와 한 글자 차이로 보입니다. 가짜 패키지로 악성코드를 심는 흔한 수법입니다.`,
        line: null,
        snippet: `"${name}": "${ver}"`,
      });
    }
    if (typeof ver === 'string' && /^(?:git\+|https?:\/\/|file:|github:)/i.test(ver) && !/^github:[\w.-]+\/[\w.-]+$/i.test(ver)) {
      out.push({
        ruleId: 'dep-nonregistry',
        category: 'dependency-risk',
        severity: 'low',
        title: '비표준 출처 의존성',
        description: `의존성 "${name}" 이(가) npm 레지스트리가 아닌 외부 URL에서 받아옵니다. 출처를 신뢰할 수 있는지 확인하세요.`,
        line: null,
        snippet: `"${name}": "${ver}"`,
      });
    }
  }

  return out.map((f) => ({ ...f, _file: filePath }));
}

// 레벤슈타인 거리 1 + 길이 유사 → 타이포스쿼팅 의심
function isLikelyTyposquat(name) {
  const n = name.toLowerCase();
  for (const known of KNOWN_PACKAGES) {
    if (n === known) return false; // 정상 패키지
    if (Math.abs(n.length - known.length) <= 1 && levenshtein(n, known) === 1) {
      return true;
    }
  }
  return false;
}

function levenshtein(a, b) {
  const m = a.length;
  const n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[m][n];
}

// ── setup.py 전용 룰 (install-hook §3) ───────────────────────────────────────
export function analyzeSetupPy(text, filePath) {
  const out = [];
  const hasInstallOverride = /cmdclass\s*=|class\s+\w*Install\w*\s*\(|class\s+\w*Develop\w*\s*\(/.test(text);
  const hasExec = /\b(?:os\.system|subprocess\.(?:run|call|Popen|check_output)|exec\(|eval\()/.test(text);
  if (hasExec) {
    const decodeExec = /(?:base64\.b64decode|requests\.get)[^\n]*\)[^\n]*(?:exec|eval|system)/.test(text);
    out.push({
      ruleId: hasInstallOverride ? 'setup-install-hook' : 'setup-exec',
      category: 'install-hook',
      severity: hasInstallOverride || decodeExec ? 'high' : 'medium',
      title: hasInstallOverride ? '설치 단계 커스텀 실행 코드' : 'setup.py 내 외부 명령 실행',
      description: hasInstallOverride
        ? '이 패키지는 pip 설치 과정에서 임의 명령을 실행하도록 설치 동작을 바꿔놨습니다. 설치만 해도 코드가 돌아갑니다.'
        : 'setup.py가 시스템 명령을 실행합니다. 설치 시점에 의도치 않은 동작이 일어날 수 있습니다.',
      line: null,
      snippet: firstMatchSnippet(text, /(?:os\.system|subprocess\.\w+|cmdclass\s*=|exec\(|eval\()/),
      _file: filePath,
    });
  }
  return out;
}

function firstMatchSnippet(text, re) {
  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    if (re.test(line)) return line.trim().slice(0, 240);
  }
  return '';
}

// ── workflow yml 전용 룰 (install-hook §3, CI 외부 유출) ──────────────────────
export function analyzeWorkflow(text, filePath) {
  const out = [];
  // run: 스텝에서 시크릿을 외부로 보내는 패턴
  const exfil =
    /\$\{\{\s*secrets\./i.test(text) &&
    /(?:curl|wget)\s+[^\n]*(?:-d|--data|https?:\/\/)/i.test(text);
  if (exfil) {
    out.push({
      ruleId: 'ci-secret-exfil',
      category: 'secret-exfiltration',
      severity: 'high',
      title: 'CI에서 시크릿 외부 전송 의심',
      description:
        'GitHub Actions 워크플로가 저장된 시크릿을 외부 서버로 보내는 것으로 보입니다. CI 시크릿 탈취 패턴입니다.',
      line: null,
      snippet: firstMatchSnippet(text, /(?:curl|wget)\s+[^\n]*(?:-d|--data|https?:\/\/)/i),
      _file: filePath,
    });
  }
  const curlBash = /(?:curl|wget)\s+[^\n|]*\|\s*(?:sh|bash)/i.test(text);
  if (curlBash) {
    out.push({
      ruleId: 'ci-curl-bash',
      category: 'remote-code-exec',
      severity: 'high',
      title: 'CI에서 외부 스크립트 실행',
      description:
        '워크플로가 외부에서 스크립트를 내려받아 실행합니다. 공급망 공격에 악용될 수 있습니다.',
      line: null,
      snippet: firstMatchSnippet(text, /(?:curl|wget)\s+[^\n|]*\|\s*(?:sh|bash)/i),
      _file: filePath,
    });
  }
  return out;
}
