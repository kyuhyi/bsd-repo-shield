# Threat Patterns — 탐지 룰셋 상세

목차
1. 공통 원칙: 조합으로 판단
2. secret-exfiltration (API키/시크릿 유출)
3. install-hook (설치 스크립트 실행)
4. remote-code-exec (원격 코드 실행)
5. obfuscation (난독화 페이로드)
6. suspicious-network (유출 채널)
7. crypto-miner
8. dependency-risk
9. 거짓양성 관리

---

## 1. 공통 원칙: 조합으로 판단

각 룰은 `{ id, category, severity, signal-regex[], 한국어설명, 조합조건 }`로 구성한다. 핵심은 **단일 시그널의 심각도는 낮고, 시그널이 결합될 때 심각도가 급상승**한다는 것.

- `읽기 신호` = 비밀을 읽는 코드 (env, 키파일, 브라우저 스토리지, 클립보드)
- `전송 신호` = 외부로 데이터를 보내는 코드 (fetch/axios/requests/curl + 외부 도메인)
- `실행 신호` = 자동 실행 지점 (설치 훅, CI 워크플로, import 시 부수효과)

> **위험 공식의 직관:** `읽기 + 전송` = 유출 의심(critical). `다운로드 + 실행` = RCE(critical). `난독화 + 실행` = 은폐된 페이로드(high). 단독 신호는 대개 low.

심각도 enum: `low | medium | high | critical`.

---

## 2. secret-exfiltration (가장 중요)

비밀을 읽어 외부로 보내는 코드. 실제 스미싱 사고의 핵심 패턴.

**읽기 신호 정규식 (언어별):**
- JS/TS: `process\.env`, `process\.env\.[A-Z_]+`, `fs\.readFileSync\([^)]*(\.npmrc|\.env|id_rsa|\.aws|credentials)`, `localStorage`, `document\.cookie`
- Python: `os\.environ`, `os\.getenv`, `open\([^)]*(\.env|\.aws|id_rsa|\.netrc)`
- Shell: `\$HOME/\.(aws|ssh|npmrc|config)`, `cat\s+.*(\.env|id_rsa|credentials)`
- 일반: `AWS_SECRET`, `OPENAI_API_KEY`, `GITHUB_TOKEN`, `PRIVATE_KEY`, `MNEMONIC`, `SEED_PHRASE`

**전송 신호 정규식:**
- `fetch\(\s*['"\`]https?://`, `axios\.(post|get)\(\s*['"\`]https?://`
- Python: `requests\.(post|get)\(`, `urllib`, `socket\.connect`
- Shell: `curl\s+.*-d`, `wget\s+--post`, `nc\s`

**판정(맥락 기반 심각도 — 거짓양성 절대 금지):** 읽기 신호 + 전송 신호가 **같은 파일**에 함께 등장하는 것만으로는 **critical 금지**다. 정상 API 클라이언트가 흔히 이 형태이기 때문(예: `ELEVENLABS_API_KEY`를 `.env`/`os.environ`에서 읽어 `https://api.elevenlabs.io/...`로 인증 헤더와 함께 전송 = 그 키의 정당한 서비스 = 정상). `secret-exfiltration`을 **critical(danger/dangerLock)**로 올리는 건 **추가 의심 신호**가 있을 때만:

- **(A) 의심스러운 목적지** — 하드코딩 IP(`http(s)://1.2.3.4[:port]`), 메신저/웹훅(discord/telegram/slack), 단축URL·pastebin·익명업로드(`bit.ly`/`pastebin`/`webhook.site`/`transfer.sh`/`0x0.st`/`ngrok` 등), `nc`(netcat), 키의 서비스와 무관해 보이는/난독화된 목적지. **또는**
- **(B) 광범위 수집** — 환경변수 전체(`JSON.stringify(process.env)`/`...process.env`/`dict(os.environ)`/`os.environ.copy()` 등 통째·직렬화)나 **다수의 시크릿 파일**(`.aws/credentials`, `id_rsa`, `.npmrc`, `.ssh/`, `.netrc` 중 2개 이상)을 읽어 전송, 또는 전송 코드에 **난독화(긴 base64/hex + 디코드) 인접**.

위 신호가 **없고** 단일 명명 키(예: `*_API_KEY`/`*_TOKEN`)를 평범한 https API 호스트에 인증 헤더로 보내는 경우 = 정상 API 사용 → **critical 금지.** 단일 명명 키 + 평범한 https는 **미탐(노이즈 제거)** 권장, 모호한 경우만 **low(정보)**. dotenv 스타일 `.env` 로딩 자체는 정상 설정 로딩이다. (강등이 아니라 **심각도가 맥락에 따라 결정**: 의심목적지/광범위수집 → critical 유지, 아니면 low/미탐.)

한국어설명 예(critical): "이 파일은 당신의 환경변수/시크릿을 읽어 의심스러운 목적지로 외부 전송합니다. 정상적인 라이브러리에는 거의 없는 키 탈취 패턴입니다."

---

## 3. install-hook

패키지 설치만 해도 자동 실행되는 코드. 사용자가 코드를 들여다보기 전에 트리거된다.

- **npm:** `package.json`의 `scripts.preinstall`, `scripts.install`, `scripts.postinstall`. 값에 `node `, `curl`, `wget`, `.sh`, `python` 등 실행이 있으면 high. `curl|bash` 류가 있으면 critical(= remote-code-exec 결합).
- **Python:** `setup.py`에 `os.system`, `subprocess`, 커스텀 `cmdclass`/`install` 오버라이드 → high.
- **빌드/CI:** `.github/workflows/*.yml`의 `run:` 스텝에서 시크릿을 외부로 보내거나 외부 스크립트를 실행 → high.
한국어설명 예: "이 패키지는 설치하는 순간 자동으로 스크립트를 실행합니다. 그 스크립트가 외부에서 코드를 내려받아 실행합니다."

---

## 4. remote-code-exec

외부에서 받은 것을 실행.

- `curl\s+[^|]*\|\s*(sh|bash)`, `wget\s+[^|]*\|\s*(sh|bash)`
- JS: `eval\(`가 네트워크 응답/`atob`/`Buffer.from(...,'base64')` 결과를 받을 때, `new Function\(`, `child_process`로 다운로드 후 실행
- Python: `exec\(`/`eval\(`가 `requests.get(...).text`/`base64.b64decode` 결과를 받을 때, `subprocess` + 다운로드
**판정:** 다운로드 신호 + 실행 신호 결합 시 critical.

---

## 5. obfuscation

페이로드를 숨기는 기법. 숨긴다는 것 자체가 적신호.

- 긴 base64/hex 리터럴(예: `[A-Za-z0-9+/]{120,}={0,2}`) + `atob`/`b64decode`/`Buffer.from(...,'base64')` + 실행
- `String.fromCharCode` 대량 연쇄, `\\x` 헥스 이스케이프 떡칠, `eval(unescape(`
- 한 줄로 압축된 수천자 minified가 소스 저장소에 원본으로 커밋된 경우(빌드 산출물이 아닌데)
**판정:** 디코드 후 실행/네트워크로 이어지면 high~critical. 단순 base64 데이터(이미지 등)만이면 low/무시.

---

## 6. suspicious-network

유출 채널/하드코딩 목적지.

- 하드코딩 IPv4 `(\d{1,3}\.){3}\d{1,3}` (특히 사설 아님 + 포트 동반)
- `discord(app)?\.com/api/webhooks/`, `api\.telegram\.org/bot`, `hooks\.slack\.com` → 데이터 유출 채널로 악용 빈번
- 단축 URL(`bit\.ly`, `t\.co`)로 스크립트 다운로드
한국어설명 예: "이 코드는 디스코드/텔레그램 웹훅으로 데이터를 보냅니다 — 탈취한 정보를 빼돌리는 흔한 통로입니다."

---

## 7. crypto-miner

- `stratum+tcp://`, `xmrig`, `minerd`, `coinhive`, 알려진 마이닝 풀 도메인, `--donate-level`
**판정:** high. 설치 훅과 결합 시 critical.

---

## 8. dependency-risk

- `package.json`/`requirements.txt`의 의존성이 유명 패키지의 **타이포스쿼팅**(예: `reqeusts`, `loadsh`, `expresss`) 의심 → medium
- `git+http`/직접 tarball URL 의존성, 알 수 없는 레지스트리 → low~medium
- 핀 고정 안 된 `*`/`latest` 다수 → low(정보성)

---

## 9. 거짓양성 관리

- **테스트/예제 디렉토리 가중 완화:** `test/`, `__tests__/`, `examples/`, `docs/` 경로의 매치는 심각도 1단계 낮춘다(악성코드 데모/보안 교육 저장소 오인 방지). 단, secret-exfiltration은 완화 폭을 작게.
- **유명·고신뢰 저장소 보정:** 스타가 매우 높고 오래되고 활발한 저장소의 단일 약신호는 점수에 거의 반영하지 않는다(risk-scoring 참조). 단, critical finding은 신뢰 신호로 덮지 않는다 — 유명 저장소도 침해될 수 있다.
- **주석/문자열 구분 노력:** 가능하면 매치가 주석/문서 내인지 라인 컨텍스트로 가볍게 판별. 완벽한 파싱은 불필요하나, 명백한 마크다운 코드블록 설명은 낮춘다.
- **설명에 불확실성 표기:** 약한 단일 신호는 "의심"으로, 강한 조합은 "위험"으로 문구를 구분해 공포 조장을 피한다.
