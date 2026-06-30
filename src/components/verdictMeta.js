// VerdictReport 소비 시 표현 정합성을 위한 헬퍼.
// 규칙: 색/아이콘/문구는 반드시 report.verdict에서 파생. enum 외 값은 가장 보수적(위험)으로 폴백.

const VERDICT_MAP = {
  safe: {
    key: 'safe',
    color: 'var(--safe)',
    soft: 'rgba(46,204,113,.14)',
    border: 'rgba(46,204,113,.35)',
    glow: 'rgba(46,204,113,.08)',
    icon: '✓',
    label: '안전',
    line: '검사 범위 내 위협 미발견',
  },
  caution: {
    key: 'caution',
    color: 'var(--caution)',
    soft: 'rgba(241,196,15,.14)',
    border: 'rgba(241,196,15,.35)',
    glow: 'rgba(241,196,15,.08)',
    icon: '⚠',
    label: '주의',
    line: '직접 확인 후 결정 권장',
  },
  danger: {
    key: 'danger',
    color: 'var(--danger)',
    soft: 'rgba(255,71,87,.14)',
    border: 'rgba(255,71,87,.4)',
    glow: 'rgba(255,71,87,.1)',
    icon: '⛔',
    label: '위험',
    line: 'clone 권장하지 않음',
  },
}

// 알 수 없는 verdict는 위험으로 폴백(거짓 안심 방지).
export function verdictMeta(verdict) {
  return VERDICT_MAP[verdict] || { ...VERDICT_MAP.danger, label: '판정 불명', line: '알 수 없는 판정 — 보수적으로 위험 표시' }
}

export function verdictStyleVars(verdict) {
  const m = verdictMeta(verdict)
  return {
    '--vc': m.color,
    '--vc-soft': m.soft,
    '--vc-border': m.border,
    '--vc-glow': m.glow,
  }
}

// riskScore 라벨 구간.
export function riskBand(score) {
  if (score >= 70) return '위험'
  if (score >= 40) return '주의'
  return '낮음'
}

// 천단위 축약 (46602 -> "46.6k").
export function abbrev(n) {
  if (n == null || Number.isNaN(n)) return '—'
  if (n < 1000) return String(n)
  if (n < 1_000_000) return (n / 1000).toFixed(n % 1000 === 0 ? 0 : 1).replace(/\.0$/, '') + 'k'
  return (n / 1_000_000).toFixed(1).replace(/\.0$/, '') + 'M'
}

export function withCommas(n) {
  if (n == null || Number.isNaN(n)) return '—'
  return n.toLocaleString('en-US')
}

// ISO 날짜 -> "YYYY-MM-DD" + 상대표현.
export function formatDateRel(iso) {
  if (!iso) return { date: '—', rel: '' }
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return { date: String(iso), rel: '' }
  const date = d.toISOString().slice(0, 10)
  const diffMs = Date.now() - d.getTime()
  const days = Math.floor(diffMs / 86_400_000)
  let rel
  if (days < 0) rel = '미래'
  else if (days < 1) rel = '오늘'
  else if (days < 30) rel = `${days}일 전`
  else if (days < 365) rel = `${Math.floor(days / 30)}개월 전`
  else rel = `${(days / 365).toFixed(1)}년 전`
  return { date, rel }
}

// TrustSignal.weight 문자열에서 칩 색 클래스 결정.
export function chipClass(weight = '') {
  const w = String(weight)
  if (w.includes('위험') || w.includes('-')) return 'chip--bad'
  if (w.includes('신뢰') || w.includes('+') || w.includes('양호') || w.includes('활발')) return 'chip--good'
  return 'chip--neutral'
}

export const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 }
