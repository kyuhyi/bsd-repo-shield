// src/config/advisories.js — 보안 권고 조회(키 불필요). GitHub repository security advisories.
//
// 키 없이 동작하므로 기본 노출. CORS/한도/없음은 graceful 폴백(빈 배열 + error 표기),
// 절대 "조회 못 함"을 "안전"으로 위장하지 않는다(호출부에서 정직히 표시).

const GH = 'https://api.github.com'

/**
 * GitHub 저장소의 공개 보안 권고 조회.
 * @returns {Promise<{ advisories: Array, error: string|null }>}
 *   advisories[i]: { ghsaId, severity, summary, htmlUrl }
 */
export async function fetchGithubAdvisories(owner, name, { token } = {}) {
  if (!owner || !name) return { advisories: [], error: null }
  const headers = { Accept: 'application/vnd.github+json' }
  if (token) headers.Authorization = `Bearer ${token}`

  let res
  try {
    res = await fetch(`${GH}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}/security-advisories?per_page=20`, { headers })
  } catch {
    return { advisories: [], error: 'GitHub 권고 조회 실패(네트워크)' }
  }

  if (res.status === 404) {
    // 권고 기능 미사용/없음 — 위협 아님. 빈 목록.
    return { advisories: [], error: null }
  }
  if (res.status === 403 || res.status === 429) {
    return { advisories: [], error: 'GitHub 권고 조회 실패(API 한도)' }
  }
  if (!res.ok) {
    return { advisories: [], error: `GitHub 권고 조회 실패(${res.status})` }
  }

  let data
  try {
    data = await res.json()
  } catch {
    return { advisories: [], error: 'GitHub 권고 응답 파싱 실패' }
  }
  if (!Array.isArray(data)) return { advisories: [], error: null }

  const advisories = data.map((a) => ({
    ghsaId: a?.ghsa_id || a?.cve_id || '권고',
    severity: (a?.severity || 'unknown').toLowerCase(),
    summary: a?.summary || a?.description || '상세 미상',
    htmlUrl: a?.html_url || null,
  }))
  return { advisories, error: null }
}
