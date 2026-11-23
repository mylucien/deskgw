function csrf(): string {
  const m = document.cookie.match(/(?:^|;\s*)deskgw_csrf=([^;]*)/)
  return m ? decodeURIComponent(m[1]) : ''
}

export interface ApiError extends Error {
  code?: string
}

// 登录态在服务端滑动过期；任一接口返回 401 说明会话已失效，
// 直接回登录页，避免页面停留在"看似可用、点击全失败"的状态。
function redirectIfUnauthorized(status: number) {
  if (status !== 401) return
  if (location.pathname === '/login') return
  location.assign('/login')
}

export async function api<T = any>(path: string, options: RequestInit = {}): Promise<T> {
  const method = (options.method || 'GET').toUpperCase()
  const headers = new Headers(options.headers)
  if (!(options.body instanceof FormData)) headers.set('Content-Type', 'application/json')
  if (method !== 'GET' && method !== 'HEAD') headers.set('X-CSRF-Token', csrf())
  const res = await fetch('/api' + path, {
    ...options,
    method,
    headers,
    credentials: 'same-origin',
  })
  let payload: any
  try { payload = await res.json() } catch { payload = null }
  if (!res.ok || !payload?.ok) {
    redirectIfUnauthorized(res.status)
    const err: ApiError = new Error(payload?.error?.message || `请求失败 (${res.status})`)
    err.code = payload?.error?.code
    throw err
  }
  return payload.data as T
}

export const get = <T = any>(p: string, headers?: Record<string, string>) =>
  api<T>(p, headers ? { headers } : {})
export const post = <T = any>(p: string, body?: any, headers?: Record<string, string>) =>
  api<T>(p, { method: 'POST', headers, body: body === undefined ? undefined : JSON.stringify(body) })
export const put = <T = any>(p: string, body?: any) =>
  api<T>(p, { method: 'PUT', body: body === undefined ? undefined : JSON.stringify(body) })
export const del = <T = any>(p: string) => api<T>(p, { method: 'DELETE' })

// 上传二进制分片：保留 Content-Type 原始类型，附带文件令牌。
export async function uploadChunk<T = any>(p: string, chunk: Blob, headers: Record<string, string>): Promise<T> {
  const h = new Headers(headers)
  h.set('X-CSRF-Token', csrf())
  const res = await fetch('/api' + p, { method: 'POST', headers: h, body: chunk, credentials: 'same-origin' })
  let payload: any
  try { payload = await res.json() } catch { payload = null }
  if (!res.ok || !payload?.ok) {
    redirectIfUnauthorized(res.status)
    const err: ApiError = new Error(payload?.error?.message || `上传失败 (${res.status})`)
    err.code = payload?.error?.code
    throw err
  }
  return payload.data as T
}
