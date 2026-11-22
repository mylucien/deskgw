function csrf(): string {
  const m = document.cookie.match(/(?:^|;\s*)deskgw_csrf=([^;]*)/)
  return m ? decodeURIComponent(m[1]) : ''
}

export interface ApiError extends Error {
  code?: string
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
    const err: ApiError = new Error(payload?.error?.message || `请求失败 (${res.status})`)
    err.code = payload?.error?.code
    throw err
  }
  return payload.data as T
}

export const get = <T = any>(p: string) => api<T>(p)
export const post = <T = any>(p: string, body?: any) =>
  api<T>(p, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) })
export const put = <T = any>(p: string, body?: any) =>
  api<T>(p, { method: 'PUT', body: body === undefined ? undefined : JSON.stringify(body) })
export const del = <T = any>(p: string) => api<T>(p, { method: 'DELETE' })
