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
    const err: ApiError = new Error(payload?.error?.message || `上传失败 (${res.status})`)
    err.code = payload?.error?.code
    throw err
  }
  return payload.data as T
}

// 下载文件为 Blob，返回建议文件名（从 Content-Disposition 解析）。
export async function downloadBlob(p: string, headers: Record<string, string>): Promise<{ blob: Blob; name: string }> {
  const h = new Headers(headers)
  const res = await fetch('/api' + p, { headers: h, credentials: 'same-origin' })
  if (!res.ok) throw new Error(`下载失败 (${res.status})`)
  const blob = await res.blob()
  const cd = res.headers.get('Content-Disposition') || ''
  const m = cd.match(/filename\*=UTF-8''([^;]+)/i)
  let name = 'download'
  if (m) { try { name = decodeURIComponent(m[1]) } catch { name = m[1] } }
  return { blob, name: name.replace(/.*[\\/]/, '') }
}
