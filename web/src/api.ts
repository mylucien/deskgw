function csrf(): string {
  const m = document.cookie.match(/(?:^|;\s*)deskgw_csrf=([^;]*)/)
  return m ? decodeURIComponent(m[1]) : ''
}

export interface ApiError extends Error {
  code?: string
  status?: number
  /** 服务端附带的错误详情（例如分片上传期望的 offset）。 */
  data?: any
}

// 只有「登录态失效」才回登录页。
//
// 原实现把任何 401 都当成登录过期：文件接口用 401 表示令牌过期或关联会话
// 已结束，上传中关掉文件面板就触发整页跳转，所有标签的远程会话一起断开。
// 现在文件接口改用 403/410，这里也只认 code=unauthorized。
function redirectIfUnauthorized(status: number, code?: string) {
  if (status !== 401 || code !== 'unauthorized') return
  if (location.pathname === '/login') return
  location.assign('/login')
}

function toError(res: Response, payload: any, fallback: string): ApiError {
  const code = payload?.error?.code
  redirectIfUnauthorized(res.status, code)
  const err: ApiError = new Error(payload?.error?.message || `${fallback} (${res.status})`)
  err.code = code
  err.status = res.status
  err.data = payload?.error
  return err
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
  if (!res.ok || !payload?.ok) throw toError(res, payload, '请求失败')
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
  if (!res.ok || !payload?.ok) throw toError(res, payload, '上传失败')
  return payload.data as T
}
