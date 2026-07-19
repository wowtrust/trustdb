export const adminApiPrefix = '/admin/api'

export type Metric = {
  name: string
  type?: string
  help?: string
  labels?: Record<string, string>
  value: number
}

export type BatchRoot = {
  schema_version: string
  batch_id: string
  node_id?: string
  log_id?: string
  batch_root: string | number[]
  tree_size: number
  closed_at_unix_nano: number
}

export type BatchManifest = {
  schema_version: string
  batch_id: string
  node_id?: string
  log_id?: string
  state: string
  tree_alg: string
  tree_size: number
  batch_root: string | number[]
  record_ids: string[]
  closed_at_unix_nano: number
  prepared_at_unix_nano?: number
  committed_at_unix_nano?: number
  wal_range?: unknown
}

export type BatchTreeLeaf = {
  schema_version: string
  batch_id: string
  record_id: string
  leaf_index: number
  leaf_hash: string | number[]
  created_at_unix_nano?: number
}

export type BatchTreeNode = {
  schema_version: string
  batch_id: string
  level: number
  start_index: number
  width: number
  hash: string | number[]
  created_at_unix_nano?: number
}

export type SignedTreeHead = {
  schema_version: string
  tree_alg: string
  tree_size: number
  root_hash: string | number[]
  timestamp_unix_nano: number
  node_id?: string
  log_id?: string
}

export type GlobalLogState = {
  schema_version: string
  tree_size: number
  root_hash?: string | number[]
  frontier: Array<string | number[]>
  updated_at_unix_nano: number
}

export type GlobalLogLeaf = {
  schema_version: string
  batch_id: string
  batch_root: string | number[]
  batch_tree_size: number
  batch_closed_at_unix_nano: number
  leaf_index: number
  leaf_hash: string | number[]
  appended_at_unix_nano: number
}

export type GlobalLogNode = {
  schema_version: string
  level: number
  start_index: number
  width: number
  hash: string | number[]
  created_at_unix_nano: number
}

export type ProofResponse = {
  record_id: string
  proof_level: string
  proof_bundle: {
    record_id: string
    committed_receipt: {
      batch_id: string
      leaf_index: number
      leaf_hash: string | number[]
      batch_root: string | number[]
      batch_closed_at_unix_nano: number
    }
    batch_proof: {
      tree_alg: string
      leaf_index: number
      tree_size: number
      audit_path: Array<string | number[]>
    }
  }
}

export type RecordIndex = {
  record_id: string
  proof_level?: string
  tenant_id?: string
  client_id?: string
  batch_id?: string
  received_at_unix_n?: number
  content_hash?: string
  storage_uri?: string
}

export type RecordsResponse = {
  records: RecordIndex[]
  limit: number
  direction: string
  next_cursor?: string
}

async function parseJSON<T>(res: Response): Promise<T> {
  const text = await res.text()
  try {
    return JSON.parse(text) as T
  } catch {
    throw new Error(text || res.statusText)
  }
}

export async function adminFetch(path: string, init?: RequestInit): Promise<Response> {
  const headers: Record<string, string> = {
    ...(init?.headers as Record<string, string> | undefined),
  }
  if (init?.body && typeof init.body === 'string' && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json'
  }
  return fetch(adminApiPrefix + path, {
    credentials: 'include',
    ...init,
    headers,
  })
}

export async function getSession(): Promise<{ ok: boolean; username?: string }> {
  const res = await adminFetch('/session', { method: 'GET' })
  return parseJSON(res)
}

export async function login(username: string, password: string): Promise<void> {
  const res = await adminFetch('/session', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  })
  const j = await parseJSON<{ ok?: boolean; error?: string }>(res)
  if (!res.ok || !j.ok) throw new Error(j.error || '登录失败')
}

export async function logout(): Promise<void> {
  await adminFetch('/session', { method: 'DELETE' })
}

export async function getMetrics(): Promise<Metric[]> {
  const res = await adminFetch('/metrics', { method: 'GET' })
  const j = await parseJSON<{ ok: boolean; metrics?: Metric[]; error?: string }>(res)
  if (!res.ok || !j.ok) throw new Error(j.error || '无法读取指标')
  return j.metrics ?? []
}

export async function getConfig(): Promise<{ config: unknown; config_path: string; notes?: string[] }> {
  const res = await adminFetch('/config', { method: 'GET' })
  const j = await parseJSON<{ ok: boolean; config?: unknown; config_path?: string; notes?: string[]; error?: string }>(res)
  if (!res.ok || !j.ok) throw new Error(j.error || '无法读取配置')
  return { config: j.config, config_path: j.config_path ?? '', notes: j.notes }
}

export async function getOverlays(): Promise<Record<string, unknown>> {
  const res = await adminFetch('/overlays', { method: 'GET' })
  const j = await parseJSON<{ ok: boolean; overlays?: Record<string, unknown>; error?: string }>(res)
  if (!res.ok || !j.ok) throw new Error(j.error || '无法读取扩展字段')
  return j.overlays ?? {}
}

export async function getConfigRaw(): Promise<string> {
  const res = await adminFetch('/config/raw', { method: 'GET' })
  if (!res.ok) {
    const t = await res.text()
    throw new Error(t || '无法读取原始配置')
  }
  return res.text()
}

export async function putConfigYaml(yaml: string): Promise<{ backup?: string }> {
  const res = await fetch(adminApiPrefix + '/config', {
    method: 'PUT',
    credentials: 'include',
    headers: { 'Content-Type': 'application/x-yaml' },
    body: yaml,
  })
  const j = await parseJSON<{ ok: boolean; backup?: string; error?: string }>(res)
  if (!res.ok || !j.ok) throw new Error(j.error || '保存失败')
  return { backup: j.backup }
}

/** GET public API through authenticated admin proxy (read-only). */
export async function proxyGet(path: string): Promise<Response> {
  const p = path.startsWith('/') ? path : `/${path}`
  return fetch(adminApiPrefix + '/proxy' + p, { credentials: 'include' })
}

async function proxyJSON<T>(path: string): Promise<T> {
  const res = await proxyGet(path)
  const j = await parseJSON<T & { code?: string; message?: string }>(res)
  if (!res.ok) throw new Error(j.message || res.statusText)
  return j
}

function withParams(path: string, params: Record<string, string | number | undefined>): string {
  const qs = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== '') qs.set(key, String(value))
  }
  const query = qs.toString()
  return query ? `${path}?${query}` : path
}

export async function getBatches(opts: { limit?: number; cursor?: string } = {}): Promise<{ roots: BatchRoot[]; next_cursor?: string }> {
  return proxyJSON(withParams('/v1/batches', { limit: opts.limit, cursor: opts.cursor }))
}

export async function getRecords(opts: { limit?: number; cursor?: string; query?: string; level?: string } = {}): Promise<RecordsResponse> {
  return proxyJSON(withParams('/v1/records', {
    limit: opts.limit,
    cursor: opts.cursor,
    q: opts.query,
    level: opts.level,
  }))
}

export async function getBatchDetail(batchID: string): Promise<{ root: BatchRoot; manifest: BatchManifest; record_count: number }> {
  return proxyJSON(`/v1/batches/${encodeURIComponent(batchID)}`)
}

export async function getBatchLeaves(batchID: string, opts: { limit?: number; cursor?: string } = {}): Promise<{ leaves: BatchTreeLeaf[]; next_cursor?: string }> {
  return proxyJSON(withParams(`/v1/batches/${encodeURIComponent(batchID)}/tree/leaves`, { limit: opts.limit, cursor: opts.cursor }))
}

export async function getBatchTreeNodes(batchID: string, opts: { level?: number; start?: number; limit?: number; cursor?: string } = {}): Promise<{ nodes: BatchTreeNode[]; next_cursor?: string }> {
  return proxyJSON(withParams(`/v1/batches/${encodeURIComponent(batchID)}/tree/nodes`, { level: opts.level, start: opts.start, limit: opts.limit, cursor: opts.cursor }))
}

export async function getProofPath(recordID: string): Promise<ProofResponse> {
  return proxyJSON(`/v1/proofs/${encodeURIComponent(recordID)}`)
}

export async function getGlobalTree(): Promise<{ ok: boolean; state?: GlobalLogState; sth?: SignedTreeHead }> {
  return proxyJSON('/v1/global-log/tree')
}

export async function getGlobalTreeNodes(opts: { level?: number; start?: number; limit?: number; cursor?: string } = {}): Promise<{ nodes: GlobalLogNode[]; next_cursor?: string }> {
  return proxyJSON(withParams('/v1/global-log/tree/nodes', { level: opts.level, start: opts.start, limit: opts.limit, cursor: opts.cursor }))
}

export async function getGlobalLeaves(opts: { limit?: number; cursor?: string } = {}): Promise<{ leaves: GlobalLogLeaf[]; next_cursor?: string }> {
  return proxyJSON(withParams('/v1/global-log/tree/leaves', { limit: opts.limit, cursor: opts.cursor }))
}
