import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { getBatchDetail, getBatches, getBatchTreeNodes, getGlobalTree, getGlobalTreeNodes, getMetrics, getRecords, login, proxyGet, putConfigYaml } from './api'

const fetchMock = vi.fn()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('admin API facade', () => {
  it('logs in with JSON body and credentials included', async () => {
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }))

    await login('root', 'secret')

    expect(fetchMock).toHaveBeenCalledWith('/admin/api/session', expect.objectContaining({
      method: 'POST',
      credentials: 'include',
      body: JSON.stringify({ username: 'root', password: 'secret' }),
    }))
  })

  it('raises server login errors', async () => {
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ ok: false, error: 'unauthorized' }), { status: 401 }))

    await expect(login('root', 'bad')).rejects.toThrow('unauthorized')
  })

  it('loads metrics from the protected JSON endpoint', async () => {
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({
      ok: true,
      metrics: [{ name: 'trustdb_batch_pending', value: 3 }],
    }), { status: 200 }))

    await expect(getMetrics()).resolves.toEqual([{ name: 'trustdb_batch_pending', value: 3 }])
  })

  it('writes YAML through PUT /config', async () => {
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ ok: true, backup: 'trustdb.yaml.bak' }), { status: 200 }))

    await expect(putConfigYaml('admin:\n  enabled: true\n')).resolves.toEqual({ backup: 'trustdb.yaml.bak' })
    expect(fetchMock).toHaveBeenCalledWith('/admin/api/config', expect.objectContaining({
      method: 'PUT',
      credentials: 'include',
      headers: { 'Content-Type': 'application/x-yaml' },
    }))
  })

  it('builds read-only proxy URLs under /admin/api/proxy', async () => {
    fetchMock.mockResolvedValueOnce(new Response('{}', { status: 200 }))

    await proxyGet('/v1/records?limit=5')

    expect(fetchMock).toHaveBeenCalledWith('/admin/api/proxy/v1/records?limit=5', { credentials: 'include' })
  })

  it('loads batch and tree endpoints through the proxy facade', async () => {
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({ roots: [{ batch_id: 'batch-a' }], next_cursor: 'c1' }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ root: { batch_id: 'batch-a' }, manifest: { batch_id: 'batch-a' }, record_count: 2 }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ nodes: [{ level: 0, start_index: 0, width: 1 }] }), { status: 200 }))

    await expect(getBatches({ limit: 10 })).resolves.toMatchObject({ next_cursor: 'c1' })
    await expect(getBatchDetail('batch-a')).resolves.toMatchObject({ record_count: 2 })
    await expect(getBatchTreeNodes('batch-a', { level: 0, start: 0 })).resolves.toMatchObject({ nodes: [{ level: 0 }] })

    expect(fetchMock).toHaveBeenNthCalledWith(1, '/admin/api/proxy/v1/batches?limit=10', { credentials: 'include' })
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/admin/api/proxy/v1/batches/batch-a', { credentials: 'include' })
    expect(fetchMock).toHaveBeenNthCalledWith(3, '/admin/api/proxy/v1/batches/batch-a/tree/nodes?level=0&start=0', { credentials: 'include' })
  })

  it('loads filtered records through the typed proxy facade', async () => {
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({
      records: [{ record_id: 'record-a', proof_level: 'L5' }],
      limit: 25,
      direction: 'desc',
    }), { status: 200 }))

    await expect(getRecords({ limit: 25, query: 'invoice', level: 'L5' })).resolves.toMatchObject({
      records: [{ record_id: 'record-a', proof_level: 'L5' }],
    })
    expect(fetchMock).toHaveBeenCalledWith('/admin/api/proxy/v1/records?limit=25&q=invoice&level=L5', { credentials: 'include' })
  })

  it('loads global tree through the proxy facade', async () => {
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({ ok: true, state: { tree_size: 2 } }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ nodes: [{ level: 0, start_index: 1 }] }), { status: 200 }))

    await expect(getGlobalTree()).resolves.toMatchObject({ ok: true, state: { tree_size: 2 } })
    await expect(getGlobalTreeNodes({ level: 0, start: 1, limit: 1 })).resolves.toMatchObject({ nodes: [{ start_index: 1 }] })
    expect(fetchMock).toHaveBeenNthCalledWith(1, '/admin/api/proxy/v1/global-log/tree', { credentials: 'include' })
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/admin/api/proxy/v1/global-log/tree/nodes?level=0&start=1&limit=1', { credentials: 'include' })
  })
})
