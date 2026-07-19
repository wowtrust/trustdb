import { expect, test, type Page } from '@playwright/test'

async function mockAdminAPI(page: Page) {
  let loggedIn = false

  await page.route('**/admin/api/session', async (route) => {
    const method = route.request().method()
    if (method === 'GET') {
      await route.fulfill({ json: { ok: loggedIn, username: loggedIn ? 'ops' : undefined } })
      return
    }
    if (method === 'POST') {
      const body = route.request().postDataJSON() as { username?: string; password?: string }
      loggedIn = body.username === 'ops' && body.password === 'secret'
      await route.fulfill({ status: loggedIn ? 200 : 401, json: loggedIn ? { ok: true } : { ok: false, error: 'unauthorized' } })
      return
    }
    if (method === 'DELETE') {
      loggedIn = false
      await route.fulfill({ json: { ok: true } })
      return
    }
    await route.fulfill({ status: 405, body: 'method not allowed' })
  })

  await page.route('**/admin/api/overlays', async (route) => {
    await route.fulfill({
      json: {
        ok: true,
        overlays: {
          server: { grpc_listen: '127.0.0.1:9090' },
          metastore: 'pebble',
          anchor: { sink: 'ots' },
        },
      },
    })
  })

  await page.route('**/admin/api/metrics', async (route) => {
    await route.fulfill({
      json: {
        ok: true,
        metrics: [
          { name: 'trustdb_ingest_accepted_total', type: 'counter', value: 12 },
          { name: 'trustdb_batch_pending', type: 'gauge', value: 3 },
          { name: 'trustdb_anchor_pending', type: 'gauge', value: 1 },
          { name: 'trustdb_custom_latency_seconds', type: 'gauge', labels: { quantile: '0.95' }, value: 0.42 },
        ],
      },
    })
  })

  await page.route('**/admin/api/config', async (route) => {
    if (route.request().method() === 'GET') {
      await route.fulfill({
        json: {
          ok: true,
          config_path: 'C:/trustdb/trustdb.yaml',
          config: {
            admin: { enabled: true, username: 'ops', password_hash: '<redacted>', session_secret: '<redacted>' },
            server: { listen: '127.0.0.1:8080' },
          },
        },
      })
      return
    }
    if (route.request().method() === 'PUT') {
      await route.fulfill({ json: { ok: true, backup: 'C:/trustdb/trustdb.yaml.bak.1' } })
      return
    }
    await route.fulfill({ status: 405, body: 'method not allowed' })
  })

  await page.route('**/admin/api/config/raw', async (route) => {
    await route.fulfill({
      contentType: 'application/x-yaml',
      body: 'admin:\n  enabled: true\nserver:\n  listen: "127.0.0.1:8080"\n',
    })
  })

  await page.route('**/admin/api/proxy/healthz', async (route) => {
    await route.fulfill({ json: { ok: true } })
  })

  await page.route('**/admin/api/proxy/v1/roots/latest', async (route) => {
    await route.fulfill({ json: { batch_id: 'batch-1', tree_size: 2 } })
  })

  await page.route('**/admin/api/proxy/v1/batches?*', async (route) => {
    await route.fulfill({ json: { roots: [{ batch_id: 'batch-1', tree_size: 2, closed_at_unix_nano: 1_700_000_000_000_000_000, batch_root: [9] }] } })
  })

  await page.route('**/admin/api/proxy/v1/batches/batch-1', async (route) => {
    await route.fulfill({
      json: {
        root: { batch_id: 'batch-1', tree_size: 2, closed_at_unix_nano: 1_700_000_000_000_000_000, batch_root: [9] },
        manifest: { batch_id: 'batch-1', state: 'committed', tree_size: 2, batch_root: [9], record_ids: ['record-abcdef123456'] },
        record_count: 1,
      },
    })
  })

  await page.route('**/admin/api/proxy/v1/batches/batch-1/tree/leaves?*', async (route) => {
    await route.fulfill({ json: { leaves: [{ batch_id: 'batch-1', record_id: 'record-abcdef123456', leaf_index: 0, leaf_hash: [1] }] } })
  })

  await page.route('**/admin/api/proxy/v1/batches/batch-1/tree/nodes?*', async (route) => {
    await route.fulfill({ json: { nodes: [{ batch_id: 'batch-1', level: 0, start_index: 0, width: 1, hash: [1] }, { batch_id: 'batch-1', level: 1, start_index: 0, width: 2, hash: [9] }] } })
  })

  await page.route('**/admin/api/proxy/v1/proofs/record-abcdef123456', async (route) => {
    await route.fulfill({
      json: {
        record_id: 'record-abcdef123456',
        proof_level: 'L5',
        proof_bundle: {
          record_id: 'record-abcdef123456',
          committed_receipt: { batch_id: 'batch-1', leaf_index: 0, leaf_hash: [1], batch_root: [9], batch_closed_at_unix_nano: 1_700_000_000_000_000_000 },
          batch_proof: { tree_alg: 'rfc6962-sha256', leaf_index: 0, tree_size: 2, audit_path: [[2]] },
        },
      },
    })
  })

  await page.route('**/admin/api/proxy/v1/global-log/tree', async (route) => {
    await route.fulfill({ json: { ok: true, state: { tree_size: 1, root_hash: [9] }, sth: { tree_size: 1, root_hash: [9], timestamp_unix_nano: 1_700_000_000_000_000_000 } } })
  })

  await page.route('**/admin/api/proxy/v1/global-log/tree/nodes?*', async (route) => {
    await route.fulfill({ json: { nodes: [{ level: 0, start_index: 0, width: 1, hash: [9] }] } })
  })

  await page.route('**/admin/api/proxy/v1/global-log/tree/leaves?*', async (route) => {
    await route.fulfill({ json: { leaves: [{ batch_id: 'batch-1', leaf_index: 0, batch_tree_size: 2, leaf_hash: [9] }] } })
  })

  await page.route('**/admin/api/proxy/v1/records?*', async (route) => {
    await route.fulfill({
      json: {
        records: [
          {
            record_id: 'record-abcdef123456',
            proof_level: 'L5',
            tenant_id: 'tenant-a',
            client_id: 'client-a',
            batch_id: 'batch-1',
            received_at_unix_n: 1_700_000_000_000_000_000,
          },
        ],
        limit: 50,
        direction: 'desc',
      },
    })
  })
}

test.beforeEach(async ({ page }) => {
  await mockAdminAPI(page)
})

test('requires login and opens the admin dashboard', async ({ page }) => {
  await page.goto('/admin/dashboard')

  await expect(page).toHaveURL(/\/admin\/login/)
  await page.locator('input').nth(0).fill('ops')
  await page.locator('input').nth(1).fill('secret')
  await page.getByRole('button', { name: '登录' }).click()

  await expect(page).toHaveURL(/\/admin\/dashboard/)
  await expect(page.getByRole('heading', { name: 'ALL SYSTEMS PROVABLE' })).toBeVisible()
  await expect(page.getByRole('heading', { name: '实时证明流水线' })).toBeVisible()
  await expect(page.getByRole('button', { name: '刷新数据' })).toBeVisible()
  await expect(page.locator('.wa-latest').getByText('batch-1', { exact: true })).toBeVisible()
})

test('shows metrics and records through authenticated admin APIs', async ({ page }) => {
  await page.goto('/admin/login')
  await page.locator('input').nth(0).fill('ops')
  await page.locator('input').nth(1).fill('secret')
  await page.getByRole('button', { name: '登录' }).click()

  await page.getByRole('link', { name: /指标/ }).click()
  await expect(page.getByText('claims accepted')).toBeVisible()
  await expect(page.getByText('12', { exact: true })).toBeVisible()
  await expect(page.getByText('trustdb_custom_latency_seconds')).toBeVisible()

  await page.getByRole('link', { name: /记录/ }).click()
  await expect(page.getByText('tenant-a')).toBeVisible()
  await expect(page.getByText('client-a')).toBeVisible()
  await expect(page.getByText('batch-1')).toBeVisible()
})

test('loads settings and saves YAML through the config endpoint', async ({ page }) => {
  await page.goto('/admin/login')
  await page.locator('input').nth(0).fill('ops')
  await page.locator('input').nth(1).fill('secret')
  await page.getByRole('button', { name: '登录' }).click()

  await page.getByRole('link', { name: /系统设置/ }).click()
  await expect(page.getByText('C:/trustdb/trustdb.yaml')).toBeVisible()
  await expect(page.locator('textarea')).toHaveValue(/admin:/)
  await page.getByRole('button', { name: '保存 YAML' }).click()
  await expect(page.getByText(/已保存/)).toBeVisible()
})

test('shows batch and global merkle visualizations', async ({ page }) => {
  await page.goto('/admin/login')
  await page.locator('input').nth(0).fill('ops')
  await page.locator('input').nth(1).fill('secret')
  await page.getByRole('button', { name: '登录' }).click()

  await page.getByRole('link', { name: /批次/ }).click()
  await expect(page.getByRole('heading', { name: '历史批次' })).toBeVisible()
  await expect(page.getByText('batch-1')).toBeVisible()
  await page.getByRole('link', { name: '查看树' }).click()
  await expect(page.getByRole('heading', { name: '批次详情' })).toBeVisible()
  await expect(page.getByText('Tree Explorer')).toBeVisible()
  await page.getByText('record-abcdef123456').click()
  await page.getByRole('button', { name: '查看 proof path' }).click()
  await expect(page.getByText('Sibling 1')).toBeVisible()

  await page.getByRole('link', { name: /全局树/ }).click()
  await expect(page.getByRole('heading', { name: '全局 Merkle Tree' })).toBeVisible()
  await expect(page.getByText('全局节点')).toBeVisible()
  await expect(page.getByText('batch-1')).toBeVisible()
})
