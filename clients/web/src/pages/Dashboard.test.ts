import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { getBatches, getMetrics, getRecords } from '@/lib/api'
import Dashboard from './Dashboard.vue'

const gsapMock = vi.hoisted(() => {
  const timeline = { from: vi.fn() } as { from: ReturnType<typeof vi.fn> }
  timeline.from.mockReturnValue(timeline)
  return {
    context: vi.fn((callback: () => void) => {
      callback()
      return { revert: vi.fn() }
    }),
    timeline: vi.fn(() => timeline),
    to: vi.fn(),
  }
})

vi.mock('gsap', () => ({ default: gsapMock }))
vi.mock('vue-router', () => ({
  RouterLink: { props: ['to'], template: '<a :href="to"><slot /></a>' },
}))
vi.mock('@/lib/api', () => ({
  getBatches: vi.fn(),
  getMetrics: vi.fn(),
  getRecords: vi.fn(),
}))

const mockedGetMetrics = vi.mocked(getMetrics)
const mockedGetBatches = vi.mocked(getBatches)
const mockedGetRecords = vi.mocked(getRecords)

describe('Dashboard page', () => {
  beforeEach(() => {
    mockedGetMetrics.mockReset()
    mockedGetBatches.mockReset()
    mockedGetRecords.mockReset()
  })

  it('renders live metrics, batches, records, and real queue attention', async () => {
    mockedGetMetrics.mockResolvedValueOnce([
      { name: 'trustdb_ingest_requests_total', labels: { result: 'accepted' }, value: 42 },
      { name: 'trustdb_anchor_pending_total', value: 2 },
      { name: 'trustdb_anchor_published_total', value: 7 },
    ])
    mockedGetBatches.mockResolvedValueOnce({
      roots: [{ schema_version: '1', batch_id: 'batch-real', batch_root: [1, 2], tree_size: 3, closed_at_unix_nano: 1_700_000_000_000_000_000 }],
    })
    mockedGetRecords.mockResolvedValueOnce({
      records: [{ record_id: 'record-1', proof_level: 'L5' }, { record_id: 'record-2', proof_level: 'L4' }],
      limit: 100,
      direction: 'desc',
    })

    const wrapper = mount(Dashboard)
    await flushPromises()

    expect(wrapper.text()).toContain('42')
    expect(wrapper.text()).toContain('batch-real')
    expect(wrapper.text()).toContain('待锚定队列')
    expect(wrapper.text()).toContain('最近 2 条')
    wrapper.unmount()
  })

  it('shows an honest partial-data state when dashboard APIs fail', async () => {
    mockedGetMetrics.mockRejectedValueOnce(new Error('metrics unavailable'))
    mockedGetBatches.mockResolvedValueOnce({ roots: [] })
    mockedGetRecords.mockResolvedValueOnce({ records: [], limit: 100, direction: 'desc' })

    const wrapper = mount(Dashboard)
    await flushPromises()

    expect(wrapper.text()).toContain('部分数据不可用')
    expect(wrapper.text()).toContain('数据源不可用')
    expect(wrapper.text()).toContain('metrics unavailable')
    wrapper.unmount()
  })
})
