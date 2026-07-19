import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { getRecords } from '@/lib/api'
import Records from './Records.vue'

vi.mock('@/lib/api', () => ({
  getRecords: vi.fn(),
}))

const mockedGetRecords = vi.mocked(getRecords)

describe('Records page', () => {
  beforeEach(() => {
    mockedGetRecords.mockReset()
  })

  it('loads records and applies filters through the admin proxy', async () => {
    mockedGetRecords
      .mockResolvedValueOnce({
        records: [{
          record_id: 'record-abcdef123456',
          proof_level: 'L5',
          tenant_id: 'tenant-a',
          client_id: 'client-a',
          batch_id: 'batch-1',
          received_at_unix_n: 1_700_000_000_000_000_000,
        }],
        limit: 50,
        direction: 'desc',
      })
      .mockResolvedValueOnce({
        records: [],
        limit: 50,
        direction: 'desc',
      })

    const wrapper = mount(Records)
    await flushPromises()

    expect(wrapper.text()).toContain('tenant-a')
    expect(wrapper.text()).toContain('client-a')
    expect(wrapper.text()).toContain('batch-1')

    const inputs = wrapper.findAll('input')
    await inputs[0].setValue('invoice')
    await inputs[1].setValue('L5')
    const apply = wrapper.findAll('button').find((button) => button.text().includes('应用'))
    expect(apply).toBeTruthy()
    await apply!.trigger('click')
    await flushPromises()

    expect(mockedGetRecords).toHaveBeenLastCalledWith({ limit: 50, cursor: '', query: 'invoice', level: 'L5' })
    wrapper.unmount()
  })

  it('shows proxy errors without replacing existing data', async () => {
    mockedGetRecords.mockRejectedValueOnce(new Error('backend down'))

    const wrapper = mount(Records)
    await flushPromises()

    expect(wrapper.text()).toContain('backend down')
    expect(wrapper.text()).toContain('暂无记录')
    wrapper.unmount()
  })
})
