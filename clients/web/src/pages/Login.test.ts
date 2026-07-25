import { mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import Login from './Login.vue'

const replace = vi.fn()
const login = vi.fn()

vi.mock('vue-router', () => ({
  useRoute: () => ({ query: { redirect: '/metrics' } }),
  useRouter: () => ({ replace }),
}))

vi.mock('@/stores/auth', () => ({
  useAuth: () => ({ login }),
}))

describe('Login page', () => {
  beforeEach(() => {
    replace.mockReset()
    login.mockReset()
  })

  it('submits trimmed username and redirects after successful login', async () => {
    login.mockResolvedValueOnce(undefined)
    const wrapper = mount(Login)

    const inputs = wrapper.findAll('input')
    await inputs[0].setValue('  ops  ')
    await inputs[1].setValue('secret')
    await wrapper.find('form').trigger('submit.prevent')

		expect(login).toHaveBeenCalledWith('ops', 'secret', '', '')
    expect(replace).toHaveBeenCalledWith('/metrics')
  })

  it('shows login failures without redirecting', async () => {
    login.mockRejectedValueOnce(new Error('unauthorized'))
    const wrapper = mount(Login)

    const inputs = wrapper.findAll('input')
    await inputs[0].setValue('ops')
    await inputs[1].setValue('bad')
    await wrapper.find('form').trigger('submit.prevent')

    expect(wrapper.text()).toContain('unauthorized')
    expect(replace).not.toHaveBeenCalled()
  })
})
