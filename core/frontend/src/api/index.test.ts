import { describe, it, expect, vi, beforeEach } from 'vitest'
import { AxiosError, CanceledError, type InternalAxiosRequestConfig } from 'axios'

// Mock all external dependencies before importing
vi.mock('@/router', () => ({
  default: { push: vi.fn() },
}))

vi.mock('@/store', () => ({
  useUserStore: vi.fn(() => ({
    login: { token: 'test-token' },
    resetLoginInfo: vi.fn(),
  })),
}))

vi.mock('@/utils', () => ({
  apiUrlPrefix: '/test-prefix',
  isObject: (val: unknown) => val !== null && typeof val === 'object' && !Array.isArray(val),
  Message: {
    error: vi.fn(),
    success: vi.fn(),
    loading: vi.fn(() => ({ close: vi.fn() })),
  },
}))

import { Message } from '@/utils'
import { instance, clearPendingRequests } from './index'

describe('API instance', () => {
  it('is an axios instance with expected defaults', () => {
    expect(instance.defaults.timeout).toBe(600000)
    expect(instance.defaults.headers['Content-Type']).toBe('application/json')
  })

  it('has request interceptors registered', () => {
    // Axios stores interceptors internally
    const reqInterceptors = (instance.interceptors.request as any).handlers
    expect(reqInterceptors.length).toBeGreaterThanOrEqual(3)
  })

  it('has response interceptors registered', () => {
    const resInterceptors = (instance.interceptors.response as any).handlers
    expect(resInterceptors.length).toBeGreaterThanOrEqual(1)
  })
})

describe('clearPendingRequests', () => {
  it('is a function', () => {
    expect(typeof clearPendingRequests).toBe('function')
  })

  it('does not throw when called with no pending requests', () => {
    expect(() => clearPendingRequests()).not.toThrow()
  })
})

// 请求在网络层失败时（core 重启、断网、超时）不会进入成功分支。
// 之前错误分支不关 loading，界面会一直卡在「请稍候」，这里锁住修复后的行为。
describe('response error handling', () => {
  const networkError = (config: InternalAxiosRequestConfig) =>
    Promise.reject(new AxiosError('Network Error', AxiosError.ERR_NETWORK, config))

  const mockLoading = () => {
    const close = vi.fn()
    vi.mocked(Message.loading).mockReturnValueOnce({ close } as any)
    return close
  }

  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('closes the loading and reports the failure when a request with loading fails', async () => {
    const close = mockLoading()

    await expect(
      instance.post('/network-error', {}, { fetchOptions: { loading: 'Saving...' }, adapter: networkError } as any),
    ).rejects.toThrow('Network Error')

    expect(close).toHaveBeenCalledTimes(1)
    expect(Message.error).toHaveBeenCalledWith('Network error, please try again later', { close: true })
  })

  it('prefers the message returned by the server', async () => {
    const close = mockLoading()
    const serverError = (config: InternalAxiosRequestConfig) =>
      Promise.reject(
        new AxiosError('Request failed with status code 500', AxiosError.ERR_BAD_RESPONSE, config, null, {
          data: { msg: 'fail to set ssl' },
          status: 500,
          statusText: 'Internal Server Error',
          headers: {},
          config,
        }),
      )

    await expect(
      instance.post('/server-error', {}, { fetchOptions: { loading: 'Saving...' }, adapter: serverError } as any),
    ).rejects.toThrow()

    expect(close).toHaveBeenCalledTimes(1)
    expect(Message.error).toHaveBeenCalledWith('fail to set ssl', { close: true })
  })

  it('stays silent for requests without loading (polling, silent retries)', async () => {
    await expect(instance.get('/polling', { adapter: networkError } as any)).rejects.toThrow('Network Error')

    expect(Message.error).not.toHaveBeenCalled()
  })

  // 连点两次同一个按钮时，前一个请求会被后一个顶掉（见 addController）。
  // 被顶掉的请求走的也是错误分支，它的 loading 同样要关，而且不该报错。
  it('closes the loading of a request superseded by an identical one', async () => {
    const closeFirst = mockLoading()
    const closeSecond = mockLoading()

    // 一直不返回，直到被中止
    const pending = (config: InternalAxiosRequestConfig) =>
      new Promise<never>((_, reject) => {
        config.signal?.addEventListener?.('abort', () =>
          reject(new AxiosError('aborted', AxiosError.ERR_CANCELED, config)),
        )
      })
    const ok = (config: InternalAxiosRequestConfig) =>
      Promise.resolve({ data: { code: 0, success: true, data: null }, status: 200, statusText: 'OK', headers: {}, config })

    const first = instance.post('/save', { id: 1 }, { fetchOptions: { loading: 'Saving...' }, adapter: pending } as any)
    const second = instance.post('/save', { id: 1 }, { fetchOptions: { loading: 'Saving...' }, adapter: ok } as any)

    await expect(first).rejects.toBeInstanceOf(CanceledError)
    await second

    expect(closeFirst).toHaveBeenCalledTimes(1)
    expect(closeSecond).toHaveBeenCalledTimes(1)
    expect(Message.error).not.toHaveBeenCalled()
  })
})
