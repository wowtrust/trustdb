import { afterEach, vi } from 'vitest'

// Product tests assert the existing Simplified Chinese copy. Locale-specific
// behavior is covered separately; pinning the test shell keeps snapshots and
// text assertions independent from the host machine's browser language.
localStorage.setItem('trustdb.locale', 'zh-CN')

const canvasContext = {
  setTransform: vi.fn(),
  clearRect: vi.fn(),
  createLinearGradient: vi.fn(() => ({ addColorStop: vi.fn() })),
  fillRect: vi.fn(),
  beginPath: vi.fn(),
  moveTo: vi.fn(),
  lineTo: vi.fn(),
  stroke: vi.fn(),
  bezierCurveTo: vi.fn(),
  arc: vi.fn(),
  fill: vi.fn(),
  closePath: vi.fn(),
  arcTo: vi.fn(),
  fillText: vi.fn(),
}

Object.defineProperty(HTMLCanvasElement.prototype, 'getContext', {
  value: vi.fn(() => canvasContext),
  configurable: true,
})

afterEach(() => {
  vi.clearAllMocks()
})
