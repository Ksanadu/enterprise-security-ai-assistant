import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
  ApiError,
  apiRequest,
  clearAccessToken,
  getAccessToken,
  setAccessToken,
} from './client'

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  })
}

const fetchMock = vi.fn<typeof fetch>()

beforeEach(() => {
  fetchMock.mockReset()
  globalThis.fetch = fetchMock as unknown as typeof fetch
  clearAccessToken()
})

afterEach(() => {
  clearAccessToken()
})

describe('apiRequest', () => {
  it('returns parsed JSON on success', async () => {
    fetchMock.mockResolvedValue(jsonResponse({ status: 'ok' }))
    await expect(apiRequest<{ status: string }>('/health')).resolves.toEqual({ status: 'ok' })
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/health', expect.objectContaining({ method: 'GET' }))
  })

  it('does not send an Authorization header when no token is set', async () => {
    fetchMock.mockResolvedValue(jsonResponse({}))
    await apiRequest('/meta')
    const init = fetchMock.mock.calls[0]?.[1] as RequestInit
    expect((init.headers as Record<string, string>).Authorization).toBeUndefined()
  })

  it('attaches the bearer token for authenticated calls', async () => {
    fetchMock.mockResolvedValue(jsonResponse({}))
    setAccessToken('token-abc')
    await apiRequest('/auth/me')
    const init = fetchMock.mock.calls[0]?.[1] as RequestInit
    expect((init.headers as Record<string, string>).Authorization).toBe('Bearer token-abc')
    expect(getAccessToken()).toBe('token-abc')
  })

  it('serialises the request body as JSON', async () => {
    fetchMock.mockResolvedValue(jsonResponse({}))
    await apiRequest('/auth/login', { method: 'POST', body: { email: 'a@b.test' } })
    const init = fetchMock.mock.calls[0]?.[1] as RequestInit
    expect(init.body).toBe(JSON.stringify({ email: 'a@b.test' }))
    expect((init.headers as Record<string, string>)['Content-Type']).toBe('application/json')
  })

  it('never persists the token to browser storage', () => {
    setAccessToken('token-abc')
    expect(window.localStorage.length).toBe(0)
    expect(window.sessionStorage.length).toBe(0)
  })

  it('normalises the backend error envelope into ApiError', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(
        { error: { code: 'authentication_required', message: 'Authentication is required.' } },
        401,
        { 'X-Request-ID': 'req-1' },
      ),
    )
    await expect(apiRequest('/auth/me')).rejects.toMatchObject({
      name: 'ApiError',
      status: 401,
      code: 'authentication_required',
      requestId: 'req-1',
    })
  })

  it('flags 401 and 403 responses distinctly', async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({ error: { code: 'permission_denied', message: 'Denied.' } }, 403),
    )
    const error = await apiRequest('/tickets').catch((caught: unknown) => caught)
    expect(error).toBeInstanceOf(ApiError)
    expect((error as ApiError).isForbidden).toBe(true)
    expect((error as ApiError).isUnauthorized).toBe(false)
  })

  it('surfaces a non-JSON error without throwing a parse error', async () => {
    fetchMock.mockResolvedValue(new Response('<html>502</html>', { status: 502 }))
    await expect(apiRequest('/health')).rejects.toMatchObject({ code: 'http_502' })
  })

  it('explains a proxy or gateway failure instead of saying "Request failed."', async () => {
    // What the user sees when the app is down but something in front of it
    // (Vite's dev proxy, nginx) answers instead.
    fetchMock.mockResolvedValue(new Response('<html>502 Bad Gateway</html>', { status: 502 }))
    await expect(apiRequest('/health')).rejects.toMatchObject({
      code: 'http_502',
      message: expect.stringMatching(/did not respond/i),
    })
  })

  it('gives the same actionable advice for any envelopeless 5xx', async () => {
    // Vite's dev proxy answers 500 when it cannot reach the backend; nginx
    // answers 502. The user needs the same advice either way, and the exact
    // status stays available in `code` for diagnosis.
    for (const status of [500, 502, 503, 504]) {
      fetchMock.mockResolvedValue(new Response('', { status }))
      await expect(apiRequest('/health')).rejects.toMatchObject({
        code: `http_${status}`,
        message: expect.stringMatching(/try again in a moment/i),
      })
    }
  })

  it('still reports the status when it has nothing better to say', async () => {
    fetchMock.mockResolvedValue(new Response('', { status: 418 }))
    await expect(apiRequest('/health')).rejects.toMatchObject({
      message: expect.stringContaining('418'),
    })
  })

  it('prefers the backend envelope over the generic message', async () => {
    // The enrichment must never mask a real, specific backend error.
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ error: { code: 'internal_error', message: 'Ticket store down.' } }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    await expect(apiRequest('/health')).rejects.toMatchObject({
      message: 'Ticket store down.',
    })
  })

  it('maps network failures to a friendly ApiError', async () => {
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'))
    await expect(apiRequest('/health')).rejects.toMatchObject({
      code: 'network_error',
      status: 0,
    })
  })

  it('propagates abort errors so callers can ignore them', async () => {
    fetchMock.mockRejectedValue(new DOMException('aborted', 'AbortError'))
    await expect(apiRequest('/health')).rejects.toBeInstanceOf(DOMException)
  })

  it('returns undefined for 204 responses', async () => {
    fetchMock.mockResolvedValue(new Response(null, { status: 204 }))
    await expect(apiRequest('/health')).resolves.toBeUndefined()
  })
})
