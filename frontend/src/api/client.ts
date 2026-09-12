/**
 * Typed HTTP client for the backend API.
 *
 * Design rules:
 *  - The access token is held in memory only. It is never written to
 *    `localStorage`, so a successful XSS cannot read a long-lived credential
 *    out of persistent storage.
 *  - Every non-2xx response is normalised into an `ApiError` carrying the
 *    backend's stable error `code`, so the UI never has to parse raw text.
 */

import { API_PREFIX, config } from '../config'
import {
  isErrorEnvelope,
  type AuditLogPage,
  type ChatCapabilities,
  type ConversationDetail,
  type ConversationList,
  type ConversationSummary,
  type DashboardOverview,
  type ErrorEnvelope,
  type HealthResponse,
  type MetaResponse,
  type PostMessageResult,
  type TicketDetail,
  type TicketList,
  type TokenResponse,
  type UserPublic,
} from './types'

export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly requestId: string | null

  constructor(status: number, code: string, message: string, requestId: string | null = null) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.requestId = requestId
  }

  get isUnauthorized(): boolean {
    return this.status === 401
  }

  get isForbidden(): boolean {
    return this.status === 403
  }
}

/**
 * A message a person can act on, for a response that carried no error envelope.
 *
 * The backend always sends one, so reaching this path means something in front
 * of it answered instead - a proxy that could not reach the app (502/503/504),
 * or a gateway error page. "Request failed." tells the user nothing about what
 * happened or what to do; these do.
 */
function describeStatus(status: number): string {
  if (status >= 500) {
    // Any 5xx without an envelope came from something in front of the app -
    // Vite's dev proxy answers 500 when it cannot reach the backend, nginx
    // answers 502. The backend itself always sends a structured error, so the
    // advice here is the same either way; the exact code is kept in `code`.
    return 'The server did not respond. It may still be starting up or briefly unavailable - try again in a moment.'
  }
  if (status === 401) {
    return 'Your session has ended. Please sign in again.'
  }
  if (status === 403) {
    return 'You do not have access to that.'
  }
  if (status === 404) {
    return 'That item no longer exists.'
  }
  return `The request was rejected (HTTP ${status}).`
}

let accessToken: string | null = null
export function setAccessToken(token: string | null): void {
  accessToken = token
}

export function getAccessToken(): string | null {
  return accessToken
}

export function clearAccessToken(): void {
  accessToken = null
}

function buildUrl(path: string): string {
  const normalised = path.startsWith('/') ? path : `/${path}`
  return `${config.apiBaseUrl}${normalised}`
}

export interface RequestOptions {
  method?: 'GET' | 'POST' | 'PATCH' | 'DELETE'
  body?: unknown
  signal?: AbortSignal
  /** Override the in-memory token (used by tests). */
  token?: string | null
}

export async function apiRequest<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = 'GET', body, signal, token } = options
  const effectiveToken = token === undefined ? accessToken : token

  const headers: Record<string, string> = { Accept: 'application/json' }
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  if (effectiveToken) headers['Authorization'] = `Bearer ${effectiveToken}`

  let response: Response
  try {
    response = await fetch(buildUrl(`${API_PREFIX}${path}`), {
      method,
      headers,
      credentials: 'omit',
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      ...(signal ? { signal } : {}),
    })
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === 'AbortError') throw cause
    throw new ApiError(0, 'network_error', 'Cannot reach the server. Is the backend running?')
  }

  const requestId = response.headers.get('X-Request-ID')

  if (response.status === 204) return undefined as T

  const raw = await response.text()
  let parsed: unknown = null
  if (raw.length > 0) {
    try {
      parsed = JSON.parse(raw)
    } catch {
      parsed = null
    }
  }

  if (!response.ok) {
    if (isErrorEnvelope(parsed)) {
      const envelope = parsed as ErrorEnvelope
      throw new ApiError(
        response.status,
        envelope.error.code,
        envelope.error.message,
        envelope.error.request_id ?? requestId,
      )
    }
    throw new ApiError(response.status, `http_${response.status}`, describeStatus(response.status), requestId)
  }

  return parsed as T
}

export const api = {
  health: (options?: RequestOptions) => apiRequest<HealthResponse>('/health', options),
  meta: (options?: RequestOptions) => apiRequest<MetaResponse>('/meta', options),
  login: (email: string, password: string, options?: RequestOptions) =>
    apiRequest<TokenResponse>('/auth/login', {
      ...options,
      method: 'POST',
      body: { email, password },
      token: null,
    }),
  me: (options?: RequestOptions) => apiRequest<UserPublic>('/auth/me', options),

  chat: {
    capabilities: (options?: RequestOptions) =>
      apiRequest<ChatCapabilities>('/chat/capabilities', options),
    listConversations: (options?: RequestOptions) =>
      apiRequest<ConversationList>('/chat/conversations', options),
    createConversation: (title: string | null, options?: RequestOptions) =>
      apiRequest<ConversationSummary>('/chat/conversations', {
        ...options,
        method: 'POST',
        body: title ? { title } : {},
      }),
    getConversation: (id: number, options?: RequestOptions) =>
      apiRequest<ConversationDetail>(`/chat/conversations/${id}`, options),
    deleteConversation: (id: number, options?: RequestOptions) =>
      apiRequest<void>(`/chat/conversations/${id}`, { ...options, method: 'DELETE' }),
    sendMessage: (id: number, content: string, options?: RequestOptions) =>
      apiRequest<PostMessageResult>(`/chat/conversations/${id}/messages`, {
        ...options,
        method: 'POST',
        body: { content },
      }),
  },

  auth: {
    /**
     * Revoke the current token server-side.
     *
     * Discarding a token in the browser leaves it usable until it expires, so
     * signing out has to tell the server. Failures are tolerated by the caller:
     * a user must always be able to sign out locally.
     */
    logout: (options?: RequestOptions) =>
      apiRequest<void>('/auth/logout', { ...options, method: 'POST' }),
  },

  tickets: {
    list: (params: { status?: string; severity?: string } = {}, options?: RequestOptions) => {
      const query = new URLSearchParams()
      if (params.status) query.set('status', params.status)
      if (params.severity) query.set('severity', params.severity)
      const suffix = query.toString() ? `?${query.toString()}` : ''
      return apiRequest<TicketList>(`/tickets${suffix}`, options)
    },
    get: (reference: string, options?: RequestOptions) =>
      apiRequest<TicketDetail>(`/tickets/${encodeURIComponent(reference)}`, options),
    updateStatus: (reference: string, status: string, note: string, options?: RequestOptions) =>
      apiRequest<TicketDetail>(`/tickets/${encodeURIComponent(reference)}`, {
        ...options,
        method: 'PATCH',
        body: { status, note },
      }),
    addNote: (reference: string, note: string, options?: RequestOptions) =>
      apiRequest<TicketDetail>(`/tickets/${encodeURIComponent(reference)}/notes`, {
        ...options,
        method: 'POST',
        body: { note },
      }),
    raise: (
      title: string,
      description: string,
      category: string,
      options?: RequestOptions,
    ) =>
      apiRequest<TicketDetail>('/tickets', {
        ...options,
        method: 'POST',
        body: { title, description, category },
      }),
  },

  dashboard: {
    /** Security role only; the server refuses anyone else. */
    overview: (days: number, options?: RequestOptions) =>
      apiRequest<DashboardOverview>(`/dashboard/overview?days=${days}`, options),
    audit: (
      params: { action?: string; outcome?: string; actor_role?: string; limit?: number },
      options?: RequestOptions,
    ) => {
      const query = new URLSearchParams()
      for (const [key, value] of Object.entries(params)) {
        if (value !== undefined && value !== '') query.set(key, String(value))
      }
      const suffix = query.toString() ? `?${query.toString()}` : ''
      return apiRequest<AuditLogPage>(`/dashboard/audit${suffix}`, options)
    },
    auditActions: (options?: RequestOptions) =>
      apiRequest<{ actions: string[] }>('/dashboard/audit/actions', options),
  },
}
