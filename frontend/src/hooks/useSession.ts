import { useCallback, useState } from 'react'

import { ApiError, api, clearAccessToken, getAccessToken, setAccessToken } from '../api/client'
import type { UserPublic } from '../api/types'

/**
 * Session state.
 *
 * The access token lives in memory only (inside the API client), so a page
 * refresh signs the user out. That is a deliberate trade-off: a token in
 * `localStorage` is readable by any injected script, and this application is
 * about demonstrating safe handling of sensitive material.
 */
export interface Session {
  user: UserPublic
  expiresInSeconds: number
}

export interface UseSessionResult {
  session: Session | null
  busy: boolean
  error: string | null
  signIn: (email: string, password: string) => Promise<boolean>
  signOut: (reason?: string) => void
  clearError: () => void
}

export function useSession(): UseSessionResult {
  const [session, setSession] = useState<Session | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const signIn = useCallback(async (email: string, password: string): Promise<boolean> => {
    setBusy(true)
    setError(null)
    try {
      const result = await api.login(email.trim(), password)
      setAccessToken(result.access_token)
      setSession({ user: result.user, expiresInSeconds: result.expires_in })
      return true
    } catch (cause) {
      clearAccessToken()
      setError(
        cause instanceof ApiError
          ? cause.message
          : 'Sign-in failed. Please check your connection and try again.',
      )
      return false
    } finally {
      setBusy(false)
    }
  }, [])

  const signOut = useCallback((reason?: string) => {
    // Revoke server-side first, best effort: a network failure must never trap
    // the user in a signed-in state.
    const hadToken = getAccessToken() !== null
    if (hadToken) {
      void api.auth.logout().catch(() => undefined)
    }
    clearAccessToken()
    setSession(null)
    setError(reason ?? null)
  }, [])

  const clearError = useCallback(() => setError(null), [])

  return { session, busy, error, signIn, signOut, clearError }
}
