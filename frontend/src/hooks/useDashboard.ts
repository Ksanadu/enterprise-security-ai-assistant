import { useCallback, useEffect, useState } from 'react'

import { ApiError, api } from '../api/client'
import type { AuditLogPage, DashboardOverview } from '../api/types'

export interface UseDashboardResult {
  overview: DashboardOverview | null
  audit: AuditLogPage | null
  actions: string[]
  days: number
  setDays: (days: number) => void
  actionFilter: string
  setActionFilter: (action: string) => void
  loading: boolean
  error: string | null
  refresh: () => Promise<void>
  loadAudit: () => Promise<void>
  dismissError: () => void
}

/** Windows the UI offers. Mirrors the server's own bounds. */
export const WINDOW_OPTIONS = [7, 14, 30, 90] as const

/**
 * Dashboard state. Only fetched once the security tab is opened, and only for a
 * caller the server will accept - a non-security user gets a 403 that is shown
 * rather than hidden.
 */
export function useDashboard(onUnauthorized: () => void, enabled: boolean): UseDashboardResult {
  const [overview, setOverview] = useState<DashboardOverview | null>(null)
  const [audit, setAudit] = useState<AuditLogPage | null>(null)
  const [actions, setActions] = useState<string[]>([])
  const [days, setDays] = useState<number>(14)
  const [actionFilter, setActionFilter] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleFailure = useCallback(
    (cause: unknown, fallback: string) => {
      if (cause instanceof ApiError && cause.isUnauthorized) {
        onUnauthorized()
        return
      }
      setError(cause instanceof ApiError ? cause.message : fallback)
    },
    [onUnauthorized],
  )

  const refresh = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [result, actionList] = await Promise.all([
        api.dashboard.overview(days),
        api.dashboard.auditActions(),
      ])
      setOverview(result)
      setActions(actionList.actions)
    } catch (cause) {
      handleFailure(cause, 'Could not load the dashboard.')
    } finally {
      setLoading(false)
    }
  }, [days, handleFailure])

  const loadAudit = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      setAudit(await api.dashboard.audit({ action: actionFilter, limit: 50 }))
    } catch (cause) {
      handleFailure(cause, 'Could not search the audit trail.')
    } finally {
      setLoading(false)
    }
  }, [actionFilter, handleFailure])

  useEffect(() => {
    if (!enabled) return
    void refresh()
  }, [enabled, refresh])

  useEffect(() => {
    if (!enabled) return
    void loadAudit()
  }, [enabled, loadAudit])

  const dismissError = useCallback(() => setError(null), [])

  return {
    overview,
    audit,
    actions,
    days,
    setDays,
    actionFilter,
    setActionFilter,
    loading,
    error,
    refresh,
    loadAudit,
    dismissError,
  }
}
