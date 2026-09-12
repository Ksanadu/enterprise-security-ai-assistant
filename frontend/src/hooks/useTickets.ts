import { useCallback, useEffect, useState } from 'react'

import { ApiError, api } from '../api/client'
import type { TicketDetail, TicketList, TicketStatus } from '../api/types'

export interface UseTicketsResult {
  listing: TicketList | null
  active: TicketDetail | null
  loading: boolean
  busy: boolean
  error: string | null
  statusFilter: TicketStatus | ''
  setStatusFilter: (status: TicketStatus | '') => void
  open: (reference: string) => Promise<void>
  close: () => void
  changeStatus: (status: TicketStatus, note: string) => Promise<void>
  addNote: (note: string) => Promise<void>
  refresh: () => Promise<void>
  dismissError: () => void
}

/**
 * Ticket workspace state.
 *
 * The client stays a view over the server's decision: `can_update` comes from
 * the API, and the status buttons are rendered from it rather than from a local
 * guess about the caller's role. The server enforces it either way.
 */
export function useTickets(onUnauthorized: () => void, enabled: boolean): UseTicketsResult {
  const [listing, setListing] = useState<TicketList | null>(null)
  const [active, setActive] = useState<TicketDetail | null>(null)
  const [loading, setLoading] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [statusFilter, setStatusFilter] = useState<TicketStatus | ''>('')

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
    try {
      const result = await api.tickets.list(
        statusFilter ? { status: statusFilter } : {},
      )
      setListing(result)
    } catch (cause) {
      handleFailure(cause, 'Could not load tickets.')
    } finally {
      setLoading(false)
    }
  }, [handleFailure, statusFilter])

  useEffect(() => {
    if (!enabled) return
    void refresh()
  }, [enabled, refresh])

  const open = useCallback(
    async (reference: string) => {
      setBusy(true)
      setError(null)
      try {
        setActive(await api.tickets.get(reference))
      } catch (cause) {
        handleFailure(cause, 'Could not open that ticket.')
      } finally {
        setBusy(false)
      }
    },
    [handleFailure],
  )

  const close = useCallback(() => setActive(null), [])

  const changeStatus = useCallback(
    async (status: TicketStatus, note: string) => {
      if (!active) return
      setBusy(true)
      setError(null)
      try {
        const updated = await api.tickets.updateStatus(active.reference, status, note)
        setActive(updated)
        await refresh()
      } catch (cause) {
        handleFailure(cause, 'Could not change the status.')
      } finally {
        setBusy(false)
      }
    },
    [active, handleFailure, refresh],
  )

  const addNote = useCallback(
    async (note: string) => {
      if (!active) return
      setBusy(true)
      setError(null)
      try {
        setActive(await api.tickets.addNote(active.reference, note))
      } catch (cause) {
        handleFailure(cause, 'Could not add the note.')
      } finally {
        setBusy(false)
      }
    },
    [active, handleFailure],
  )

  const dismissError = useCallback(() => setError(null), [])

  return {
    listing,
    active,
    loading,
    busy,
    error,
    statusFilter,
    setStatusFilter,
    open,
    close,
    changeStatus,
    addNote,
    refresh,
    dismissError,
  }
}
