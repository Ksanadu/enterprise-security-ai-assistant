import { useState, type FormEvent } from 'react'

import type { TicketDetail, TicketList, TicketStatus } from '../api/types'

/** Statuses a ticket can be moved to, in the order they appear in the UI. */
const NEXT_STATUSES: TicketStatus[] = [
  'open',
  'in_progress',
  'escalated',
  'resolved',
  'closed',
]

export interface TicketBoardProps {
  listing: TicketList | null
  active: TicketDetail | null
  loading: boolean
  busy: boolean
  statusFilter: TicketStatus | ''
  onFilterChange: (status: TicketStatus | '') => void
  onOpen: (reference: string) => void
  onClose: () => void
  onChangeStatus: (status: TicketStatus, note: string) => void
  onAddNote: (note: string) => void
}

function formatTimestamp(value: string | null): string {
  if (!value) return 'unknown'
  const parsed = new Date(value)
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString()
}

export function TicketBoard({
  listing,
  active,
  loading,
  busy,
  statusFilter,
  onFilterChange,
  onOpen,
  onClose,
  onChangeStatus,
  onAddNote,
}: TicketBoardProps) {
  return (
    <div className="tickets">
      <section className="tickets__list" aria-label="Tickets">
        <header className="tickets__header">
          <h2 className="tickets__title">Tickets</h2>
          <label className="tickets__filter">
            <span className="tickets__filter-label">Status</span>
            <select
              value={statusFilter}
              onChange={(event) => onFilterChange(event.target.value as TicketStatus | '')}
            >
              <option value="">All</option>
              {NEXT_STATUSES.map((status) => (
                <option key={status} value={status}>
                  {status.replace('_', ' ')}
                </option>
              ))}
            </select>
          </label>
        </header>

        {listing && (
          <dl className="ticket-stats">
            <div>
              <dt>Visible</dt>
              <dd>{listing.statistics.total}</dd>
            </div>
            <div>
              <dt>Open</dt>
              <dd>{listing.statistics.open}</dd>
            </div>
            <div>
              <dt>Escalated</dt>
              <dd className="ticket-stats__alert">{listing.statistics.escalated}</dd>
            </div>
            <div>
              <dt>Needs a human</dt>
              <dd className="ticket-stats__alert">{listing.statistics.requiring_human}</dd>
            </div>
          </dl>
        )}

        {loading && <p className="state state--loading">Loading tickets…</p>}

        {listing && listing.tickets.length === 0 && !loading && (
          <p className="tickets__empty">
            No tickets are visible to your role. Ask the assistant about a security problem and one
            may be raised for you.
          </p>
        )}

        <ul className="ticket-list">
          {(listing?.tickets ?? []).map((ticket) => (
            <li key={ticket.reference}>
              <button
                type="button"
                className={`ticket-row ${active?.reference === ticket.reference ? 'is-active' : ''}`}
                onClick={() => onOpen(ticket.reference)}
              >
                <span className="ticket-row__top">
                  <code className="ticket-row__ref">{ticket.reference}</code>
                  <span className={`pill pill--risk-${ticket.severity}`}>{ticket.severity}</span>
                  <span className={`pill pill--status-${ticket.status}`}>
                    {ticket.status.replace('_', ' ')}
                  </span>
                </span>
                <span className="ticket-row__title">{ticket.title}</span>
                <span className="ticket-row__meta">
                  {ticket.owner_role} queue · {ticket.source}
                  {ticket.escalation_required && ' · needs a human'}
                </span>
              </button>
            </li>
          ))}
        </ul>
      </section>

      <section className="tickets__detail" aria-label="Ticket detail">
        {active === null ? (
          <p className="tickets__empty">Select a ticket to see its history.</p>
        ) : (
          <TicketDetailPanel
            ticket={active}
            busy={busy}
            onClose={onClose}
            onChangeStatus={onChangeStatus}
            onAddNote={onAddNote}
          />
        )}
      </section>
    </div>
  )
}

interface TicketDetailPanelProps {
  ticket: TicketDetail
  busy: boolean
  onClose: () => void
  onChangeStatus: (status: TicketStatus, note: string) => void
  onAddNote: (note: string) => void
}

function TicketDetailPanel({
  ticket,
  busy,
  onClose,
  onChangeStatus,
  onAddNote,
}: TicketDetailPanelProps) {
  const [note, setNote] = useState('')

  function submitStatus(event: FormEvent<HTMLFormElement>, status: TicketStatus) {
    event.preventDefault()
    onChangeStatus(status, note)
    setNote('')
  }

  return (
    <article className="ticket-detail">
      <header className="ticket-detail__header">
        <div>
          <code className="ticket-detail__ref">{ticket.reference}</code>
          <h2 className="ticket-detail__title">{ticket.title}</h2>
        </div>
        <button type="button" className="button button--ghost" onClick={onClose}>
          Close
        </button>
      </header>

      <dl className="ticket-detail__facts">
        <div>
          <dt>Status</dt>
          <dd>
            <span className={`pill pill--status-${ticket.status}`}>
              {ticket.status.replace('_', ' ')}
            </span>
          </dd>
        </div>
        <div>
          <dt>Severity</dt>
          <dd>
            <span className={`pill pill--risk-${ticket.severity}`}>{ticket.severity}</span>
          </dd>
        </div>
        <div>
          <dt>Queue</dt>
          <dd>{ticket.owner_role}</dd>
        </div>
        <div>
          <dt>Raised by</dt>
          <dd>{ticket.source.replace('_', ' ')}</dd>
        </div>
        <div>
          <dt>Updated</dt>
          <dd>{formatTimestamp(ticket.updated_at)}</dd>
        </div>
      </dl>

      {ticket.escalation_required && (
        <p className="assessment__escalation" role="status">
          This ticket requires a human response and must be acknowledged before it can be
          resolved.
        </p>
      )}

      {ticket.description && (
        <section className="ticket-detail__section">
          <h3 className="ticket-detail__subtitle">Assessment</h3>
          <pre className="ticket-detail__description">{ticket.description}</pre>
        </section>
      )}

      <section className="ticket-detail__section">
        <h3 className="ticket-detail__subtitle">Timeline</h3>
        <ol className="timeline">
          {ticket.events.map((event) => (
            <li key={event.id} className="timeline__item">
              <span className="timeline__type">{event.event_type.replace('_', ' ')}</span>
              <span className="timeline__meta">
                {formatTimestamp(event.created_at)} ·{' '}
                {event.automated ? 'system' : (event.actor_role ?? 'user')}
                {event.to_status && ` · → ${event.to_status.replace('_', ' ')}`}
                {event.to_severity && ` · → ${event.to_severity}`}
              </span>
              {event.note && <p className="timeline__note">{event.note}</p>}
            </li>
          ))}
        </ol>
      </section>

      <form
        className="ticket-detail__actions"
        onSubmit={(event) => submitStatus(event, nextStatus(ticket.status))}
      >
        <label className="field">
          <span className="field__label">Note (optional)</span>
          <input
            className="field__input"
            value={note}
            maxLength={2000}
            onChange={(event) => setNote(event.target.value)}
            placeholder="Why is the status changing?"
          />
        </label>

        {ticket.can_update ? (
          <div className="ticket-detail__buttons">
            {NEXT_STATUSES.filter((status) => status !== ticket.status).map((status) => (
              <button
                key={status}
                type="submit"
                className="button button--ghost"
                disabled={busy}
                onClick={(event) => submitStatus(event as unknown as FormEvent<HTMLFormElement>, status)}
              >
                Move to {status.replace('_', ' ')}
              </button>
            ))}
          </div>
        ) : (
          <p className="ticket-detail__readonly">
            You can follow this ticket but not change its status. The security team handles the
            resolution.
          </p>
        )}

        <button
          type="button"
          className="button button--ghost"
          disabled={busy || note.trim().length === 0}
          onClick={() => {
            onAddNote(note)
            setNote('')
          }}
        >
          Add note
        </button>
      </form>
    </article>
  )
}

/** The sensible next status, used when the form is submitted with Enter. */
function nextStatus(current: TicketStatus): TicketStatus {
  if (current === 'open') return 'in_progress'
  if (current === 'in_progress') return 'resolved'
  if (current === 'escalated') return 'in_progress'
  if (current === 'resolved') return 'closed'
  return current
}
