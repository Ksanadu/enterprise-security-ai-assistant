import type { AuditLogPage, DashboardOverview } from '../api/types'
import { WINDOW_OPTIONS } from '../hooks/useDashboard'

export interface DashboardProps {
  overview: DashboardOverview | null
  audit: AuditLogPage | null
  actions: string[]
  days: number
  actionFilter: string
  loading: boolean
  onDaysChange: (days: number) => void
  onActionChange: (action: string) => void
}

function formatSeconds(value: number | null): string {
  if (value === null) return '—'
  if (value < 90) return `${Math.round(value)}s`
  if (value < 5400) return `${Math.round(value / 60)} min`
  return `${(value / 3600).toFixed(1)} h`
}

/**
 * A bar row for one bucket.
 *
 * Rendered with plain CSS rather than a charting library: the numbers are the
 * point, and a dependency-free bar is easier to audit than a canvas.
 */
function BarRow({
  label,
  value,
  max,
  tone = 'neutral',
}: {
  label: string
  value: number
  max: number
  tone?: 'neutral' | 'warn' | 'danger'
}) {
  const width = max > 0 ? Math.round((value / max) * 100) : 0
  return (
    <li className="bar-row">
      <span className="bar-row__label">{label.replace(/_/g, ' ')}</span>
      <span className={`bar-row__track bar-row__track--${tone}`}>
        <span className="bar-row__fill" style={{ width: `${width}%` }} />
      </span>
      <span className="bar-row__value">{value}</span>
    </li>
  )
}

function Distribution({ title, data, tones }: { title: string; data: Record<string, number>; tones?: Record<string, 'warn' | 'danger'> }) {
  const entries = Object.entries(data)
  const max = Math.max(1, ...entries.map(([, value]) => value))
  return (
    <section className="dash-card">
      <h3 className="dash-card__title">{title}</h3>
      <ul className="bar-list">
        {entries.map(([key, value]) => (
          <BarRow key={key} label={key} value={value} max={max} tone={tones?.[key] ?? 'neutral'} />
        ))}
      </ul>
    </section>
  )
}

export function Dashboard({
  overview,
  audit,
  actions,
  days,
  actionFilter,
  loading,
  onDaysChange,
  onActionChange,
}: DashboardProps) {
  if (overview === null) {
    return (
      <div className="dash">
        <p className="state state--loading">
          {loading ? 'Loading the dashboard…' : 'No dashboard data.'}
        </p>
      </div>
    )
  }

  const { summary, distributions, response_times: responseTimes, document_access: access } =
    overview
  const series = overview.timeseries.series
  const peak = Math.max(1, ...series.map((point) => point.questions))

  return (
    <div className="dash">
      <header className="dash__header">
        <h2 className="dash__title">Security dashboard</h2>
        <label className="dash__window">
          <span className="tickets__filter-label">Window</span>
          <select value={days} onChange={(event) => onDaysChange(Number(event.target.value))}>
            {WINDOW_OPTIONS.map((option) => (
              <option key={option} value={option}>
                last {option} days
              </option>
            ))}
          </select>
        </label>
      </header>

      <section className="dash-cards" aria-label="Headline numbers">
        <article className="dash-card dash-card--stat">
          <span className="dash-stat__value">{summary.questions.in_window}</span>
          <span className="dash-stat__label">questions in window</span>
          <span className="dash-stat__sub">{summary.questions.total} all time</span>
        </article>
        <article className="dash-card dash-card--stat">
          <span className="dash-stat__value dash-stat__value--danger">
            {summary.escalations.in_window}
          </span>
          <span className="dash-stat__label">escalations in window</span>
          <span className="dash-stat__sub">{summary.escalations.total} all time</span>
        </article>
        <article className="dash-card dash-card--stat">
          <span className="dash-stat__value dash-stat__value--danger">
            {summary.tickets.requiring_human}
          </span>
          <span className="dash-stat__label">tickets needing a human</span>
          <span className="dash-stat__sub">{summary.tickets.unacknowledged} not acknowledged</span>
        </article>
        <article className="dash-card dash-card--stat">
          <span className="dash-stat__value">{summary.security_signals.access_denials}</span>
          <span className="dash-stat__label">access denials</span>
          <span className="dash-stat__sub">
            {summary.security_signals.blocked_prompt_injections} injection attempts blocked
          </span>
        </article>
        <article className="dash-card dash-card--stat">
          <span className="dash-stat__value">{formatSeconds(responseTimes.median_seconds)}</span>
          <span className="dash-stat__label">median time to acknowledge</span>
          <span className="dash-stat__sub">
            {responseTimes.acknowledged} of {responseTimes.escalated_tickets} escalated tickets
          </span>
        </article>
        <article className="dash-card dash-card--stat">
          <span className="dash-stat__value">{summary.users.active_in_window}</span>
          <span className="dash-stat__label">active users in window</span>
          <span className="dash-stat__sub">
            {summary.users.total} accounts · {summary.users.active_sessions} live sessions
          </span>
        </article>
      </section>

      <section className="dash-card dash-card--wide">
        <h3 className="dash-card__title">Daily activity</h3>
        <ul className="spark" aria-label="Questions per day">
          {series.map((point) => (
            <li key={point.date} className="spark__day" title={`${point.date}: ${point.questions} questions, ${point.escalations} escalations`}>
              <span
                className="spark__bar"
                style={{ height: `${Math.max(2, Math.round((point.questions / peak) * 100))}%` }}
              />
              {point.escalations > 0 && (
                <span
                  className="spark__escalation"
                  style={{
                    height: `${Math.max(4, Math.round((point.escalations / peak) * 100))}%`,
                  }}
                />
              )}
              <span className="spark__label">{point.date.slice(5)}</span>
            </li>
          ))}
        </ul>
        <p className="dash-card__hint">
          Blue is questions answered; the red marker on a day shows escalations.
        </p>
      </section>

      <div className="dash-grid">
        <Distribution
          title="Risk levels"
          data={distributions.risk_levels}
          tones={{ high: 'warn', critical: 'danger' }}
        />
        <Distribution title="Intents" data={distributions.intents} />
        <Distribution
          title="Ticket status"
          data={distributions.ticket_status}
          tones={{ escalated: 'danger' }}
        />
        <Distribution
          title="Ticket severity"
          data={distributions.ticket_severity}
          tones={{ high: 'warn', critical: 'danger' }}
        />
        <Distribution title="Ticket queue" data={distributions.ticket_owner_role} />
        <Distribution title="Refusals by role" data={access.denials_by_role} tones={{ employee: 'warn' }} />
      </div>

      <div className="dash-grid">
        <section className="dash-card">
          <h3 className="dash-card__title">Most viewed documents</h3>
          {access.most_viewed_documents.length === 0 ? (
            <p className="dash-card__hint">No document reads recorded in this window.</p>
          ) : (
            <ul className="bar-list">
              {access.most_viewed_documents.map((entry) => (
                <BarRow
                  key={entry.document_id}
                  label={entry.document_id}
                  value={entry.count}
                  max={Math.max(...access.most_viewed_documents.map((item) => item.count))}
                />
              ))}
            </ul>
          )}
        </section>

        <section className="dash-card">
          <h3 className="dash-card__title">Refused document accesses</h3>
          {access.most_refused_documents.length === 0 ? (
            <p className="dash-card__hint">Nothing was refused in this window.</p>
          ) : (
            <ul className="bar-list">
              {access.most_refused_documents.map((entry) => (
                <BarRow
                  key={entry.document_id}
                  label={entry.document_id}
                  value={entry.count}
                  max={Math.max(...access.most_refused_documents.map((item) => item.count))}
                  tone="warn"
                />
              ))}
            </ul>
          )}
        </section>

        <section className="dash-card">
          <h3 className="dash-card__title">Busiest audit actions</h3>
          <ul className="bar-list">
            {distributions.top_actions.map((entry) => (
              <BarRow
                key={entry.action}
                label={entry.action}
                value={entry.count}
                max={Math.max(...distributions.top_actions.map((item) => item.count), 1)}
              />
            ))}
          </ul>
        </section>
      </div>

      <section className="dash-card dash-card--wide">
        <header className="audit__header">
          <h3 className="dash-card__title">Audit trail</h3>
          <label className="dash__window">
            <span className="tickets__filter-label">Action</span>
            <select value={actionFilter} onChange={(event) => onActionChange(event.target.value)}>
              <option value="">All actions</option>
              {actions.map((action) => (
                <option key={action} value={action}>
                  {action}
                </option>
              ))}
            </select>
          </label>
        </header>

        {audit === null || audit.entries.length === 0 ? (
          <p className="dash-card__hint">No audit entries match.</p>
        ) : (
          <table className="audit">
            <thead>
              <tr>
                <th scope="col">When</th>
                <th scope="col">Action</th>
                <th scope="col">Outcome</th>
                <th scope="col">Role</th>
                <th scope="col">Resource</th>
              </tr>
            </thead>
            <tbody>
              {audit.entries.map((entry) => (
                <tr key={entry.id} className={entry.outcome === 'denied' ? 'is-denied' : ''}>
                  <td>{entry.created_at ? new Date(entry.created_at).toLocaleString() : '—'}</td>
                  <td>
                    <code>{entry.action}</code>
                  </td>
                  <td>{entry.outcome}</td>
                  <td>{entry.actor_role ?? '—'}</td>
                  <td>{entry.resource_id ?? entry.resource_type ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <p className="dash-card__hint">
          Showing {audit?.returned ?? 0} of {audit?.total ?? 0} entries. Audit detail is recorded
          as metadata only; the dashboard shows counts and identifiers, never conversation
          content.
        </p>
      </section>
    </div>
  )
}
