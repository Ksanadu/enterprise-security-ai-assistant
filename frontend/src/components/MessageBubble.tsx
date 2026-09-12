import type { ChatMessage } from '../api/types'
import { RiskBadge } from './RiskBadge'
import { SourceCitations } from './SourceCitations'

export interface MessageBubbleProps {
  message: ChatMessage
  /** Present when the user may raise a ticket from this answer. */
  onRaiseTicket?: ((message: ChatMessage) => void) | undefined
  /** True while this message's ticket request is in flight. */
  raisingTicket?: boolean
  /** The reference of a ticket the user raised from this answer. */
  raisedReference?: string | null
}

/** Render a plain-text answer, preserving the line breaks the model produced. */
function AnswerText({ content }: { content: string }) {
  const paragraphs = content.split(/\n{2,}/).filter((part) => part.trim())
  return (
    <>
      {paragraphs.map((paragraph, index) => {
        const lines = paragraph.split('\n')
        return (
          <p key={index} className="bubble__paragraph">
            {lines.map((line, lineIndex) => (
              <span key={lineIndex}>
                {line}
                {lineIndex < lines.length - 1 && <br />}
              </span>
            ))}
          </p>
        )
      })}
    </>
  )
}

export function MessageBubble({
  message,
  onRaiseTicket,
  raisingTicket = false,
  raisedReference = null,
}: MessageBubbleProps) {
  const isUser = message.role === 'user'
  const payload = message.payload

  // A ticket the user asks for, as opposed to the one the backend raises by
  // itself for a high-risk event. Offered when the assistant answered without
  // resolving the problem and nothing has been filed yet - the specification's
  // "if it cannot be solved, suggest raising a ticket".
  const canRaiseTicket =
    !isUser &&
    Boolean(onRaiseTicket) &&
    Boolean(payload) &&
    payload?.grounded === true &&
    payload?.blocked !== true &&
    !payload?.ticket_reference &&
    !raisedReference

  return (
    <article className={`bubble ${isUser ? 'bubble--user' : 'bubble--assistant'}`}>
      <header className="bubble__header">
        <span className="bubble__author">{isUser ? 'You' : 'Security Assistant'}</span>
        {!isUser && payload && (
          <span className="bubble__provider" title="Answer generator">
            {payload.blocked
              ? 'request refused'
              : payload.grounded
                ? 'grounded in the knowledge base'
                : 'no matching document'}
          </span>
        )}
      </header>

      <div className="bubble__body">
        <AnswerText content={message.content} />
      </div>

      {payload?.ticket_reference && (
        <p className="ticket-chip" role="status">
          <span className="ticket-chip__label">
            {payload.ticket_status === 'escalated'
              ? 'Security ticket raised and escalated'
              : 'Security ticket raised'}
          </span>
          <code className="ticket-chip__ref">{payload.ticket_reference}</code>
        </p>
      )}

      {raisedReference && (
        <p className="ticket-chip ticket-chip--requested" role="status">
          <span className="ticket-chip__label">Ticket raised at your request</span>
          <code className="ticket-chip__ref">{raisedReference}</code>
        </p>
      )}

      {canRaiseTicket && (
        <div className="bubble__follow-up">
          <button
            type="button"
            className="button button--ghost"
            onClick={() => onRaiseTicket?.(message)}
            disabled={raisingTicket}
            aria-busy={raisingTicket}
          >
            {raisingTicket ? 'Creating ticket…' : 'Create ticket'}
          </button>
          <span className="bubble__follow-up-hint">
            Raise this with the service desk if you need a person to follow up.
          </span>
        </div>
      )}

      {payload && !isUser && (
        <RiskBadge
          level={payload.risk_level}
          intent={payload.intent}
          signals={payload.risk_signals}
          escalation={payload.human_escalation}
        />
      )}

      {payload && payload.recommended_actions.length > 0 && (
        <section className="actions" aria-label="Recommended actions">
          <h3 className="actions__title">Recommended actions</h3>
          <ol className="actions__list">
            {payload.recommended_actions.map((action, index) => (
              <li key={index}>{action}</li>
            ))}
          </ol>
        </section>
      )}

      {payload && <SourceCitations sources={payload.source_documents} />}
    </article>
  )
}
