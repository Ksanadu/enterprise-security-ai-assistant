import type { ChatMessage } from '../api/types'
import { MessageBubble } from './MessageBubble'

export interface MessageThreadProps {
  messages: ChatMessage[]
  loading: boolean
  sending: boolean
  hasConversation: boolean
  /** Omitted when the user may not raise tickets from this view. */
  onRaiseTicket?: ((message: ChatMessage) => void) | undefined
  raisingTicketId?: number | null
  raisedTickets?: Record<number, string>
}

const EXAMPLE_QUESTIONS = [
  'What are the company password requirements?',
  'I received an email asking me to click a link and log in again — is that normal?',
  'After I opened an email attachment my computer started showing strange pop-up windows.',
  'I suddenly cannot connect to the company VPN today.',
]

export function MessageThread({
  messages,
  loading,
  sending,
  hasConversation,
  onRaiseTicket,
  raisingTicketId = null,
  raisedTickets = {},
}: MessageThreadProps) {
  if (loading) {
    return (
      <div className="thread thread--placeholder">
        <p className="state state--loading">Loading conversation…</p>
      </div>
    )
  }

  if (!hasConversation || messages.length === 0) {
    return (
      <div className="thread thread--placeholder">
        <h2 className="placeholder__title">Ask about security policy, incidents or IT problems</h2>
        <p className="placeholder__text">
          Answers are drawn only from the internal knowledge base, and every answer lists the
          documents it used.
        </p>
        <ul className="placeholder__examples">
          {EXAMPLE_QUESTIONS.map((question) => (
            <li key={question}>{question}</li>
          ))}
        </ul>
      </div>
    )
  }

  return (
    <div className="thread" aria-live="polite">
      {messages.map((message) => (
        <MessageBubble
          key={message.id}
          message={message}
          onRaiseTicket={onRaiseTicket}
          raisingTicket={raisingTicketId === message.id}
          raisedReference={raisedTickets[message.id] ?? null}
        />
      ))}
      {sending && (
        <p className="thread__pending" role="status">
          Searching the knowledge base…
        </p>
      )}
    </div>
  )
}
