import { useCallback, useState } from 'react'

import { useChat } from '../hooks/useChat'
import { useDashboard } from '../hooks/useDashboard'
import { useTickets } from '../hooks/useTickets'
import type { ChatMessage, UserPublic } from '../api/types'
import { Composer } from './Composer'
import { ConversationSidebar, SessionBar } from './ConversationSidebar'
import { Dashboard } from './Dashboard'
import { MessageThread } from './MessageThread'
import { TicketBoard } from './TicketBoard'

export interface ChatWorkspaceProps {
  user: UserPublic
  onSignOut: (reason?: string) => void
  maxMessageLength?: number
}

type Tab = 'chat' | 'tickets' | 'dashboard'

export function ChatWorkspace({ user, onSignOut, maxMessageLength = 2000 }: ChatWorkspaceProps) {
  const [tab, setTab] = useState<Tab>('chat')

  // Stable identity: the hooks hold this in a ref, but an inline arrow would
  // still churn the dependency chain on every render.
  const handleUnauthorized = useCallback(
    () => onSignOut('Your session expired. Please sign in again.'),
    [onSignOut],
  )
  const chat = useChat(handleUnauthorized)
  const tickets = useTickets(handleUnauthorized, tab === 'tickets')
  const dashboard = useDashboard(handleUnauthorized, tab === 'dashboard')

  const busy = chat.status === 'loading' || chat.status === 'sending'
  // The dashboard is a security-team view. The server enforces it; hiding the
  // tab only avoids offering a button that would be refused.
  const canSeeDashboard = user.role === 'security'

  /**
   * Raise a ticket from an answer the user could not resolve.
   *
   * The title comes from the question that produced the answer, so the queue
   * shows what was asked rather than a generic label. The queue it lands in is
   * decided by the server from the caller's role, not by anything sent here.
   */
  const raiseTicketFrom = useCallback(
    (message: ChatMessage) => {
      const index = chat.messages.findIndex((candidate) => candidate.id === message.id)
      const question = [...chat.messages.slice(0, Math.max(index, 0))]
        .reverse()
        .find((candidate) => candidate.role === 'user')

      const title = (question?.content ?? 'Follow-up needed on a security question')
        .replace(/\s+/g, ' ')
        .trim()
        .slice(0, 200)

      const description = [
        'Raised by the user from the security assistant.',
        question ? `\n\nQuestion: ${question.content}` : '',
        `\n\nAssessment: intent=${message.payload?.intent ?? 'unknown'}, ` +
          `risk=${message.payload?.risk_level ?? 'unknown'}.`,
        '\n\nReason: the knowledge base answer did not resolve the problem.',
      ].join('')

      // The owning queue is the server's decision, from the caller's role. The
      // category is only a label, but it should still agree with what the answer
      // was about rather than always saying "security".
      const category = message.payload?.intent === 'it_support' ? 'it' : 'security'

      void chat.raiseTicket(message.id, title, description, category)
    },
    [chat],
  )

  return (
    <div className="workspace">
      <SessionBar user={user} capabilities={chat.capabilities} onSignOut={() => onSignOut()} />

      <nav className="tabs" aria-label="Sections">
        <button
          type="button"
          className={`tabs__tab ${tab === 'chat' ? 'is-active' : ''}`}
          aria-current={tab === 'chat'}
          onClick={() => setTab('chat')}
        >
          Assistant
        </button>
        <button
          type="button"
          className={`tabs__tab ${tab === 'tickets' ? 'is-active' : ''}`}
          aria-current={tab === 'tickets'}
          onClick={() => setTab('tickets')}
        >
          Tickets
        </button>
        {canSeeDashboard && (
          <button
            type="button"
            className={`tabs__tab ${tab === 'dashboard' ? 'is-active' : ''}`}
            aria-current={tab === 'dashboard'}
            onClick={() => setTab('dashboard')}
          >
            Dashboard
          </button>
        )}
      </nav>

      {tab === 'chat' && (
        <div className="workspace__body">
          <ConversationSidebar
            conversations={chat.conversations}
            activeId={chat.activeId}
            busy={busy}
            onSelect={(id) => void chat.selectConversation(id)}
            onCreate={() => void chat.startConversation()}
            onDelete={(id) => void chat.removeConversation(id)}
          />

          <main className="panel">
            {chat.error && (
              <div className="alert alert--error" role="alert">
                <span>{chat.error}</span>
                <button type="button" className="alert__dismiss" onClick={chat.dismissError}>
                  Dismiss
                </button>
              </div>
            )}
            {chat.notice && !chat.error && (
              <p className="alert alert--info" role="status">
                {chat.notice}
              </p>
            )}

            <MessageThread
              messages={chat.messages}
              loading={chat.status === 'loading'}
              sending={chat.status === 'sending'}
              hasConversation={chat.activeId !== null}
              onRaiseTicket={raiseTicketFrom}
              raisingTicketId={chat.raisingTicketId}
              raisedTickets={chat.raisedTickets}
            />

            <Composer
              disabled={chat.status === 'loading'}
              sending={chat.status === 'sending'}
              maxLength={maxMessageLength}
              onSend={chat.send}
            />
          </main>
        </div>
      )}

      {tab === 'tickets' && (
        <main className="panel panel--wide">
          {tickets.error && (
            <div className="alert alert--error" role="alert">
              <span>{tickets.error}</span>
              <button type="button" className="alert__dismiss" onClick={tickets.dismissError}>
                Dismiss
              </button>
            </div>
          )}
          <TicketBoard
            listing={tickets.listing}
            active={tickets.active}
            loading={tickets.loading}
            busy={tickets.busy}
            statusFilter={tickets.statusFilter}
            onFilterChange={tickets.setStatusFilter}
            onOpen={(reference) => void tickets.open(reference)}
            onClose={tickets.close}
            onChangeStatus={(status, note) => void tickets.changeStatus(status, note)}
            onAddNote={(note) => void tickets.addNote(note)}
          />
        </main>
      )}

      {tab === 'dashboard' && canSeeDashboard && (
        <main className="panel panel--wide">
          {dashboard.error && (
            <div className="alert alert--error" role="alert">
              <span>{dashboard.error}</span>
              <button type="button" className="alert__dismiss" onClick={dashboard.dismissError}>
                Dismiss
              </button>
            </div>
          )}
          <Dashboard
            overview={dashboard.overview}
            audit={dashboard.audit}
            actions={dashboard.actions}
            days={dashboard.days}
            actionFilter={dashboard.actionFilter}
            loading={dashboard.loading}
            loadingMoreAudit={dashboard.loadingMoreAudit}
            onDaysChange={dashboard.setDays}
            onActionChange={dashboard.setActionFilter}
            onLoadMoreAudit={() => void dashboard.loadMoreAudit()}
          />
        </main>
      )}
    </div>
  )
}
