import type { ChatCapabilities, ConversationSummary, UserPublic } from '../api/types'

export interface ConversationSidebarProps {
  conversations: ConversationSummary[]
  activeId: number | null
  busy: boolean
  onSelect: (id: number) => void
  onCreate: () => void
  onDelete: (id: number) => void
}

export function ConversationSidebar({
  conversations,
  activeId,
  busy,
  onSelect,
  onCreate,
  onDelete,
}: ConversationSidebarProps) {
  return (
    <aside className="sidebar" aria-label="Conversations">
      <button
        type="button"
        className="button button--primary sidebar__new"
        onClick={onCreate}
        disabled={busy}
      >
        New conversation
      </button>

      {conversations.length === 0 ? (
        <p className="sidebar__empty">No conversations yet.</p>
      ) : (
        <ul className="sidebar__list">
          {conversations.map((conversation) => (
            <li key={conversation.id} className="sidebar__item">
              <button
                type="button"
                className={`sidebar__link ${conversation.id === activeId ? 'is-active' : ''}`}
                onClick={() => onSelect(conversation.id)}
                aria-current={conversation.id === activeId}
              >
                <span className="sidebar__title">{conversation.title}</span>
                <span className="sidebar__meta">{conversation.message_count} messages</span>
              </button>
              <button
                type="button"
                className="sidebar__delete"
                aria-label={`Delete conversation: ${conversation.title}`}
                onClick={() => onDelete(conversation.id)}
              >
                &times;
              </button>
            </li>
          ))}
        </ul>
      )}
    </aside>
  )
}

export interface SessionBarProps {
  user: UserPublic
  capabilities: ChatCapabilities | null
  onSignOut: () => void
}

export function SessionBar({ user, capabilities, onSignOut }: SessionBarProps) {
  return (
    <header className="session">
      <div className="session__identity">
        <span className={`role-badge role-badge--${user.role}`}>{user.role_label || user.role}</span>
        <span className="session__name">{user.full_name}</span>
      </div>

      {capabilities && (
        <p className="session__scope">
          <strong>{capabilities.document_count}</strong> knowledge documents available to your
          role. {capabilities.scope_description}
        </p>
      )}

      <button type="button" className="button button--ghost" onClick={onSignOut}>
        Sign out
      </button>
    </header>
  )
}
