import { useEffect, useState } from 'react'

import { ApiError, api } from './api/client'
import type { MetaResponse } from './api/types'
import { ChatWorkspace } from './components/ChatWorkspace'
import { LoginPanel } from './components/LoginPanel'
import { config } from './config'
import { useSession } from './hooks/useSession'

/**
 * Application shell.
 *
 * Two states only: signed out (login) and signed in (chat workspace). The
 * capability check that used to live here is kept as a small footer so an
 * operator can still see whether the backend is reachable and which providers
 * are configured - none of that is secret.
 */
export function App() {
  const session = useSession()
  const [meta, setMeta] = useState<MetaResponse | null>(null)
  const [backendError, setBackendError] = useState<string | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    api
      .meta({ signal: controller.signal })
      .then(setMeta)
      .catch((cause: unknown) => {
        if (controller.signal.aborted) return
        setBackendError(
          cause instanceof ApiError ? cause.message : 'The backend is not reachable.',
        )
      })
    return () => controller.abort()
  }, [])

  const demoLoginEnabled = meta?.features.demo_login ?? true

  return (
    <div className="app">
      {session.session === null ? (
        <LoginPanel
          busy={session.busy}
          error={session.error ?? backendError}
          demoLoginEnabled={demoLoginEnabled}
          onSignIn={session.signIn}
        />
      ) : (
        <ChatWorkspace user={session.session.user} onSignOut={session.signOut} />
      )}

      <footer className="app__footer">
        <span>{config.appTitle}</span>
        <span className="app__footer-meta">
          {meta
            ? `${meta.environment} · ${meta.app_name} v${meta.version}`
            : backendError
              ? 'backend unreachable'
              : 'connecting…'}
        </span>
      </footer>
    </div>
  )
}
