import { useState, type FormEvent } from 'react'

import { config } from '../config'

export interface LoginPanelProps {
  busy: boolean
  error: string | null
  demoLoginEnabled: boolean
  onSignIn: (email: string, password: string) => Promise<boolean>
}

/** Demo accounts. These are fictional and exist only for the demonstration. */
const DEMO_ACCOUNTS = [
  { email: 'employee@example.com', label: 'Employee', detail: 'Security FAQ and employee policies' },
  { email: 'it@example.com', label: 'IT Support', detail: 'Adds VPN and endpoint procedures' },
  { email: 'security@example.com', label: 'Security Team', detail: 'All security knowledge' },
]

const DEMO_PASSWORD = 'Demo@12345'

export function LoginPanel({ busy, error, demoLoginEnabled, onSignIn }: LoginPanelProps) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    await onSignIn(email, password)
  }

  async function signInAs(demoEmail: string) {
    setEmail(demoEmail)
    setPassword(DEMO_PASSWORD)
    await onSignIn(demoEmail, DEMO_PASSWORD)
  }

  return (
    <main className="login">
      <div className="login__card">
        <h1 className="login__title">{config.appTitle}</h1>
        <p className="login__subtitle">
          Ask security questions and get answers grounded in the internal knowledge base. Every
          answer cites the documents it used, and you only ever see documents your role may read.
        </p>
        <p className="login__disclaimer">
          Simulated data only &mdash; no real enterprise data is used anywhere in this system.
        </p>

        <form className="login__form" onSubmit={submit} noValidate>
          <label className="field">
            <span className="field__label">Work email</span>
            <input
              className="field__input"
              type="email"
              name="email"
              autoComplete="username"
              required
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="you@example.com"
            />
          </label>

          <label className="field">
            <span className="field__label">Password</span>
            <input
              className="field__input"
              type="password"
              name="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="••••••••"
            />
          </label>

          {error && (
            <p className="alert alert--error" role="alert">
              {error}
            </p>
          )}

          <button className="button button--primary" type="submit" disabled={busy}>
            {busy ? 'Signing in…' : 'Sign in'}
          </button>
        </form>

        {demoLoginEnabled && (
          <section className="login__demo" aria-label="Demo accounts">
            <h2 className="login__demo-title">Demo accounts</h2>
            <p className="login__demo-hint">
              These fictional accounts hold different knowledge permissions. Sign in as each one
              and ask the same question to see the answers change.
            </p>
            <ul className="demo-list">
              {DEMO_ACCOUNTS.map((account) => (
                <li key={account.email}>
                  <button
                    type="button"
                    className="demo-list__item"
                    aria-label={`Sign in as ${account.label}`}
                    disabled={busy}
                    onClick={() => void signInAs(account.email)}
                  >
                    <span className="demo-list__label">{account.label}</span>
                    <span className="demo-list__email">{account.email}</span>
                    <span className="demo-list__detail">{account.detail}</span>
                  </button>
                </li>
              ))}
            </ul>
          </section>
        )}
      </div>
    </main>
  )
}
