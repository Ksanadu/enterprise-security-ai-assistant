import { useEffect, useRef, useState, type FormEvent, type KeyboardEvent } from 'react'

export interface ComposerProps {
  disabled: boolean
  sending: boolean
  maxLength: number
  onSend: (content: string) => Promise<void>
}

export function Composer({ disabled, sending, maxLength, onSend }: ComposerProps) {
  const [value, setValue] = useState('')
  const textareaRef = useRef<HTMLTextAreaElement>(null)

  useEffect(() => {
    if (!sending) textareaRef.current?.focus()
  }, [sending])

  async function submit(event?: FormEvent<HTMLFormElement>) {
    event?.preventDefault()
    const content = value.trim()
    if (!content || disabled || sending) return
    setValue('')
    await onSend(content)
  }

  function onKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    // Enter sends; Shift+Enter inserts a newline.
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault()
      void submit()
    }
  }

  const remaining = maxLength - value.length

  return (
    <form className="composer" onSubmit={submit}>
      <label className="composer__label" htmlFor="composer-input">
        Ask a security question
      </label>
      <textarea
        id="composer-input"
        ref={textareaRef}
        className="composer__input"
        rows={2}
        value={value}
        maxLength={maxLength}
        disabled={disabled}
        placeholder="For example: I received an email asking me to log in again — is that normal?"
        onChange={(event) => setValue(event.target.value)}
        onKeyDown={onKeyDown}
      />
      <div className="composer__footer">
        <span className={`composer__counter ${remaining < 100 ? 'composer__counter--low' : ''}`}>
          {remaining} characters left
        </span>
        <button
          className="button button--primary"
          type="submit"
          disabled={disabled || sending || value.trim().length === 0}
        >
          {sending ? 'Thinking…' : 'Send'}
        </button>
      </div>
    </form>
  )
}
