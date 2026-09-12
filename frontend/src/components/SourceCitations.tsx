import type { SourceDocument } from '../api/types'

export interface SourceCitationsProps {
  sources: SourceDocument[]
}

/**
 * The documents behind an answer.
 *
 * Rendering these is a product requirement: every answer must show where it came
 * from. The list is already the server's authorised set, so the UI does not
 * filter it - and it must not pretend to.
 */
export function SourceCitations({ sources }: SourceCitationsProps) {
  if (sources.length === 0) return null

  return (
    <section className="sources" aria-label="Sources">
      <h3 className="sources__title">
        Sources <span className="sources__count">({sources.length})</span>
      </h3>
      <ul className="sources__list">
        {sources.map((source) => (
          <li key={`${source.document_id}-${source.section}-${source.score}`} className="source">
            <details className="source__details">
              <summary className="source__summary">
                <span className="source__id">{source.document_id}</span>
                <span className="source__title">{source.title}</span>
                <span className="source__meta">
                  {source.category} &middot; {Math.round(source.score * 100)}% match
                </span>
              </summary>
              {source.section && <p className="source__section">{source.section}</p>}
              <blockquote className="source__snippet">{source.snippet}</blockquote>
            </details>
          </li>
        ))}
      </ul>
    </section>
  )
}
