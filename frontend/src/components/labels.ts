import type { RiskLevel } from '../api/types'

/**
 * Display labels for the backend's classification vocabulary.
 *
 * Kept out of the component file so that file exports components only, which is
 * what React Fast Refresh requires to reload it without a full page refresh.
 */

const INTENT_LABELS: Record<string, string> = {
  security_faq: 'Security question',
  phishing: 'Phishing',
  security_incident: 'Security incident',
  it_support: 'IT support',
  policy_question: 'Policy question',
  out_of_scope: 'Outside scope',
}

const RISK_LABELS: Record<RiskLevel, string> = {
  low: 'Low risk',
  medium: 'Medium risk',
  high: 'High risk',
  critical: 'Critical risk',
}

export function intentLabel(intent: string | null): string {
  if (!intent) return 'Unclassified'
  return INTENT_LABELS[intent] ?? intent
}

export function riskLabel(level: RiskLevel | null): string {
  if (!level) return 'Not assessed'
  return RISK_LABELS[level] ?? level
}
