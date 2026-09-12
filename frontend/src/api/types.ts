/**
 * Shared API types.
 *
 * These mirror the backend Pydantic schemas. The backend remains the source of
 * truth: the frontend never decides authorization, it only renders what the
 * server returns.
 */

export type Role = 'employee' | 'it' | 'security'

export type Intent =
  | 'security_faq'
  | 'phishing'
  | 'security_incident'
  | 'it_support'
  | 'policy_question'
  | 'out_of_scope'

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical'

export interface ApiErrorBody {
  code: string
  message: string
  request_id?: string | null
  details?: Record<string, unknown> | null
}

export interface ErrorEnvelope {
  error: ApiErrorBody
}

export interface HealthResponse {
  status: string
  app_name: string
  version: string
  environment: string
  checks: Record<string, string>
}

/** Non-sensitive AI pipeline configuration reported by `GET /api/v1/meta`. */
export interface AiConfig {
  llm_provider: string
  llm_model: string
  llm_configured: boolean
  embedding_provider: string
  vector_store: string
  retrieval_top_k: number
}

export interface AppFeatures {
  demo_login: boolean
  demo_users_seeded: boolean
}

export interface MetaResponse {
  app_name: string
  version: string
  environment: string
  features: AppFeatures
  ai: AiConfig
  roles: Role[]
}

export interface UserPublic {
  id: number
  email: string
  full_name: string
  role: Role
  role_label: string
}

export interface TokenResponse {
  access_token: string
  token_type: string
  expires_in: number
  user: UserPublic
}

/* ------------------------------------------------------------------ chat -- */

export interface SourceDocument {
  document_id: string
  title: string
  category: string
  section: string
  score: number
  snippet: string
}

export interface RiskSignal {
  label: string
  level: RiskLevel
  evidence: string
}

export interface MessagePayload {
  /**
   * The answer text. Mirrors `MessageOut.content` on purpose, so the structured
   * payload is a complete record of the turn (PRODUCT_SPEC.md section 8).
   */
  answer: string
  recommended_actions: string[]
  source_documents: SourceDocument[]
  grounded: boolean
  provider: string
  model: string
  offline: boolean
  /** Intent classification (Phase 5). */
  intent: Intent | null
  intent_confidence: number
  intent_source: string
  /** Risk classification and the escalation decision (Phase 5). */
  risk_level: RiskLevel | null
  risk_signals: RiskSignal[]
  risk_reason: string
  human_escalation: boolean
  create_ticket: boolean
  peak_risk_level: RiskLevel | null
  /** Prompt-injection handling. */
  blocked: boolean
  block_reason: string | null
  block_categories: string[]
  context_injection_blocked: number
  /** Set when the workflow manager created or escalated a ticket for this turn. */
  ticket_reference: string | null
  ticket_status: string | null
}

/* --------------------------------------------------------------- tickets -- */

export type TicketStatus = 'open' | 'in_progress' | 'escalated' | 'resolved' | 'closed'
export type TicketSeverity = 'low' | 'medium' | 'high' | 'critical'

export interface TicketEvent {
  id: number
  created_at: string | null
  event_type: string
  from_status: string | null
  to_status: string | null
  from_severity: string | null
  to_severity: string | null
  actor_role: string | null
  automated: boolean
  note: string
}

export interface TicketSummary {
  reference: string
  title: string
  category: string
  severity: TicketSeverity
  status: TicketStatus
  source: string
  owner_role: Role
  escalation_required: boolean
  created_at: string | null
  updated_at: string | null
}

export interface TicketDetail extends TicketSummary {
  description: string
  related_query: string
  /** Whether the server would accept a status change from this caller. */
  can_update: boolean
  events: TicketEvent[]
}

export interface TicketStatistics {
  total: number
  open: number
  escalated: number
  requiring_human: number
  by_status: Record<string, number>
  by_severity: Record<string, number>
}

export interface TicketList {
  count: number
  statistics: TicketStatistics
  tickets: TicketSummary[]
}

/* ------------------------------------------------------------- dashboard -- */

export interface DashboardSummary {
  window_days: number
  window_start: string
  users: Record<string, number>
  conversations: Record<string, number>
  questions: Record<string, number>
  escalations: Record<string, number>
  tickets: Record<string, number>
  security_signals: Record<string, number>
}

export interface TimeseriesPoint {
  date: string
  questions: number
  escalations: number
  tickets: number
  denials: number
  logins: number
}

export interface DashboardDistributions {
  window_days: number
  risk_levels: Record<string, number>
  intents: Record<string, number>
  ticket_status: Record<string, number>
  ticket_severity: Record<string, number>
  ticket_owner_role: Record<string, number>
  ticket_source: Record<string, number>
  top_actions: { action: string; count: number }[]
}

export interface ResponseTimes {
  window_days: number
  escalated_tickets: number
  acknowledged: number
  still_unacknowledged: number
  median_seconds: number | null
  slowest_seconds: number | null
  fastest_seconds: number | null
}

export interface DocumentAccess {
  window_days: number
  most_viewed_documents: { document_id: string; count: number }[]
  most_refused_documents: { document_id: string; count: number }[]
  denials_by_role: Record<string, number>
}

export interface DashboardOverview {
  summary: DashboardSummary
  timeseries: { window_days: number; series: TimeseriesPoint[] }
  distributions: DashboardDistributions
  response_times: ResponseTimes
  document_access: DocumentAccess
  outcomes: Record<string, unknown>
}

export interface AuditEntry {
  id: number
  created_at: string | null
  action: string
  outcome: string
  actor_role: string | null
  resource_type: string | null
  resource_id: string | null
  request_id: string | null
  ip_address: string | null
  detail_keys: string[]
}

export interface AuditLogPage {
  total: number
  returned: number
  offset: number
  entries: AuditEntry[]
}

export interface ChatMessage {
  id: number
  conversation_id: number
  role: 'user' | 'assistant' | 'system'
  content: string
  payload: MessagePayload | null
  created_at: string | null
}

export interface ConversationSummary {
  id: number
  title: string
  message_count: number
  created_at: string | null
  updated_at: string | null
}

export interface ConversationDetail extends ConversationSummary {
  messages: ChatMessage[]
}

export interface ConversationList {
  count: number
  conversations: ConversationSummary[]
}

export interface PostMessageResult {
  conversation_id: number
  user_message: ChatMessage
  assistant_message: ChatMessage
}

export interface ChatCapabilities {
  role: Role
  role_label: string
  scope_description: string
  document_count: number
  provider: { provider: string; model: string; offline: boolean }
  knowledge_ready: boolean
  categories: Record<string, number>
}

export function isErrorEnvelope(value: unknown): value is ErrorEnvelope {
  if (typeof value !== 'object' || value === null) return false
  const candidate = (value as { error?: unknown }).error
  if (typeof candidate !== 'object' || candidate === null) return false
  const body = candidate as Partial<ApiErrorBody>
  return typeof body.code === 'string' && typeof body.message === 'string'
}
