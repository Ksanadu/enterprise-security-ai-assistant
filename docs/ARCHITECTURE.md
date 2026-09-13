# Architecture

How the Enterprise Security AI Assistant is put together, and why.

This document explains the decisions that are not obvious from the code. For how to run it, see
the [README](../README.md); for the demonstration, see [DEMO.md](DEMO.md).

**Everything in this system is simulated.** The knowledge base, the users, the tickets and the
audit trail are fictional. No real enterprise data is used anywhere.

---

## 1. The whole picture

```
                          ┌───────────────────────────────────────────┐
   browser  ────────────► │  frontend   (React + TypeScript, Vite)    │
   :8080 / :5173          │    api/client.ts   typed fetch + envelope │
                          │    hooks/          session, chat, tickets │
                          │    components/     login, workspace, ...  │
                          └───────────────────┬───────────────────────┘
                                              │  HTTPS, one origin
                                              │  Authorization: Bearer <JWT>
                          ┌───────────────────▼───────────────────────┐
                          │  nginx   (production only)                │
                          │    /          dist/ + SPA fallback        │
                          │    /api/      proxy_pass backend:8000     │
                          └───────────────────┬───────────────────────┘
                                              │
   ┌──────────────────────────────────────────▼──────────────────────────────────────┐
   │  FastAPI                                                                        │
   │                                                                                 │
   │  middleware      correlation id · security headers · Cache-Control: no-store    │
   │  deps            settings · db session · current user · client address          │
   │  routes/auth     login, me, logout, sessions                                    │
   │  routes/knowledge documents, search, scope, stats, reindex                      │
   │  routes/chat     conversations, messages                                        │
   │  routes/tickets  queue, detail, status, notes                                   │
   │  routes/dashboard summary, timeseries, distributions, audit                     │
   │                                                                                 │
   │  ┌─────────────────────────── services ──────────────────────────────────────┐  │
   │  │  auth_service      credentials, users, sessions                          │  │
   │  │  knowledge_service documents, search, index lifecycle                    │  │
   │  │  chat_service      THE PIPELINE (see §3)                                 │  │
   │  │  ticket_service    queue, transitions, timeline, visibility rules        │  │
   │  │  workflow_manager  escalation and ticket decisions (backend-owned)       │  │
   │  │  dashboard_service aggregate counts; identifiers only, never content     │  │
   │  └──────────────────────────────────────────────────────────────────────────┘  │
   │                                                                                 │
   │  ┌──── security ────┐  ┌──── rag ────────┐  ┌──── ai ──────────────────────┐    │
   │  │ rbac              │  │ loader          │  │ prompt_guard                 │    │
   │  │ audit             │  │ chunking        │  │ intent_classifier            │    │
   │  │ sessions          │  │ embeddings      │  │ risk_classifier              │    │
   │  │ rate_limit        │  │ vector_store    │  │ response_generator           │    │
   │  │ login_guard       │  │ index           │  │ llm (mock | openai_compat)   │    │
   │  │ client_address    │  │ retriever       │  │ structured, turn_analysis    │    │
   │  │ redaction         │  │                 │  │                              │    │
   │  └───────────────────┘  └─────────────────┘  └──────────────────────────────┘    │
   │                                                                                 │
   │  SQLite (SQLAlchemy 2.0)              FAISS IndexFlatIP + fitted BM25 TF-IDF    │
   │  users, conversations, messages,      knowledge_base/*.md  (12 documents,       │
   │  tickets, ticket_events,              83 chunks, ~1000-term vocabulary)         │
   │  audit_logs, user_sessions                                                      │
   └─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Where the specification's six AI components live

PRODUCT_SPEC.md requires the AI logic to be split rather than written as one prompt. One module
per responsibility, each independently testable and each with its own test file:

| Spec component | Module | Responsibility | Decided by |
| -------------- | ------ | -------------- | ---------- |
| Intent Classifier | `app/ai/intent_classifier.py` | 49 rules over 6 intents, optional model refinement | rules (+ model to raise confidence) |
| Permission Checker | `app/security/rbac.py` | which documents a role may read; which tickets a user may see | **backend code only** |
| Retriever | `app/rag/retriever.py` | scored, permission-filtered, deduplicated context | backend code |
| Response Generator | `app/ai/response_generator.py` | grounded answer, recommended actions, citations | model, constrained by retrieved context |
| Risk Classifier | `app/ai/risk_classifier.py` | 39 rules mapping signals to a risk level | rules (+ model may **raise**, never lower) |
| Workflow Manager | `app/services/workflow_manager.py` | escalate? create ticket? notify whom? | **backend code only** |

The prompt guard (`app/ai/prompt_guard.py`) runs before any of them and can refuse the turn outright.

Every assistant message carries a structured payload alongside its prose. PRODUCT_SPEC.md §8 fixes
the fields, and `tests/test_documentation.py` asserts the contract against a real response rather
than against the schema alone:

```jsonc
{
  "answer": "...",                 // mirrors MessageOut.content
  "intent": "phishing",
  "risk_level": "high",
  "recommended_actions": ["..."],
  "source_documents": [ { "document_id": "KB-002", "title": "...", "score": 0.19 } ],
  "human_escalation": true,
  "create_ticket": true
  // plus: grounded, risk_signals, risk_reason, peak_risk_level, blocked,
  //       ticket_reference, ticket_status, provider, model, offline,
  //       intent_confidence, intent_source, context_injection_blocked
}
```

`answer` repeats the message body on purpose: the payload is then a complete, self-describing record
of the turn, which is what an integration consuming the structured output needs. It was **absent**
until a Phase 10 review read §8 against the schema - the answer existed only on `MessageOut.content`,
so the documented contract was not actually met.

---

## 3. The request pipeline

PRODUCT_SPEC.md §4 defines the order. This is what actually happens for one chat message, in
`app/services/chat_service.py`:

```
    question
       │
   1   ▼  prompt guard                       app/ai/prompt_guard.py
       │    injection / jailbreak / exfiltration attempt -> refuse, audit, stop.
       │    No model is called, no retrieval happens, no ticket is raised.
       │
   2   ▼  intent classification              app/ai/intent_classifier.py
       │    rule score over the question expanded with recent context,
       │    optionally refined by the model. Never authoritative for access.
       │
   3   ▼  permission check                   app/security/rbac.py
       │    role -> authorized_document_ids(). Computed from the caller's
       │    server-side session record, never from the request body.
       │
   4   ▼  retrieval                          app/rag/retriever.py
       │    VectorStore.search(vector, top_k, allowed_document_ids=<the list
       │    from step 3>)  <- authorization is an argument, not a post-filter
       │
   5   ▼  response generation                app/ai/response_generator.py
       │    only the authorized chunks reach the prompt. Out-of-scope questions
       │    skip retrieval entirely and get an honest "no approved document".
       │
   6   ▼  risk classification                app/ai/risk_classifier.py
       │    signals -> level. The model may raise the level, never lower it.
       │
   7   ▼  workflow decision                  app/services/workflow_manager.py
       │    escalation and ticket creation are decided here, in Python.
       │
       └─►  response + audit rows + ticket (if any)
```

Two properties are worth stating explicitly, because they are the reason the pipeline is shaped
this way:

* **The model never decides access.** It sees only what step 3 already permitted. There is no code
  path in which a model output widens a role's reach.
* **The model never decides escalation.** It can contribute a risk signal; the decision to escalate
  or file a ticket is made by `WorkflowManager` from the classified risk level.

---

## 4. Authorization is an argument, not a filter

This is the single most important design decision in the project.

The obvious implementation of RAG with permissions is: search the whole index, then drop the
results the user may not see. That works, and it is also how restricted content ends up in a
prompt, a log line or a cache after one careless refactor.

Instead, the authorization set is **required** by the search itself
(`app/rag/vector_store.py`):

```python
def search(
    self,
    query_vector: np.ndarray,
    *,
    top_k: int,
    allowed_document_ids: Collection[str],   # no default, no "search everything"
) -> list[VectorMatch]: ...
```

`allowed_document_ids` is keyword-only with no default, so a caller that forgets it gets a
`TypeError` rather than an unrestricted search. With FAISS, the allow-list becomes an
`IDSelectorBatch` before scoring, so filtered-out vectors are never compared at all.

Defence in depth: `Retriever` re-checks every match against the role's authorized set before
returning it, and `KnowledgeService.document_for()` resolves a single document by scanning only the
role's own document list. Three independent places would all have to fail.

Where the allow-list comes from:

```
JWT (sub, jti)  ->  user_sessions row  ->  users.role  ->  authorized_document_ids(role)
         │                                                              │
    informational only: the role claim in the token is never trusted
    for access. The session row is the authority, which is what makes
    logout and logout-all take effect immediately.
```

`backend/knowledge_base/README.md` documents the metadata contract every document must satisfy.
`allowed_roles` is validated strictly at load: a misspelled or missing key fails startup when
`KB_STRICT_VALIDATION=true`, because a silently skipped document silently changes what the assistant
is allowed to answer.

---

## 5. Retrieval without an embedding API

The default embedder (`app/rag/embeddings.py`) is a **BM25-weighted TF-IDF** model over
Snowball-stemmed tokens, fitted on the knowledge base and persisted with the index. Provider name
`tfidf`. Setting `EMBEDDING_PROVIDER=openai_compatible` swaps in real semantic embeddings without
touching anything else.

Why a lexical model is an acceptable default here:

* it needs no API key and no network, so the demo, the tests and the evaluation set are
  deterministic and run offline;
* the knowledge base is small (12 documents, 83 chunks) and its vocabulary is stable;
* the evaluation set measures the outcome, so the trade-off is visible rather than assumed
  (top-1 accuracy 11/12 on the specification's demo scenarios, expected document recalled 29/29 on
  the graded evaluation questions).

Why it is a **quality** choice and not a **security** choice: retrieval authorization is enforced
independently of the embedding provider. Changing the embedder cannot change who may read what,
because the allow-list is applied before any scoring happens.

Two thresholds do the precision work in `app/rag/retriever.py`:

* an absolute cosine floor (`RETRIEVAL_MIN_SCORE=0.05`) that rejects obviously unrelated chunks;
* a **relative** floor (`RETRIEVAL_RELATIVE_FLOOR=0.5`) that drops matches scoring below half the
  best match. This was tuned against the evaluation set: 0.7 recalled the expected document for 86%
  of questions, 0.5 recalls 97%, and an irrelevant question still returns nothing either way.

Chunking (`app/rag/chunking.py`) splits on document structure, with a 700-character budget and 100
characters of overlap so a sentence spanning a boundary is still retrievable.

The index fingerprint (`app/rag/index.py`) covers the documents **and** a configuration fingerprint
that includes `TOKENIZER_VERSION`. That last part exists because a stale cache surviving a
tokenizer change once produced results nobody could reproduce.

---

## 6. Data model

`app/db/models.py`. Seven tables, SQLite via SQLAlchemy 2.0.

| Table | Holds | Notes |
| ----- | ----- | ----- |
| `users` | account, bcrypt password hash, role, active flag | 4 fictional accounts, one per role plus a second employee |
| `user_sessions` | one row per issued token, keyed by the JWT `jti` | This is what makes revocation immediate. Rows are kept after expiry as evidence (`AUTH_SESSION_RETENTION_DAYS`). |
| `conversations` | per-user thread, **`peak_risk_level`** | The peak is sticky: a conversation that reached High stays High, so a later innocuous message cannot quietly downgrade an incident. |
| `messages` | content, role, and the assessment | `intent`, `risk_level` and `escalated` are denormalised onto the row (indexed as `ix_messages_intent_risk`) so the dashboard aggregates without parsing JSON. |
| `tickets` | reference, severity, status, `owner_role`, `escalation_required`, creator | The reference prefix names the owning queue: `SEC-` for security, `IT-` for employee-raised. |
| `ticket_events` | append-only timeline | Every transition, with actor role and whether it was automated. There is no update or delete path. |
| `audit_logs` | append-only audit trail | Actor, role, outcome, resource, correlation id, client address, and `detail` holding **counts and identifiers only** - never document text or credentials. |

Deliberate choices:

* **Append-only.** The audit log and ticket timeline have no update or delete code path. An audit
  trail that can be edited is not an audit trail.
* **No soft deletes.** Conversations are hard-deleted on request; the audit rows that reference
  them survive.
* **One incident, one ticket.** A conversation that escalates again reuses its existing ticket
  rather than creating duplicates, so the queue reflects incidents rather than messages.
* **Schema drift in development only.** `app/db/session.py` detects missing columns and rebuilds the
  affected table when `APP_ENV=development`, and raises otherwise. There is no migration tool; that
  is recorded as a known limitation rather than hidden.

---

## 7. Security model

Threat by threat, with where the control lives.

### Prompt injection

| | |
| --- | --- |
| Control | `app/ai/prompt_guard.py`, applied twice: `scan_query` on the user's message **before** any retrieval or model call, and `scan_context` on retrieved text before it reaches the prompt. |
| Why twice | A knowledge-base document is data, not instructions. If one were ever edited to contain an injected instruction, the second scan stops it. |
| Test | `tests/test_prompt_guard.py`, plus 5 injection questions in the evaluation set asserted as `blocked` for every role. |

A blocked turn is terminal: no retrieval, no model call, no ticket, and an audit row recording the
categories that matched.

### Broken access control

| | |
| --- | --- |
| Control | `app/security/rbac.py` + the required `allowed_document_ids` argument in `VectorStore.search`. |
| Identity | From the `user_sessions` row for the token's `jti`, not from the token's claims. |
| Enumeration | A restricted document returns **404, not 403**, so the endpoint cannot be used to discover which restricted documents exist. Same for another user's ticket. |
| Metadata, not just content | The refusal has to hold for *metadata* too, or the 404 is pointless. A Phase 4 re-verification found two leaks of exactly that kind: `/knowledge/scope` listed every role's document ids (naming the security team's playbooks to an employee), and `/knowledge/stats` returned the knowledge base's absolute path. Both are fixed, and a sweep of every route as an employee now finds no endpoint disclosing a restricted identifier, title or path. |

### Injection is not the only way to reach the model

`app/ai/prompt_guard.py` is heuristic, so it will eventually miss a novel attempt. The design does
not depend on it: retrieval authorization happens *before* the model is involved, so a successful
injection has nothing restricted to extract. `tests/test_rbac_adversarial.py` makes this concrete by
running the pipeline with a deliberately hostile model that claims administrator rights, fabricates
citations for restricted documents and names them in its answer. The caller's reach is unchanged and
the fabricated citations are discarded, because the citation list is built from the retrieval result
rather than from anything the model returned.

### Sensitive information leakage

| | |
| --- | --- |
| Control | Error envelopes never echo submitted values; `app/security/redaction.py` masks credential-shaped strings before they are **persisted anywhere**; `app/core/logging.py` installs a redaction filter over stdout. |
| Order matters | Redaction runs at the storage boundary, after the pipeline. Classification, retrieval and risk assessment all use the raw text - the wording *is* the signal - so masking never costs the incident, only the secret. The ticket body, the message row and the conversation title are all masked; the ticket was the only one covered originally, which a security review at Phase 10 caught. |
| Dashboard | `dashboard_service` returns counts and identifiers. Audit entries expose `detail_keys` (which fields are present) rather than `detail` values. |
| Frontend | The access token is memory-only: never `localStorage`, never `sessionStorage`. |

### Hardcoded secrets

| | |
| --- | --- |
| Control | Configuration is environment-only (`app/core/config.py`). `.env` is git-ignored and `scripts/check-no-secrets.ps1` fails if a sensitive path becomes stageable. |
| Startup refusal | With `APP_ENV=production`, a placeholder signing key, demo login, demo seeding or the default demo password are **startup failures**, not warnings. |
| Containers | Secrets are absent from `docker-compose.yml` by design and excluded by both `.dockerignore` files. |

### Unauthorized document retrieval

| | |
| --- | --- |
| Control | The same allow-list described in §4, applied before scoring. |
| Invariant | Asserted for all 40 evaluation questions and every role: **zero** restricted documents returned. |
| Regression | `tests/test_authorization_matrix.py` walks the full role × document matrix. |

### Unsafe tool calling

| | |
| --- | --- |
| Position | This implementation has **no tool-calling surface**. The model is used for two things only: producing answer text from retrieved context, and (optionally) refining a classification. It cannot invoke functions, run code, reach the network or write to the database. |
| Consequence | The class of risk does not exist here. That is a deliberate scope decision, not an oversight: adding tools would require a separate authorization design for each tool, which this prototype does not need. |
| Structured output | Even so, every model response is parsed defensively (`app/ai/structured.py`): the JSON object is extracted, validated against a pydantic model, and confidence is clamped to `[0, 1]` with a fallback to the rule-based result when parsing fails. A depth limit rejects pathological nesting before the recursive decoder sees it - `RecursionError` is a `RuntimeError`, not a `JSONDecodeError`, and would otherwise escape every handler on that path. |

### Abuse of the sign-in endpoint

| | |
| --- | --- |
| Control | `app/security/login_guard.py`: per-account and per-address sliding windows, checked **before** the credential comparison, so a correct password during a lockout is still refused. |
| Client address | `app/security/client_address.py`. Behind a proxy the socket peer is the proxy, which would collapse the per-address limit into one shared bucket. `TRUSTED_PROXY_COUNT` states how many proxies are real, and the address is read from the **right** of `X-Forwarded-For`, where a client cannot write. |
| Enumeration | Unknown account and wrong password return one identical message with comparable timing. |

---

## 8. Design decisions worth knowing

| Decision | Why | Trade-off accepted |
| -------- | --- | --- |
| Authorization pushed into the vector search | A post-filter is one refactor away from leaking | Every caller must pass the allow-list; the type system enforces it |
| Rules for intent and risk, model optional | Deterministic, explainable, testable offline; a classifier that changes between runs cannot be regression-tested | Keyword-driven rules can miss unusual phrasing. Mitigated by the evaluation set, which surfaced nine such misses |
| Backend decides escalation | A model that can decide to file - or not file - a security ticket is not auditable | Less flexible than letting the model judge |
| Peak risk is sticky per conversation | A later calm message must not downgrade a live incident | A genuinely resolved conversation stays High in the aggregate |
| Out-of-scope questions never retrieve | Answering from an unrelated document with a citation is worse than saying "I do not know" | Bare follow-ups need conversation context to classify correctly (fixed by classifying with the same expanded text retrieval uses) |
| One incident, one ticket | The queue should reflect incidents, not messages | A long conversation produces one ticket even with several signals |
| `closed` is terminal | Reopening would make the timeline ambiguous | A genuinely new event needs a new ticket |
| Offline extractive generator by default | Reproducible, no API key, no network; the demo and the evaluation set must not depend on a third party | Answers read as selected sentences, not composed prose. `LLM_PROVIDER=openai_compatible` replaces it |
| Rate limiting in-process | Correct for the single-worker deployment, and honest about its limits | Multiple workers or replicas would need a shared store. Recorded as a limitation, not pretended away |
| 404 rather than 403 for hidden resources | A 403 confirms the resource exists | Slightly less helpful error messages |

---

## 9. Testing strategy

Three layers, all runnable offline. See the [README](../README.md#testing) for the counts.

1. **Unit and integration** - every module, with an isolated SQLite file per test and no shared
   state (`tests/conftest.py`).
2. **Security** (`pytest -m security`) - RBAC, injection, leakage, session lifecycle, ticket
   scoping, redaction, client-address spoofing and deployment hardening. Roughly two thirds of the
   suite carries this marker.
3. **Evaluation** (`pytest -m evaluation`) - the 40-question set in
   `tests/data/evaluation_questions.json`, driven through the **chat API** so the whole pipeline is
   under test rather than the units. Safety properties (escalation, ticket creation, injection
   blocking) must be **perfect** and are asserted per question; quality properties have thresholds
   (intent 90%, risk 90%, retrieval 85%) and print the exact misses.

The evaluation set is the project's most valuable test asset, and it earned its keep during
development: it caught a harness bug (a shared conversation let sticky escalation contaminate later
questions), a policy contradiction (a phishing report with no interaction was rated Medium when
KB-009 says S4/Low), four classifier misses, an out-of-scope question answered from an unrelated
document, and a retrieval threshold that was cutting correctly-ranked results.

`tests/test_end_to_end_demo.py` walks the specification's mandatory demonstration through HTTP, and
`tests/test_demo_script.py` runs `scripts/demo.py` itself, so the demo documentation cannot drift
away from the product.

---

## 10. Deployment

Two multi-stage images, both running unprivileged, plus a named volume for state. `nginx` serves the
built SPA and reverse-proxies `/api`, so **the production request path has no CORS at all**.

Docker was not available in the environment this was developed in, so `docker compose up` was not
executed here. Instead the deployment is verified by 83 tests in
`tests/test_deployment_assets.py` that cross-check the files against each other and against the
application's own settings model - the nginx `proxy_pass` target must equal the compose service
name, `KB_DIR` must equal a real `COPY` destination, the volume must cover both the database and the
index, the database URL must be absolute inside the container, and the CSP directives in
`nginx.conf` must match the ones injected into the built HTML.

See the [README](../README.md#deployment) for the full deployment section, including the production
checklist and the equivalent no-Docker path.
