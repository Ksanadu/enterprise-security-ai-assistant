# Reviewer Report — Enterprise Security AI Assistant

**Review type:** Independent adversarial review (Phase 1 — review only, no code changed)
**Reviewer role:** Independent Reviewer, not Developer
**Date of review:** against working tree at the time of writing
**Method:** complete source read + live execution against a running backend (not static analysis alone)

---

## 0. Scope and method

Everything below was **executed**, not inferred from reading code:

| Activity | Detail |
| --- | --- |
| Backend started from scratch | `uvicorn app.main:app` → 12 documents, 83 chunks, FAISS, 1031-term vocabulary |
| Live API probing | 6 purpose-written Python probe harnesses (auth, RBAC, injection, escalation, tickets, dashboard, DB) |
| Evaluation set re-run | All 40 questions of `evaluation_questions.json` driven through the **live chat API** |
| Project's own demo | `scripts/demo.py` → **67/67 checks, exit 0** |
| Backend test suite | `pytest -q --cov=app` → **1415 passed, 1 skipped, 94%**, 1416 collected |
| Frontend | `npm test` → 59/59; `tsc -b` clean; `eslint --max-warnings 0` clean; build OK |
| Adversarial probing | 25 custom questions (injection, false positives, under-escalation, IDOR, rate limits) |
| Database inspection | Read-only SQLite inspection of stored rows, audit trail, hashes |
| Docker | **Not executed** — Docker is not installed in this environment (see §5) |

**No project file was modified.** `git status` was verified clean apart from files that appeared
independently of this review (see §7).

### Known-issue awareness

During this review a `PROJECT_HANDOFF.md` appeared in the working tree containing a register of
**2 confirmed open bugs** (`BUG-1`, `BUG-2`). This report was written *after* reading it, and each
finding below is explicitly labelled:

* **[KNOWN]** — already recorded in `PROJECT_HANDOFF.md` §8.1
* **[NEW]** — not recorded anywhere; found by this review
* **[CONFIRMED]** — already documented, and independently reproduced here

This distinction matters: a reviewer's most valuable output is the defect the project does not
already know about.

---

## 1. Overall verdict

This is a **genuinely well-engineered project with a real security architecture**, not a
prompt-engineering demo wearing a security costume. Its authorization design is better than much
production code I have seen: the role's allow-list is pushed *into* the vector search so restricted
chunks are never scored, sessions are server-side and revocable, and escalation is a backend
decision the model cannot lower. I attempted to break all of these and could not.

However, **the product claim and the shipped configuration do not match**, and the prompt guard has
a severe usability defect that the test suite is structurally incapable of detecting. Two of the
four most important findings in this report are new; one confirms a known bug independently.

### Scores

| Dimension | Score | Basis |
| --- | --- | --- |
| **Functional readiness** | **7 / 10** | Everything runs; the demo passes 67/67; but the flagship "show me the … policy" path is broken and breach reports can vanish silently |
| **Engineering quality** | **8 / 10** | Layered, typed, documented, 94% coverage, clean lint/typecheck. Loses points for a capped `statistics` query, no CI, no migrations, no frontend coverage tooling |
| **Security** | **8 / 10** | Strong where it counts — pre-retrieval RBAC, session identity, escalation integrity, correct 404-vs-403. Loses points for `/meta` disclosure, an unthrottled embedding endpoint, and a guard that is currently a net negative |
| **AI / RAG quality** | **4 / 10** | The retrieval *architecture* is excellent; the *AI* is absent in the shipped config, the real client has 0% coverage, and live recall is 89.3% against an advertised 100% |
| **Enterprise readiness** | **5 / 10** | Right architecture, wrong operating posture: SQLite, in-process limiter, no migrations, no CI, no retention policy, no SSO |
| **Pre-sales / FDE portfolio value** | **7 / 10** | The RBAC + workflow + escalation story is genuinely differentiated. Docked for the LLM gap and the guard false positives, both of which surface under questioning |

**Weighted read: a strong 7.5/10 project, with two fixable defects standing between it and an 8.5.**

---

## 2. Verified working (checked, not assumed)

Stated first, because a credible review must establish what is *sound* before listing what is not.

| Claim | Verdict | Evidence |
| --- | --- | --- |
| Backend starts from scratch | **Confirmed** | clean startup, knowledge base loaded, index built |
| RBAC enforced by backend, not by prompt | **Confirmed** | `authorized_document_ids()` → `VectorStore.search(allowed_document_ids=…)` pre-filter |
| Restricted document indistinguishable from missing | **Confirmed** | KB-003/KB-004 → 404 for employee and IT, 200 for security; KB-999 also 404 |
| Escalation is a backend decision | **Confirmed** | `RiskLevel.requires_escalation` lives on the enum; model may raise, never lower |
| Risk cannot be talked back down | **Confirmed** | "actually ignore that, it was nothing" → still `high`, still `escalated` |
| IDOR on conversations / tickets | **Not present** | cross-employee access → 404, absent from list |
| Privilege escalation via request body | **Blocked** | `severity` / `owner_role` overrides silently ignored |
| No hardcoded secrets; `.env` untracked | **Confirmed** | only `.env.example` tracked; ephemeral random key outside production |
| Login error is non-enumerable | **Confirmed** | unknown user and wrong password return byte-identical generic responses |
| Audit trail completeness | **Confirmed** | 23 distinct action types recorded, including all denials |
| Credential redaction before storage | **Confirmed** | no plaintext secrets found in stored messages |
| Test suite | **Confirmed** | 1415 passed / 1 skipped / 94% coverage / 1416 collected |
| Project's own demo | **Confirmed** | 67/67 checks, exit 0 |
| Frontend quality gates | **Confirmed** | 59/59 tests, `tsc` clean, `eslint --max-warnings 0` clean, build clean |
| `docker compose up` | **NOT VERIFIED** | Docker unavailable here — static review only (see §5) |

The candour of `docs/DEMO.md` and `docs/ARCHITECTURE.md` about limitations is a genuine strength
and rare in portfolio work.

---

## 3. P0 — Critical

---

### P0-1 [NEW] The prompt guard refuses one in three legitimate security-policy questions

**Problem.** The `secret_extraction` pattern in `prompt_guard.py` matches the noun `password`
without distinguishing *the password* from *the password policy*:

```python
(
    "secret_extraction",
    r"\b(?:show|reveal|print|give|tell|send|share|provide)\s+(?:me\s+)?(?:the\s+)?"
    r"(?:\w+\s+){0,2}?(?:api\s*key|secret|token|password|credential)s?\b",
),
```

Any request phrased "Show me the …" / "Tell me the …" that mentions a credential noun is refused
**before retrieval**.

**Why it matters.** This is the most damaging defect in the project. The exact use case the product
exists for — an employee asking about password policy, credential handling, API key rotation, token
lifetime — is refused with a message accusing the user of an attack:

> "I can't help with that request. It asks me to change my operating rules or to disclose material
> outside your access level…"

In a live 3-minute demo this reads as a broken product. It also directly contradicts
`PRODUCT_SPEC.md` §2 scenario A, whose canonical question is about password requirements.

**Reproduction.** Live, as `employee@example.com`. Measured **8 of 12 legitimate questions blocked
(67%)**:

| Question | Blocked | Category |
| --- | --- | --- |
| Show me the password policy | **YES** | `secret_extraction` |
| Tell me the password policy | **YES** | `secret_extraction` |
| Give me the password requirements | **YES** | `secret_extraction` |
| Show me the password requirements | **YES** | `secret_extraction` |
| Show me the API key rotation policy | **YES** | `secret_extraction` |
| Please show me the credential handling procedure | **YES** | `secret_extraction` |
| Show me the token lifetime policy | **YES** | `secret_extraction` |
| Tell me the secret management policy | **YES** | `secret_extraction` |
| Show me the API key management standard | **YES** | `secret_extraction` |
| Show me the access control policy | no | — |
| What does the password policy say about length? | no | — |
| List the password rules | no | — |

**Expected.** Answered from KB-001 (Password Policy) with a citation, since KB-001 is in the
employee's authorised set.

**Actual.** `blocked=True`, `intent=out_of_scope`, no retrieval, no sources, no ticket.

**Relevant files.**
* `backend/app/ai/prompt_guard.py:106-111` (the pattern)
* `backend/app/services/chat_service.py:291-295` (guard runs before intent/retrieval)

**Recommended fix.** Require the credential noun to be a **bare value request**, not a document
request. Add a negative lookahead for document nouns
(`policy|policies|requirements?|procedure|standard|guideline|rotation|lifetime|management|handling|strength`)
or require possessive binding to the assistant (`your …`). Then add a **false-positive corpus** to
the test suite.

**Why the test suite cannot see this.** The guard's precision is asserted against 14 hand-written
legitimate questions plus the 40-question evaluation set. **Neither contains a single "Show me the
X policy" phrasing** — I checked every question in `evaluation_questions.json`. The README's
"30/30 coverage with zero false positives" is simultaneously true and misleading: precision was
measured on a corpus constructed to avoid the failure mode.

---

### P0-2 [KNOWN — §8.2] The LLM path is dead and untested code; the shipped product is keyword search plus sentence extraction

**Problem.** The shipped `.env` sets `LLM_PROVIDER=mock`. `get_llm_client()` then returns
`MockLLMClient`, a deterministic sentence ranker that scores retrieved sentences by keyword overlap.
`OpenAICompatibleLLMClient.complete()` — the real generation path — is **never executed**.
Coverage confirms lines `423–472` (the entire method) are missed; `app/ai/llm.py` sits at 84%.
`EMBEDDING_PROVIDER=tfidf` likewise means no semantic embeddings.

**Why it matters.** This is the difference between "a RAG assistant" and "lexical search that
quotes sentences." The quality claims in the README were measured against the mock under
test-only overrides. The project's central claim — retrieval-augmented *generation* — has never
once been run end to end. A single interviewer question (*"show me the prompt you send the
model"*) exposes this, because there is no executed call site.

**Status note.** `PROJECT_HANDOFF.md` §8.2 documents this honestly ("`mock` LLM is not a language
model"), and `docs/DEMO.md:205` discloses it. The defect is therefore **not that it is hidden from
maintainers** — it is that `README.md` line 1 leads with "an enterprise security knowledge
assistant" while `PRODUCT_SPEC.md` §6 requires "可配置 LLM API", and the disclosure lives three
documents deep.

**Reproduction.**
```powershell
cd backend
.\.venv\Scripts\python.exe -c "from app.core.config import get_settings; from app.ai.llm import get_llm_client; s=get_settings(); print(s.llm_provider, type(get_llm_client(s)).__name__)"
# -> mock MockLLMClient

.\.venv\Scripts\python.exe -m pytest --cov=app --cov-report=term-missing
# -> app\ai\llm.py  213  34  84%  ... 423-472   <- OpenAICompatibleLLMClient.complete
```

**Expected.** The real provider path is covered by at least one test and exercised once end to end.

**Actual.** Zero coverage, zero executions.

**Relevant files.** `.env`, `backend/app/ai/llm.py:381-472`, `backend/tests/conftest.py:54-55`,
`README.md:1-6`.

**Recommended fix.** (1) Add tests driving `OpenAICompatibleLLMClient.complete` against a stubbed
HTTP transport. (2) Execute one recorded end-to-end run against a real endpoint and commit the
transcript. (3) Move the `mock` disclosure into the README's opening paragraph.

---

## 4. P1 — Important

---

### P1-1 [CONFIRMED — BUG-1] Real breach phrasings fall through to `out_of_scope` with no escalation

**Problem.** Because `out_of_scope` **skips retrieval** (`chat_service.py:316-318`) *and* also
yields `risk=low`, `escalation=False`, a report the classifier does not recognise is neither
answered nor escalated. It vanishes.

**Why it matters.** This is the highest-consequence failure in the domain. A user reporting an
actual breach is told "I do not have an approved knowledge document that answers this question"
and **nobody is notified**. Silent under-escalation of a real incident is the worst possible
outcome for a security tool.

**Reproduction (live, as an employee)** — independently found before reading the handoff register:

| Report | intent | risk | escalation | sources |
| --- | --- | --- | --- | --- |
| "We lost 500 customer records to an attacker" | `out_of_scope` | **low** | **False** | none |
| "Someone installed a keylogger on my machine" | `security_incident` | **medium** | **False** | KB-012 |
| "There is a strange process running on the server" | `policy_question` | **low** | **False** | KB-010, KB-011 |

The first is unambiguous S1 data loss under KB-009 §1. No ticket, no escalation.

`PROJECT_HANDOFF.md` BUG-1 documents the same defect from a different angle (account-takeover
phrasings) with excellent root-cause analysis: a word-boundary trap (`logged\s+in\b` cannot match
"logged into") and a grammar conflation in the risk rule (the noun `access` takes "to"; the verb
`accessed` does not). My probes confirm the same root cause manifests beyond account takeover.

**Expected.** A data-exfiltration or malware signal → `critical`/`high` → ticket + escalation.

**Actual.** No escalation, no ticket, an unhelpful answer.

**Relevant files.**
* `backend/app/ai/risk_classifier.py` (exfiltration rules 141-154 require *leaked/exfiltrated/copied/uploaded/sent*, not *lost … to an attacker*)
* `backend/app/ai/intent_classifier.py:146-147` (account-takeover rule, per BUG-1)
* `backend/app/services/chat_service.py:316-320` (the consequence amplifier)

**Recommended fix.** (a) Broaden the rules per BUG-1's suggested fix. (b) **Add a fail-safe**: if
intent is `out_of_scope` but high/critical-shaped vocabulary is present, still run the risk
classifier and escalate on its result. Never let a classification miss silently suppress
escalation — that structural guard is what prevents this class of bug recurring.

---

### P1-2 [NEW] `"Zero LLM execution"` is masked by test-only configuration overrides

**Problem.** `backend/tests/conftest.py:60` sets `RETRIEVAL_RELATIVE_FLOOR=0.5`, but the shipped
`.env:111` sets **0.7**. The README's headline retrieval claim and its tuning note describe **0.5**
— a value production does not use. `docs/DEMO.md:211` compounds it by asserting "the relative floor
is 0.5" while `.env` says 0.7.

**Why it matters.** Every quality number is measured under a configuration the demo does not run.

**Reproduction.**
```powershell
Select-String -Path .env,backend\tests\conftest.py,backend\tests\test_evaluation_set.py -Pattern 'RELATIVE_FLOOR'
# .env:111                                   RETRIEVAL_RELATIVE_FLOOR=0.7
# backend\tests\conftest.py:60               "RETRIEVAL_RELATIVE_FLOOR": "0.5",
# backend\tests\test_evaluation_set.py:170   "RETRIEVAL_RELATIVE_FLOOR": "0.5",
```

I ran the full 40-question set against the **live** app (floor 0.7):

| Metric | README claim | Live measurement (floor 0.7) |
| --- | --- | --- |
| intent | 40/40 | **40/40** ✅ |
| risk | 40/40 | **40/40** ✅ |
| escalation | 40/40 | **40/40** ✅ |
| ticket | 40/40 | **40/40** ✅ |
| blocked | 5/5 | **5/5** ✅ |
| expected document retrieved | **29/29** | **25/28 (89.3%)** ❌ |

Three retrieval misses: `faq-005` (got KB-012, expected KB-001); `incident-005` (got KB-002,
expected KB-003/KB-009); `incident-006` (got KB-011/KB-010/KB-002, expected KB-005/KB-009).
89.3% clears the set's own 85% bar, but it is not the advertised 100%.

Additionally, **"29/29" is wrong on its face**: the file contains **28** graded questions
(`documents_any_of` non-empty), not 29.

**Expected.** Test configuration equals demo configuration, or the README states which
configuration each number came from.

**Actual.** README reports test-config numbers as product behaviour.

**Relevant files.** `.env:111`, `.env.example:134`, `backend/tests/conftest.py:60`,
`docs/DEMO.md:211`, `README.md:761`.

**Recommended fix.** Align `.env.example`/`.env` to 0.5, or re-tune and re-measure at 0.7 and
correct the README to 25/28 and "28 graded questions."

---

### P1-3 [NEW] Unauthenticated `/api/v1/meta` discloses the full AI stack fingerprint

**Problem.** `GET /api/v1/meta` requires no token and returns provider, model, embedding backend,
vector store, retrieval `top_k`, environment, and demo-login/seed state.

**Why it matters.** It tells an attacker exactly which surfaces to attack and how.
`retrieval_top_k: 5`, combined with `/chat/capabilities` reporting `blocking_rules: 30`,
`intent.rule_count: 46`, `risk.rule_count: 35`, `intent.threshold: 0.6`, amounts to: *"here is the
size of the pattern-matching gate you must get past, and where its threshold sits."* In any
enterprise security review this is a finding. `environment: development` also advertises that demo
credentials are live.

**Reproduction.**
```powershell
curl http://127.0.0.1:8000/api/v1/meta     # no Authorization header
```
```json
{"app_name":"...","environment":"development",
 "features":{"demo_login":true,"demo_users_seeded":true},
 "ai":{"llm_provider":"mock","llm_model":"gpt-4o-mini","llm_configured":true,
       "embedding_provider":"tfidf","vector_store":"faiss","retrieval_top_k":5},
 "roles":["employee","it","security"]}
```

**Expected.** Public metadata limited to name/version/health; AI internals behind authentication
or a role check.

**Actual.** Full disclosure to any anonymous caller.

**Relevant files.** `backend/app/api/routes/health.py:51-70`, `backend/app/schemas/common.py`
(`MetaResponse`), `backend/app/core/config.py:304-322` (`public_summary`).

**Recommended fix.** Keep `app_name`/`version`/`health` public; move the `ai` block behind
`require_roles(Role.SECURITY)` or drop it. In `/chat/capabilities`, report rule counts as booleans
("injection guard: enabled") rather than integers.

---

### P1-4 [NEW] `/knowledge/search` performs embeddings unthrottled (60 requests in 0.8 s)

**Problem.** The rate limiter is applied only to
`POST /chat/conversations/{id}/messages` (`chat.py:177`). `POST /knowledge/search` embeds a query and
runs a vector search with no limiter at all.

**Why it matters.** It is the same expensive primitive. With `EMBEDDING_PROVIDER=openai_compatible`
(the documented production option) this endpoint is an unmetered path to a billed API —
straightforward cost amplification, plus a cheap CPU DoS. The README presents rate limiting as a
control; it covers one of two equivalent routes.

**Reproduction.** 60 rapid `POST /api/v1/knowledge/search` → `{200: 60}` in 0.8 s, no 429. The
identical workload through the chat endpoint hits 429 at request 21.

**Expected.** Per-user throttle on every endpoint that embeds or retrieves.

**Actual.** Unlimited.

**Relevant files.** `backend/app/api/routes/knowledge.py:117-169`,
`backend/app/api/routes/chat.py:176-177`, `backend/app/security/rate_limit.py`.

**Recommended fix.** Apply a shared limiter via dependency on `/knowledge/search`, or add a global
dependency for any route calling `KnowledgeService.search`.

---

### P1-5 [NEW] Employees see system-wide escalation metrics; `statistics` is capped and silently wrong past 200 rows

**Problem.** `TicketService.statistics()` computes counts by calling
`list_visible(..., limit=MAX_PAGE_SIZE)` and counting in Python. For an employee, `list_visible`
also returns every **security-owned** ticket they created (auto-escalations from their own chat),
so their "My tickets" statistics reflect the security queue. The cap is 200 rows with no `COUNT(*)
` query, so beyond 200 tickets every number is silently truncated.

**Why it matters.** Two separate defects. (1) An employee's ticket page reports `escalated: 58`,
`requiring_human: 70` — the operational state of the security team, disclosed to a non-security
role. `README.md:257` claims the dashboard returns "aggregates, never content"; `tickets.statistics`
is not the dashboard and is not scoped as implied. (2) The truncation is a correctness bug that
appears as the demo grows. Note `count_visible()` (`ticket_service.py:216`) has the identical cap.

**Reproduction (live).**
```
employee GET /tickets/statistics ->
{"total":74,"open":62,"escalated":58,"requiring_human":70,
 "by_severity":{"low":4,"high":58,"critical":12}}
```
No security role was involved.

**Expected.** Counts over the caller's visible set, computed in SQL, with no page cap.

**Actual.** Queue-wide figures for a non-security user; approximate due to the row cap.

**Relevant files.** `backend/app/services/ticket_service.py:469-484` and `:215-216`,
`backend/app/security/rbac.py:189-200`.

**Recommended fix.** Replace fetch-then-count with
`select(func.count()).select_from(...)` using the same `visible_ticket_filter` predicates. Decide
explicitly whether an employee's cross-team view is intended; if not, add
`Ticket.owner_role == caller_role` to the employee branch (as `can_update_ticket` already implies).

---

### P1-6 [NEW] Self-raised tickets ignore the requested category and can never be updated by the raiser

**Problem.** `POST /tickets` derives `owner_role` from the raiser's role via `OWNER_ROLE_FOR_RAISER`
and ignores the `category` field entirely. The UI's "Create ticket" button posts
`category: 'security'`; the resulting ticket is `owner_role=it`, `severity=low`, and the raiser gets
`can_update: false`.

**Why it matters.** An employee who reports a security concern through the UI files it into the
**IT** queue at **low** severity, where the security team may never triage it, and then cannot
follow it up. This is a workflow dead end on the product's flagship path.

**Reproduction (live).**
```
POST /tickets  {"title":"VPN will not connect","description":"...","category":"security"}
-> 201 owner_role=it severity=low status=open source=user_request can_update=False

POST /tickets  {"title":"...","category":"incident","severity":"critical","owner_role":"security"}
-> 201 owner_role=it severity=low        (unknown fields silently ignored)
```
Good news, and worth stating: `severity`/`owner_role` overrides are correctly ignored — privilege
escalation via the request body is properly blocked.

**Expected.** A security-category request routes to `owner_role=security` (or the UI offers the
correct category), and the raiser can at least track it.

**Actual.** Always IT, always low, read-only.

**Relevant files.** `backend/app/api/routes/tickets.py:36-40, 127-163`,
`frontend/src/hooks/useChat.ts:212-228`.

**Recommended fix.** Map `category` → `owner_role` for user-raised tickets
(`phishing|incident` → security), or have the UI send a category matching the routing table.
Consider letting a raiser add a follow-up note.

---

### P1-7 [NEW] Test-suite blind spots, including one gap that directly caused P0-1

**Problem.** The suite is genuinely strong — real rendering, real service calls, 94% coverage — but
has specific holes that let P0-1 and P1-1 through.

**Why it matters.** The suite is presented as the evidence base for the README's claims. These gaps
mean the claims are narrower than stated.

**Findings.**

1. **No false-positive corpus for the prompt guard.** `tests/test_prompt_guard.py` uses 14
   hand-written legitimate questions; the 40-question evaluation set has none. **This is the direct
   cause of P0-1.**
2. **The real LLM client is untested** — see P0-2.
3. **Unreachable assertion** — `frontend/src/App.test.tsx:338` and `:417`:
   `expect((await screen.findAllByText(/…/)).length).toBeGreaterThan(0)`. `findAllBy*` rejects when
   it matches nothing, so if the await resolves the assertion is already proven. It can never fail.
4. **Value-blind tests** — `App.test.tsx:650-654` ("shows the queue statistics") asserts only that
   the label `'Needs a human'` exists, never the number; it **passes unchanged if every statistic
   renders `0` or `NaN`**. Same pattern at `:1038-1046` (distributions) and `:1067-1076` (whose
   only asserted outcome is an outgoing request URL).
5. **Weak-but-failable assertions** — `App.test.tsx:319` uses `getByText(/7/)` (matches any text
   containing the digit 7, so KB-007 or a timestamp would satisfy it); `App.test.tsx:556-561`
   guards "never offers a role switcher" with `queryByRole('combobox')` only, so a switcher built
   as a button or link would slip through.
6. **No frontend coverage tooling at all.** `@vitest/coverage-v8` is absent from
   `devDependencies`; neither `package.json` nor `vite.config.ts` contains any `coverage`
   configuration or script (verified: zero matches). The frontend reports a raw count — 59 tests —
   with **no denominator**. `App.test.tsx` imports only `./App` and `./api/client`, so the 11
   component files and 4 hooks are exercised only indirectly through `render(<App />)`. A component
   App never mounts could be entirely untested while all 59 tests pass.
7. **Coverage excludes `app/main.py`** (`pyproject.toml` `omit`), so lifespan wiring is unmeasured.

**Reproduction.**
```powershell
cd backend; .\.venv\Scripts\python.exe -m pytest -q --cov=app --cov-report=term-missing
# 1415 passed, 1 skipped, 94%   |   app\ai\llm.py 213 34 84% ... 423-472

cd ..\frontend; npm test        # 59 passed
Select-String -Path package.json,vite.config.ts -Pattern 'coverage'   # no matches
```

**Expected.** A legitimate-question corpus asserting `blocked == False`; value assertions on
statistics and distributions; a frontend coverage provider with thresholds.

**Actual.** None of the above.

**Relevant files.** `frontend/src/App.test.tsx`, `frontend/package.json`,
`frontend/vite.config.ts`, `backend/tests/test_prompt_guard.py`, `backend/pyproject.toml`,
`backend/tests/conftest.py`.

**Recommended fix.** Add a 30-question legitimate corpus (including document-noun phrasings) asserted
not to block. Fix the two dead assertions and the value-blind tests. Add HTTP-stub tests for
`OpenAICompatibleLLMClient`. Install `@vitest/coverage-v8` with thresholds, or drop the unqualified
frontend test count from the README.

---

## 5. Docker Compose — not verified, and why that matters

**Docker is not installed in this environment.** I could not run `docker compose up`, and neither
could the project's authors (`README.md:693`, `docs/DEMO.md:239` both state this explicitly).

**What I could verify statically** — and it is genuinely well constructed:

* Two multi-stage images; backend runs as uid 10001, frontend under nginx's own worker user.
* `AUTH_SECRET_KEY` and `LLM_API_KEY` are deliberately **absent** from `docker-compose.yml`, so they
  cannot be baked into an image layer.
* nginx terminates same-origin: `/api` is proxied to the `backend` service, so the production
  request path has **no CORS at all**.
* `TRUSTED_PROXY_COUNT: 1` matches the single nginx hop, and `client_address.py` reads
  `X-Forwarded-For` from the **right**, where a client cannot write — a correct and unusually
  careful implementation.
* `DATABASE_URL` uses four slashes (absolute path), and the volume covers both the database and the
  index.
* `security_opt: no-new-privileges:true` on both services; CSP declared at both the nginx layer and
  injected into the built HTML.
* `scripts/verify-container-image.ps1` reproduces the image layout without Docker — an honest
  partial substitute.

**What remains unverified.** Whether the images actually build, whether the named-volume ownership
`chown` works as intended in practice, and whether the healthcheck gating behaves. 80 static tests
in `test_deployment_assets.py` cross-check the files against each other, and one **skips with an
explicit reason** when the Docker CLI is absent — which is the right behaviour, and is why the skip
is not a defect.

**Assessment.** This is a **residual risk, not a defect**. The project discloses it rather than
claiming otherwise, which is the correct posture. But acceptance criterion 10 of `PRODUCT_SPEC.md`
("Docker Compose 可以启动整个系统") is **not met by evidence** — only by static argument. Anyone
claiming it as met in an interview is overstating.

---

## 6. P2 — Improvement

| # | Issue | Why it matters |
| --- | --- | --- |
| **P2-1** | `rate_limit.py` is per-process, in memory | Correct for the single-worker deployment and documented as such, but `--workers N` or horizontal scaling silently multiplies every limit by N. Needs Redis or sticky routing before it means anything. (Also in `PROJECT_HANDOFF.md` §8.2.) |
| **P2-2** | Login returns 422 for malformed input, 401 for wrong credentials | The 401 path is properly generic (verified byte-identical for unknown user vs. wrong password), but the 422/401 split is a minor enumeration signal. `README.md:51`'s "no account enumeration" holds only for well-formed requests. |
| **P2-3** | Audit rows store the actor's email (`audit.py:98`) | Deliberate and useful for triage, but it is personal data in an append-only log with no retention policy — a GDPR/DPO conversation in a real enterprise. |
| **P2-4** | No database migration tool | `session.py:119-138` detects schema drift, rebuilds in development and refuses to start elsewhere. Clever and honestly documented, but not a substitute for Alembic. (Also §8.2.) |
| **P2-5** | No CI configuration | `scripts/check.ps1` exists but nothing runs it automatically. 1415 tests with no pipeline is a maintainability risk — and P0-1 shows what such a suite can miss. |
| **P2-6** | `MessageBubble.tsx:133` reads `payload.recommended_actions.length` | Would throw if the field were ever absent. Low risk today given the closed payload shape. |
| **P2-7** | Guard/classifier corpora are duplicated across test files | The same 5 injections appear in the evaluation set and `test_prompt_guard.py`; a shared fixture would prevent drift. |
| **P2-8** | `BUG-2` per `PROJECT_HANDOFF.md` | A medium-risk report whose clarifying question is never answered is never tracked. I reproduced the medium/clarify path; the handoff register has the full write-up and I add nothing to it. |

---

## 7. P3 — Nice to Have

* **P3-1.** Alembic migrations.
* **P3-2.** Semantic embeddings in the demo path — one config line, and retrieval quality visibly improves.
* **P3-3.** Multi-turn evaluation cases. The set is 40 independent single turns; conversation-aware behaviour rests on one end-to-end test.
* **P3-4.** Streaming responses. Currently a single blocking POST with a 120 s nginx read timeout.
* **P3-5.** i18n. The English-only limitation is documented honestly, but a Chinese-language enterprise deployment needs it.
* **P3-6.** Structured audit export (JSONL/SIEM). The append-only trail is good; a sink would make it operationally useful.
* **P3-7.** Replace SQLite + named volume with a managed database beyond demo scale.

---

## 8. F — Solution / Pre-sales assessment

Framed for a Tencent Solutions / ByteDance FDE interview panel.

**1. What enterprise problem does this actually solve?**
A real and underserved one: *security knowledge is trapped in PDFs nobody reads, and incident
triage depends on a human being awake at 3 a.m.* The genuine insight is not "AI answers questions"
— it is **"route the cheap 80% to self-service while guaranteeing the dangerous 20% reaches a
person."** That is a sellable problem.

**2. Why is RAG necessary here?**
Three defensible reasons: (a) security policy changes constantly and a fine-tuned model goes stale;
(b) **citations are an audit requirement** — a security answer with no traceable source is useless
in a compliance review; (c) it keeps the internal corpus out of a third party's training set.
Reasons (b) and (c) are the strong ones, and the project implements both.

**3. Why is RBAC necessary?**
Because the corpus is genuinely tiered: phishing *response* is employee-visible; phishing
*investigation* is not. Showing an employee the investigation playbook teaches them the detection
thresholds. The implementation is the project's best feature: **the allow-list is pushed into the
vector search before scoring**, so restricted chunks are never scored, never counted, never ordered.
This is rare — most portfolio RAG projects filter *after* retrieval and leak through result counts.

**4. Why is a Workflow necessary?**
Because an answer is not an outcome. The three-tier design (low = self-service, medium = ask one
clarifying question, high/critical = file and escalate) is a thoughtful product decision, and
"one incident, one ticket — escalate the existing one rather than opening a second" shows real
operational thinking.

**5. What does AI add over a traditional FAQ?**
Honestly: **with the shipped mock provider, little.** A keyword FAQ with a ticket button would do
80% of this. The AI earns its place in three ways — free-text → structured intent/risk extraction,
conversational follow-up that raises severity as facts arrive, and grounded summarisation across
documents. Lead with the second: it is the one thing a FAQ cannot do, and it is the demo's
strongest moment.

**6. Which features are genuine enterprise capabilities?**
* Pre-retrieval authorisation inside the vector store (the strongest asset)
* Server-side sessions with immediate revocation; brute-force lockout a correct password cannot bypass
* Backend-owned escalation the model cannot lower, with monotonic risk per conversation
* Append-only ticket timeline requiring acknowledgement before resolution
* Idempotent, audited, credential-redacted ticket creation that survives a write failure
* Health-check gating, unprivileged containers, a no-CORS single-origin production path

**7. Which features are for show rather than substance?**
* The 30-regex prompt guard — currently a liability, not a control (P0-1)
* `/chat/capabilities` disclosing rule counts
* The 67-check demo script: impressive engineering, partly self-congratulatory
* `kb_strict_validation` and the schema-drift rebuild — elegant solutions to problems a real deployment would not have

**8. Can the demo be told in 3 minutes?**
Yes — `docs/DEMO.md` is a good script — **but not as currently configured**, because "show me the
password policy" is a natural thing for a presenter or audience to ask and it fails today. The
spine is strong and I verified it end to end: phishing email → answer + citation → "I entered my
password" → risk rises to High → ticket `SEC-2026-XXXX` → visible on the security dashboard →
human acknowledges.

**9. Is this resume-worthy?**
**Yes, with the caveats fixed.** The security architecture is above the typical portfolio bar and
the documentation discipline is unusual. As it stands, a sharp interviewer finds the LLM gap in
about two questions, and that single discovery retroactively devalues every other claim.

**10. What will an interviewer challenge?**
* *"Is an LLM actually called here?"* → **This lands today.** Fix P0-2 first.
* *"Show me your tests for the real model path."* → Currently nothing to show.
* *"Your guard blocked 'show me the password policy' — is that acceptable?"* → Fix P0-1.
* *"What happens when someone reports a real breach in words your rules miss?"* → Fix P1-1.
* *"Why is your evaluation set only 28 graded questions? That's a small sample."* → Answer honestly.
* *"How does this scale past one process?"* → Have the Redis answer ready; `rate_limit.py` already documents it.
* *"Has `docker compose up` ever been run?"* → The project answers this honestly already; keep that answer.

---

## 9. Recommended fix order

### Before any interview or demo (2–4 hours, highest return)

1. **P0-1 — guard false positives.** Add the document-noun negative lookahead; add a 30-question
   legitimate corpus. *Small change; removes the defect most likely to surface in a live demo.*
2. **P0-2 — make the LLM path real.** Stub-transport tests for `OpenAICompatibleLLMClient`; one
   recorded run against a real endpoint; move the `mock` disclosure into the README's first
   paragraph. *Removes the single most damaging question.*
3. **P1-2 — reconcile configuration.** Align `RETRIEVAL_RELATIVE_FLOOR`, correct "29/29" to the real
   figure, and state which configuration produced each metric.

### Before claiming enterprise readiness

4. **P1-1 — never let a classification miss suppress escalation.** Broaden the rules *and* add the
   structural fail-safe. *Highest consequence-per-line-of-code on this list.*
5. **P1-3 — restrict `/api/v1/meta` and the capability rule counts.**
6. **P1-5 — fix `statistics` to count in SQL over the scoped filter; decide the employee cross-team view explicitly.**
7. **P1-4 — throttle `/knowledge/search`.**
8. **P1-6 — route self-raised tickets by category.**
9. **P1-7 + P2-5 — repair the weak tests *and* wire `scripts/check.ps1` into CI, adding frontend
   coverage so the gap cannot silently reopen.**

> Rationale for promoting CI: P0-1 and P1-1 both passed a 1416-test suite. A suite that cannot see
> its own blind spots needs a pipeline that at least measures them on every change — otherwise the
> same class of defect returns the next time somebody widens a regex.

### Then

P2-4 (Alembic) → P2-1 (shared rate-limit store) → P2-3 (audit retention) → P2-2 / P2-6 / P2-7 /
P2-8 → the P3 list.

---

## 10. Summary of findings

| ID | Severity | Status | Title |
| --- | --- | --- | --- |
| P0-1 | Critical | **[NEW]** | Prompt guard refuses 67% of legitimate policy questions |
| P0-2 | Critical | [KNOWN §8.2] | LLM path is dead and untested code; product is search + extraction |
| P1-1 | Important | [CONFIRMED BUG-1] | Breach phrasings fall to `out_of_scope` with no escalation |
| P1-2 | Important | **[NEW]** | Test config (0.5) ≠ shipped config (0.7); recall 25/28, not 29/29 |
| P1-3 | Important | **[NEW]** | Unauthenticated `/meta` discloses AI stack and rule counts |
| P1-4 | Important | **[NEW]** | `/knowledge/search` embeds unthrottled |
| P1-5 | Important | **[NEW]** | Cross-tenant metrics leak; `statistics` capped at 200 rows |
| P1-6 | Important | **[NEW]** | Self-raised security tickets route to IT, low, read-only |
| P1-7 | Important | **[NEW]** | Test blind spots (incl. the gap that caused P0-1); no frontend coverage |
| — | Residual risk | Known | `docker compose up` never executed (no Docker available) |

**Of the nine P0/P1 findings: 7 are new, 1 confirms a known bug independently, and 1 was documented
but under-communicated.**

---

## 11. Reviewer's closing note

The engineering instincts here are good, and the authorization design in particular is better than
what I typically see in production code rather than in portfolios. The project's own honesty about
its limitations — the mock provider, the lexical retriever, the English-only corpus, the unrun
Docker path, and a handoff register that names its own open bugs — is a genuine strength and a
signal of a disciplined developer.

The gap is not capability. It is that **the configuration the tests measure is not the
configuration the product ships**, and that the prompt guard — the one component written
specifically to be careful — is currently the thing most likely to reject a legitimate user. Both
are fixable in an afternoon. Fix those two and this moves from a strong portfolio project to one
that survives an adversarial interview without losing a claim.

---

*This review changed no code. All probe scripts were written outside the repository (in the system
temp directory); the only state change was test data created through the running API's own
endpoints, which is the intended use of a chat and ticketing system.*
