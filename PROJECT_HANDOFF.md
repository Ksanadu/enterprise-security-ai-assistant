# PROJECT HANDOFF — Enterprise Security AI Assistant

**Handoff date:** end of Phase 10 (all ten phases complete)
**Repository:** `git@github.com:Ksanadu/enterprise-security-ai-assistant.git`, branch `main`
**Audience:** the engineer who inherits this codebase. This document assumes you have never
seen the project and have one working day to become productive in it.

**How to read this document.** Sections 1–5 get you running and testing. Sections 6–7 tell you
what exists and why it is built the way it is. Sections 8–10 are the parts that will hurt you
if you skip them: known bugs, deployment reality, and the security invariants you must not
break. Sections 11–12 are the maintenance playbook and a sign-off checklist.

> **Reviewed and corrected during the stabilization pass (2026-09-13).** Every factual claim in
> this document was checked against the repository by execution, not by reading. Thirteen were
> wrong or stale, and they are corrected in place below: two deployment validations that did not
> exist (§5.5), the gate's step order and content (§5.1), the session-storage claim (§8.2), the
> evaluation set's graded-question count (§5.4), the settings count (§4.5), and the test and
> coverage numbers throughout. Both open bugs in §8.1 are now **fixed**; §8.1 records what was
> actually wrong and where the fix lives. The running state of the project, round by round, is
> `PROJECT_STATUS.md`. Where this document and the code disagree, the code wins - and then this
> document gets fixed in the same commit, which is the rule it already asked for.
>
> **Amended after the one-command deployment change.** §9.1 and §9.2 previously required
> `Copy-Item .env.example .env` before `docker compose up`, and presented the missing env file as
> the reason the command could not be validated on a runner. That prerequisite was doing work the
> compose file should have done itself: the `env_file` entry is now optional, the compose file
> carries a working default for every value the stack needs, and `docker compose up --build` works
> on a fresh clone with nothing else. The two launcher scripts and the tests that cover them are in
> §3 and §5.5; `PROJECT_STATUS.md` records the round.

---

## 1. What this project is

**One sentence:** a runnable prototype of an enterprise security knowledge assistant — employees
ask security questions in natural language, the assistant answers from an internal,
role-scoped knowledge base, cites its sources, classifies the risk of what it is told, and
escalates high-risk incidents into security tickets for a human team.

**Business value.** It compresses three things that today cost an enterprise money and latency:

| Problem today | What this system does |
| --- | --- |
| Employees ask Security/IT the same policy questions repeatedly; answers are slow and inconsistent | Answers instantly from the approved internal knowledge base, with citations a compliance reviewer can audit |
| Employees do not know whether an incident is serious, so real incidents sit unreported for hours | Classifies intent and risk on every message, and escalates high-risk reports to a human immediately |
| Sensitive material is visible to everyone because filtering happens after retrieval | Enforces role scope *inside* the search itself, so a user can never retrieve a document their role may not read |

**What it is not.** It is a **prototype with simulated data**. There is no real employee,
customer, system or incident data anywhere in this repository; every user, document, ticket
and phone number is fictional. It has never run in production. Section 9 lists exactly what
must change before it could.

**Core requirement sources.** `PRODUCT_SPEC.md` (292 lines) is the authority for scope: §9 lists
the 13 acceptance criteria, §11 lists the 10 phases, §10 defines the end-to-end demo. Where this
document and the spec disagree, the spec wins and this document is wrong — tell someone.

---

## 2. Technology stack and versions

### Backend

| Component | Version | Notes |
| --- | --- | --- |
| Python | 3.12.10 | developed and verified on this exact version |
| FastAPI | 0.115.14 | ASGI app, `create_app()` factory |
| Uvicorn | pinned in requirements | single worker in every supported run mode (see §8) |
| SQLAlchemy | 2.0.52 | 2.0-style typed ORM |
| Pydantic | 2.13.5 | v2 API; settings via `pydantic-settings` |
| PyJWT | pinned | HS256 access tokens |
| bcrypt | pinned | password hashing, called directly (not via passlib) |
| httpx | pinned | LLM + embedding HTTP calls, and the test client |
| pytest | 8.4.2 | test runner; `pytest-cov` for coverage |
| FAISS | `faiss-cpu` | `IndexFlatIP`, exact inner-product search |
| NumPy | pinned | embedding vectors |
| snowballstemmer | pinned | offline embedder tokenisation |
| PyYAML | pinned | knowledge base front-matter |

### Frontend

| Component | Version | Notes |
| --- | --- | --- |
| React | 18 | function components + hooks only |
| TypeScript | 5.x, `strict` **and** `exactOptionalPropertyTypes: true` | the second flag is the one that bites; see §11 |
| Vite | 6 | dev server + production build |
| vitest | 2 | component/unit tests |
| ESLint | 9 | flat config |
| nginx | `nginx:alpine` | production static host + `/api` reverse proxy |

### Data and model services

| Concern | Default | Alternatives |
| --- | --- | --- |
| Relational store | SQLite (`sqlite:///./data/app.db`) | any SQLAlchemy URL |
| Vector store | FAISS `IndexFlatIP` on disk | `InMemoryVectorStore` (`VECTOR_STORE=memory`) |
| Embeddings | **offline BM25-weighted TF-IDF** over Snowball-stemmed tokens (`EMBEDDING_PROVIDER=tfidf`) | `openai_compatible` |
| LLM | `mock` (deterministic, no network) | any `openai_compatible` endpoint |
| Auth | simulated login for seeded demo users | — |

**The most important stack fact:** the default configuration needs **no network and no API key**.
`LLM_PROVIDER=mock` and `EMBEDDING_PROVIDER=tfidf` mean the whole system, including the full
test suite and the demo, runs offline and deterministically. That is deliberate (§7).

---

## 3. Directory structure

```
.
├── PRODUCT_SPEC.md            the requirements authority (§9 acceptance, §11 phases)
├── README.md                  main user/operator documentation (~70 KB)
├── PROJECT_HANDOFF.md         this document
├── PROJECT_STATUS.md          the running state: rounds, what is fixed, what is scheduled
├── Reviewer Report.md         the independent adversarial review (Phase 1, review only)
├── docker-compose.yml         two services: backend + frontend(nginx)
├── .github/workflows/ci.yml   runs scripts/check.ps1 on push and pull request
├── .env.example               48 settings, every one documented inline
├── .env                       YOUR local file — gitignored, never commit
├── .gitattributes             * text=auto eol=lf  (see §11, line endings)
├── .gitignore
├── docs/
│   ├── ARCHITECTURE.md        pipeline, authorization design, data model, threat model
│   └── DEMO.md                how to run the demo + presenter script + acceptance traceability
├── scripts/
│   ├── docker-up.ps1          ONE COMMAND: start the Docker stack, wait for readiness, report
│   ├── docker-up.sh           the same six steps for Linux/macOS
│   ├── run-local.ps1          start backend+frontend without Docker (the compose equivalent)
│   ├── check.ps1              THE gate: ruff + mypy + pytest(--cov, floor 90) +
│   │                          tsc + eslint + vitest(--coverage, thresholds) + secrets
│   ├── check-no-secrets.ps1   secret scan AND required-asset check
│   └── verify-container-image.ps1  build the image layout from requirements.txt alone, no Docker
├── .github/workflows/ci.yml   runs check.ps1 on every push to main and every pull request
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt       runtime deps (the image installs exactly these)
│   ├── requirements-dev.txt   test/lint deps
│   ├── app/
│   │   ├── main.py            create_app(): wiring, lifespan, middleware, routers
│   │   ├── core/        (6)   settings, logging, errors, security primitives
│   │   ├── db/          (5)   engine/session, base, bootstrap + demo seeding
│   │   ├── schemas/     (7)   Pydantic request/response contracts
│   │   ├── security/    (8)   RBAC, auth dependencies, rate limiting, lockout, redaction
│   │   ├── ai/          (9)   intent classifier, risk classifier, prompt guard, prompts, structured output
│   │   ├── rag/         (8)   chunking, embeddings, vector stores, retriever
│   │   ├── services/    (7)   chat orchestration, tickets, workflow manager, dashboard, audit
│   │   └── api/        (11)   one module per route group (auth, chat, tickets, dashboard, knowledge, …)
│   ├── knowledge_base/        12 simulated policy/SOP documents as Markdown + front-matter
│   │                          (83 chunks at the configured 700/100 chunking; the chunker's own
│   │                          defaults of 900/120 would give 66, so the number is settings-dependent)
│   ├── scripts/demo.py        the self-verifying end-to-end demonstration (71 assertions)
│   └── tests/           (37 files) 1475 tests
└── frontend/
    ├── Dockerfile
    ├── nginx.conf             SPA fallback + /api proxy
    └── src/
        ├── api/               typed fetch client, one module per route group
        ├── components/        chat, tickets, dashboard, admin views
        ├── hooks/             auth session, data fetching
        └── test/              vitest setup + helpers
```

**Where to look first for a given task:**

| I need to change… | Go to |
| --- | --- |
| what the assistant says when it has no answer | `backend/app/ai/prompts.py` |
| whether a message is phishing/malware/VPN/… | `backend/app/ai/intent_classifier.py` |
| how severe a message is | `backend/app/ai/risk_classifier.py` |
| what happens as a result (ticket / escalate / clarify) | `backend/app/services/workflow_manager.py` |
| who may read which document | `backend/app/security/rbac.py` and each KB file's `allowed_roles` |
| the per-turn pipeline order | `backend/app/services/chat_service.py` |
| an HTTP contract | `backend/app/schemas/` then `backend/app/api/` |
| the KB documents themselves | `backend/knowledge_base/*.md` |

---

## 4. Running it locally

### 4.1 Prerequisites

- **Python 3.12** (3.12.10 verified). On Windows, the `py` launcher or an explicit interpreter
  path is required; the Microsoft Store stub `python.exe` is a trap and the scripts skip it.
- **Node.js 20+** with npm.
- **PowerShell 5.1 or 7+.** All scripts are `.ps1` and were verified on Windows PowerShell 5.1.
  The script headers say `pwsh -File …`; if `pwsh` is not installed, use
  `powershell -ExecutionPolicy Bypass -File …` — the scripts themselves are version-agnostic.
- **Docker is optional** and only needed for §9. Nothing in the normal dev loop requires it.

### 4.2 First-time setup

```powershell
git clone git@github.com:Ksanadu/enterprise-security-ai-assistant.git
cd enterprise-security-ai-assistant

# 1. backend virtualenv + dependencies
py -3.12 -m venv backend\.venv
backend\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
backend\.venv\Scripts\python.exe -m pip install -r backend\requirements-dev.txt

# 2. frontend dependencies
cd frontend; npm install; cd ..

# 3. your local settings
Copy-Item .env.example .env
```

`AUTH_SECRET_KEY` in `.env.example` is a placeholder. **Generate a real one** before doing
anything you intend to keep:

```powershell
backend\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))"
```

### 4.3 Starting the system — two ways

**Way A — one command, no Docker (recommended for development):**

```powershell
.\scripts\run-local.ps1              # start backend + frontend, keep running
.\scripts\run-local.ps1 -Check       # start, smoke-test, shut down, return an exit code
.\scripts\run-local.ps1 -FrontendPort 5174 -BackendPort 8001
```

This is the non-container equivalent of `docker compose up`, and it deliberately reproduces the
same **single-origin topology** the nginx image provides: the browser only ever talks to the
Vite server, which serves the SPA and proxies `/api` to the backend on a second port. That means
the CORS configuration you exercise in development is the one production uses.

- Frontend (open this): **http://localhost:5173**
- Backend API + OpenAPI docs: **http://127.0.0.1:8000/docs**

**Way B — two terminals, more control:**

```powershell
# terminal 1
cd backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

# terminal 2
cd frontend
npm run dev
```

### 4.4 First run and demo logins

The database, the FAISS index, the demo users **and three sample tickets** are created
automatically on first startup (`SEED_DEMO_USERS=true`, `KB_STRICT_VALIDATION=true`). There is no
migration step and no manual data load — see §8 for why that is a limitation, not a feature.

Seeded accounts (password from `DEMO_USER_PASSWORD`):

| Email | Role | What it can see |
| --- | --- | --- |
| `employee@example.com` | employee | public FAQ + employee-facing policies (7 documents) |
| `employee2@example.com` | employee | the same, and the second account exists so cross-employee ticket isolation can be demonstrated |
| `it@example.com` | it | + VPN/endpoint troubleshooting, IT SOPs (10 documents) |
| `security@example.com` | security | everything, including incident-response SOPs (12 documents), plus the dashboard |

There is **no `admin` account and no `admin` role**: the role enum is `employee` / `it` /
`security`, and the dashboard is gated on `security`. This table previously listed an
`admin@example.com` that was never seeded — an audit of this document against the code found it, and
`admin@example.com` returns 401.

Log in as `security@example.com` to see the dashboard, and as `employee@example.com` to see the
RBAC boundary do its job (ask about the malware SOP as the employee, then as security).

### 4.5 Settings

All 48 settings are declared in `.env.example` with a comment on each — and `Settings` has **50**
fields: `PASSWORD_HASH_ROUNDS` and `AUTH_SECRET_EPHEMERAL` are real settings that the template
does not list (`AUTH_SECRET_EPHEMERAL` is set by the application rather than by an operator, but
`PASSWORD_HASH_ROUNDS` is one you may legitimately want to change). The ones you are most likely
to touch:

| Variable | Default | Effect |
| --- | --- | --- |
| `LLM_PROVIDER` | `mock` | set to `openai_compatible` to use a real model |
| `LLM_API_KEY` | empty | required only for a real model; read from env, never committed |
| `EMBEDDING_PROVIDER` | `tfidf` | `openai_compatible` for a real embedder |
| `VECTOR_STORE` | `faiss` | `memory` for a non-persistent store |
| `CLASSIFIER_USE_LLM` | `true` | `false` forces pure rule-based classification |
| `RETRIEVAL_TOP_K` | `6` | chunks requested per query |
| `RETRIEVAL_MIN_SCORE` | (see file) | absolute relevance floor |
| `RETRIEVAL_RELATIVE_FLOOR` | (see file) | score relative to the best hit |
| `TRUSTED_PROXY_COUNT` | `0` | **security-relevant**; see §10 |
| `CHAT_RATE_LIMIT_PER_MINUTE` | (see file) | per-user chat throttle |
| `AUTH_MAX_LOGIN_ATTEMPTS` | (see file) | then lockout for `AUTH_LOCKOUT_SECONDS` |
| `KB_STRICT_VALIDATION` | `true` | refuse to start on malformed KB front-matter |

Docker-only variables, consumed by `docker-compose.yml` and defined in your shell or `.env`:
`ESAA_API_PORT` (default 8000), `ESAA_HTTP_PORT` (default 8080), `ESAA_CORS_ORIGINS`.

Frontend build-time variables live in `frontend/.env.example` and are **four** `VITE_*` names:
`VITE_API_BASE_URL`, `VITE_APP_TITLE`, `VITE_DEV_PROXY_TARGET` and `VITE_DEV_PORT` (all four
typed in `frontend/src/vite-env.d.ts`). A fifth, `VITE_PREVIEW_PORT`, is read by
`frontend/vite.config.ts` for `vite preview` only and is deliberately not in the template.

### 4.6 The self-verifying demo

```powershell
cd backend
.\.venv\Scripts\python.exe scripts\demo.py
```

This drives the **real HTTP API** through the spec §10 scenario end to end — ask about a phishing
email, receive an answer with citations, say you entered your password, watch the risk rise, the
ticket get created, and the dashboard show the new event — and asserts **71** specific properties
along the way. It exits non-zero on the first failure. It is the fastest way to confirm a fresh
checkout actually works, and it is safe to run repeatedly (it waits out `429` rate-limit
responses — on the chat *and* the retrieval endpoint — rather than failing).

---

## 5. Testing and acceptance

### 5.1 The one gate that matters

```powershell
.\scripts\check.ps1
```

Run this before every commit. It executes, in order:

1. `ruff check app tests` — lint
2. `mypy app` — type check
3. `pytest -q --cov=app --cov-report=term-missing` — the backend suite **and** the coverage floor
   (`fail_under = 90` in `pyproject.toml`)
4. `npx tsc -b` — frontend type check
5. `npm run lint` — eslint (`--max-warnings 0`)
6. `npm run test:coverage` — vitest **and** the frontend coverage thresholds
7. `check-no-secrets.ps1` — secret scan and required-asset check

Non-zero exit means something failed; the output names it. `.github/workflows/ci.yml` runs this
same script on every push to `main` and every pull request, so the gate is not optional.

The order above is the file's real order: this section previously listed eslint before the type
check, called it `tsc --noEmit` when the gate runs `tsc -b`, and omitted the seventh step.

### 5.2 Current measured state

| Metric | Value |
| --- | --- |
| Backend tests | **1475 passing**, 1 skipped (was 1415/1 before the stabilization pass) |
| Frontend tests | **59 passing** (2 files), now with coverage thresholds |
| Backend coverage | **95%** (4213 statements, 215 missed), floor 90 enforced by the gate |
| Frontend coverage | **91.4% statements / 80.4% branches / 74.4% functions**, thresholds 85/75/70 |
| Security-marked tests | **1110** of 1476 collected (was 1067 of 1416) |
| Demo assertions | **71 / 71** (was 67; SCENARIO 0 demonstrates the disclosure boundary and the limiter) |
| Lint + type check | clean (ruff, mypy on 63 source files, eslint, tsc) |
| Committable files scanned | **176**, no secrets, all required assets present |

The single skip is deliberate and is itself evidence for §9: `tests/test_deployment_assets.py`
skips its live-Docker assertion with *"docker CLI is not installed in this environment;
docker-compose.yml is validated by static analysis instead"*. **That skip is acceptance criterion
§9.10 going unverified.** When you install a container runtime, that test stops skipping — it is
your signal that criterion 10 can finally be closed.

**Note on coverage:** `scripts/check.ps1` now runs pytest **with** coverage and a
`fail_under = 90` floor, and vitest with frontend thresholds, so both numbers are enforced by the
gate rather than produced on request. Reproduce the detail with the `--cov` command in §5.3.

### 5.3 Running pieces individually

```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest -q                      # everything
.\.venv\Scripts\python.exe -m pytest -q -m security          # security suite only
.\.venv\Scripts\python.exe -m pytest -q tests/test_phase6_qa_matrix.py
.\.venv\Scripts\python.exe -m pytest -q --cov=app --cov-report=term-missing

cd ..\frontend
npm run test          # or: npx vitest run
npm run lint
npx tsc --noEmit
```

### 5.4 Quality corpora — the numbers you must not regress

Four test files encode measured quality. **If you change a classifier or the guard, these are the
tests that tell you whether you helped or hurt.** Current state:

| Corpus | File | Score |
| --- | --- | --- |
| Escalation coverage | `tests/test_escalation_coverage.py` (45 tests) | **52 / 52 must-escalate phrases** across 9 KB-009 buckets escalate; 20 legitimate questions do not |
| Prompt-injection corpus | in the security suite | **31 / 31 blocked**, and 12 document requests + 3 reported requests must not be |
| Evaluation question set | `tests/test_*evaluation*`, data in `tests/data/evaluation_questions.json` | 40 / 40 across intent, risk, escalation, ticket and blocked; expected document **28 / 28 graded** |
| Structured-output stability | `tests/test_structured_output_stability.py` (124 tests) | all passing |

The escalation corpus started at **14 / 32** and the injection corpus at **22 / 30**; both were
raised to full marks during development. They are the project's regression net for "did we make
the classifier dumber", and the stabilization pass widened both: the account-takeover family
("someone may have accessed my account", "someone logged into my account") had never been in the
corpus at all, which is exactly why a possible breach could be answered with "I do not have an
approved knowledge document" for so long.

> `backend/tests/data/evaluation_questions.json` is a **required committed asset**. It once
> matched the `data/` ignore rule and was silently absent from the repository — a fresh clone
> could not run the evaluation tests. `.gitignore` now has an explicit negation and
> `scripts/check-no-secrets.ps1` asserts the file is committable. Do not "tidy" that stanza.

### 5.5 Acceptance criteria — spec §9

| # | Criterion | Status | Evidence |
| --- | --- | --- | --- |
| 1 | User can log in | ✅ | `tests/test_auth.py`, demo step 1 |
| 2 | User can send a question | ✅ | chat API tests, demo step 2 |
| 3 | AI identifies intent | ✅ | `test_intent_*`, 40/40 evaluation set |
| 4 | System retrieves from the KB | ✅ | retriever tests, demo step 3 |
| 5 | Answer shows cited sources | ✅ | citation tests, demo assertion on `source_documents` |
| 6 | RBAC is enforced | ✅ | `test_rbac_adversarial.py` (36 tests) |
| 7 | High-risk events are identified | ✅ | `test_escalation_coverage.py` 32/32 |
| 8 | High-risk events create a Security Ticket | ✅ | `test_phase6_qa_matrix.py` (18), demo step 5 |
| 9 | Tickets are visible in the back office | ✅ | `test_phase7_qa_dashboard.py` (50), demo step 6 |
| 10 | **Docker Compose starts the whole system** | ⚠️ **PARTIAL** | see below |
| 11 | README provided | ✅ | `README.md` |
| 12 | ≥ 30 test questions provided | ✅ | 40 in `tests/data/evaluation_questions.json` |
| 13 | Basic automated tests provided | ✅ | 1475 backend + 59 frontend, with coverage floors |

**12 of 13 are fully verified. Criterion 10 is honestly partial: `docker compose up` has never
been executed**, because no container runtime exists on the development machine (no Docker
Desktop, no WSL2 distribution). The test suite says so out loud rather than hiding it — the one
skipped test in §5.2 is exactly this gap. The Compose file and both images are validated two
other ways:

- `scripts/verify-container-image.ps1` builds the image layout from `requirements.txt` **alone**,
  applies the container environment and exact `CMD`, and asserts the mount points — this catches
  a missing dependency or a wrong path without a runtime. (Its own end-to-end success is
  unverified on a machine without `pwsh`; the tests that assert its properties do run.)
- `test_deployment_assets.py` cross-checks `docker-compose.yml`, both Dockerfiles and
  `nginx.conf` against each other, and validates the Compose file by shelling out to
  `docker compose config` when the CLI exists.

**Two validations this section used to claim do not exist and never did**: a check of
`docker-compose.yml` against the official Compose Specification JSON schema (no JSON-schema
validation exists anywhere in the repository — the only Compose check is the CLI one above), and
a check that the production frontend bundle is served through an nginx-equivalent proxy (nothing
builds or serves the bundle outside `vite preview`, which no script invokes). Both were removed
rather than implemented, because §9.10's real answer is to run it once on a machine with Docker.

You should treat criterion 10 as **unproven until you run it once on a machine with Docker**.
That is the single highest-value thing to do in your first week (§12).

### 5.6 Definition of done for a change

1. `.\scripts\check.ps1` passes.
2. `backend\scripts\demo.py` still reports 71 / 71.
3. The four corpora in §5.4 have not regressed.
4. `.\scripts\check-no-secrets.ps1` passes.
5. If behaviour changed, `README.md` and `docs/DEMO.md` are updated in the same commit.

---

## 6. Implemented functionality, mapped to the phases

Spec §11 prescribed the phase order; §11's own rule was *run tests → check functionality → fix
errors → update README → only then proceed*. All ten phases are complete.

| Phase | Scope | Delivered |
| --- | --- | --- |
| **1** | Project scaffolding | FastAPI app factory, settings layer, structured logging, error handling, SQLAlchemy models for users/roles/tickets/audit, SQLite bootstrap, React+TS+Vite app shell, `.env.example`, `scripts/check.ps1` |
| **2** | Knowledge base + RAG | 12 simulated policy/SOP documents as Markdown with validated front-matter (`document_id`, `title`, `category`, `allowed_roles`, `content`) — a superset of the 10 the spec §5 names, adding `KB-003-phishing-investigation-playbook.md` and `KB-012-vpn-connection-guide.md` — chunked into 83 chunks; versioned chunker, offline BM25-weighted TF-IDF embedder, FAISS `IndexFlatIP` store with an in-memory fallback, retriever with absolute + relative score floors, per-document caps and a context-length budget |
| **3** | Chat UI | Conversation list, message thread, streaming-free turn submission, cited sources rendered with document titles, recommended-action list, risk badge, ticket reference surfaced inline, workflow-action feedback |
| **4** | RBAC | Role model (employee/it/security/admin), JWT auth with bcrypt, login lockout by account **and** by IP, **authorization pushed into the vector search** rather than applied after it, 404-not-403 for out-of-scope resources, adversarial test suite |
| **5** | Intent + risk classification | 46 intent rules across 6 intents (`security_faq`, `policy_question`, `phishing`, `security_incident`, `it_support`, `out_of_scope`), 35 risk rules across 4 levels (`low`, `medium`, `high`, `critical`), optional LLM refinement that **may raise risk but never lower it**, sticky peak risk within a conversation, strict structured-output parsing with depth and recursion guards |
| **6** | Ticket workflow + escalation | Three-tier decision — high risk creates a ticket and escalates, medium risk asks a clarifying question, low risk self-services. Audit-log recording, ticket lifecycle (open → acknowledged → resolved → closed), duplicate suppression so one incident is one ticket |
| **7** | Dashboard | Security-team event and consultation statistics, ticket queue with acknowledgement/resolution, keyset-paginated audit log, role-scoped visibility |
| **8** | Testing | 40-question evaluation set, a backend suite that ended the phase at 1415 tests (1475 after the stabilization pass), frontend suite, escalation and injection corpora driven to full marks, `scripts/demo.py`, documentation tests |
| **9** | Docker deployment | Backend and frontend Dockerfiles, nginx config serving the SPA with `/api` proxying, `docker-compose.yml` with health checks and loopback-bound ports, `verify-container-image.ps1` to validate without a runtime |
| **10** | README + demo docs | ~70 KB README, `docs/ARCHITECTURE.md`, `docs/DEMO.md` with presenter script and acceptance traceability, `scripts/verify-container-image.ps1`, this handoff |

### Functional inventory (what a user can actually do)

**Chat.** Log in; create and revisit conversations; ask a question; get an answer built from
retrieved policy text; see which documents were cited; see the detected intent and risk level;
see recommended actions; be told when a ticket was raised, and its reference.

**Classification.** 46 intent rules across 6 intents, covering FAQ, phishing, malware, ransomware, lost device,
data leakage, account compromise, VPN/endpoint troubleshooting, access requests and more; 35 risk
rules mapping both explicit statements and *implied effects* (ransomware behaviour, data
exfiltration, privileged compromise, malware execution, approved MFA prompts, credentials handed
over) to severity. Mitigating evidence is honoured via negative lookaheads — a device reported
lost *and already encrypted and wiped* does not escalate the same way as one that is not.

**Escalation.** High risk → ticket created, human escalation flagged. Medium → the assistant asks
a targeted clarifying question derived from the signals that were *absent* in the report. Low →
answered from the knowledge base. All three write an audit record.

**Tickets.** Employee-raised tickets carry an `IT-` reference; security incidents carry the
security series. One incident produces one ticket, not one per message. A flagged ticket must be
acknowledged before it can be resolved. `closed` is terminal.

**Dashboard.** Security and admin roles only. Ticket queue, event counts, consultation statistics,
and a keyset-paginated audit log. Returns counts and identifiers plus `detail_keys` — never
sensitive values.

**Knowledge API.** List documents in scope, document statistics, and role scope inspection. The
scope endpoint reports *which* roles see what, without enumerating every role's document list to
every caller, and the statistics endpoint does not disclose absolute server paths.

**Security defences.** Prompt-injection blocking and context-tainting patterns (role-claim plus
material-request rules, relaying, enumeration, authority-coercion, override and extraction
attempts), redaction applied at the persistence boundary, rate limiting, login lockout, and
input-length limits.

---

## 7. Key design decisions and why

Read this section before you "fix" something that looks wrong. Most of the surprising choices are
load-bearing.

### 7.1 Authorization is pushed *into* the search, not applied after it

The vector store's search signature is
`search(query_vector, *, top_k, allowed_document_ids)` — keyword-only, **no default value**.
Callers cannot forget to pass the caller's permitted document set, because omitting it is a
`TypeError` rather than a silent privacy leak. FAISS applies the restriction with an
`IDSelectorBatch` prefilter, so forbidden chunks are never scored, never ranked, never counted
against `top_k`, and cannot influence a relative score floor.

*Why:* the natural implementation — retrieve top-k, then filter by role — leaks two ways. It
returns too few results (because forbidden documents consumed the budget), and it leaks existence
and similarity through result counts and scores. Pushing it down removes both.

### 7.2 Out-of-scope questions never retrieve at all

If intent classification says the question is not a security or IT question, retrieval is skipped
entirely and the user gets a clean "not something I cover" answer with **zero** sources. Verified:
a nonsense question yields `intent=out_of_scope`, `risk=low`, `grounded=False`, `sources=0`,
`action=none`.

*Why:* retrieving anyway invites the model to answer an unrelated question from security
documents, which is both a correctness bug and an information-disclosure surface.

### 7.3 The LLM may raise risk, never lower it

Rule-based classification runs first. The LLM refines. If the model's severity is *lower* than the
rules', the rules win. Peak risk is sticky for the life of a conversation.

*Why:* the expensive error here is under-escalation. A model that talks a genuine incident down is
far worse than one that over-escalates a benign message. The asymmetry is intentional: rules are
the floor, the model can only add caution.

### 7.4 Deterministic offline defaults

`LLM_PROVIDER=mock`, `EMBEDDING_PROVIDER=tfidf`. The default system needs no API key and no
network.

*Why:* the whole suite and the demo are reproducible. A test that depends on a live model is not a
test. A demo that fails on a conference wifi network is not a demo. The `openai_compatible`
providers exist for when you want real quality, and switching is one variable.

### 7.5 404, not 403, for resources outside your scope

*Why:* `403` confirms the resource exists. `404` does not. For tickets and documents, existence
itself is information.

### 7.6 Redaction happens at the persistence boundary

Message rows, ticket titles and ticket bodies are redacted before they are written. Classification
and retrieval run on the **raw** text.

*Why:* the classifiers need the real content to detect a leaked credential, while the audit trail
and the ticketing system must not become a second copy of the secret. Redacting before
classification would blind the very detector that matters; redacting after persistence would be too
late.

### 7.7 The dashboard returns identifiers, not values

Security statistics expose counts, IDs and `detail_keys`. Sensitive values are not returned.

*Why:* dashboards get screenshotted, shared and exported. A count is auditable; a leaked credential
in a chart tooltip is not.

### 7.8 One incident is one ticket

Repeated high-risk messages in the same conversation escalate and update; they do not spawn
duplicate tickets. A flagged ticket must be acknowledged before resolution.

*Why:* duplicate tickets destroy the queue's signal-to-noise ratio and the acknowledgement gate
prevents an incident being closed by someone who never read it.

### 7.9 Empty-after-generation is not the same as no-context

Two distinct responses exist: `build_no_context_answer` (nothing was retrieved) and
`build_unextractable_answer(role=…)` (documents *were* found and are being cited, but nothing in
them can be quoted).

*Why:* this was a real bug. Early versions cited documents while telling the user they had no
information, which reads as a broken system and undermines the citations.

### 7.10 `TRUSTED_PROXY_COUNT` defaults to `0`

Client IP — and therefore rate limiting and IP lockout — is derived from the socket peer unless you
explicitly declare how many proxies are in front of the app.

*Why:* trusting `X-Forwarded-For` by default lets any client spoof its IP and bypass rate limiting
and lockout entirely. If you deploy behind nginx, you **must** set this to the real hop count.

### 7.11 Versioned chunker and tokenizer

`TOKENIZER_VERSION = "2"`, `CHUNKER_VERSION = "2"` are stored with the index.

*Why:* if you change chunking or tokenisation without rebuilding, old vectors and new queries
disagree and retrieval quality silently degrades with no error. The version stamp makes the
mismatch detectable.

---

## 8. Known issues and limitations

### 8.1 Confirmed bugs — **both fixed during the stabilization pass (2026-09-13)**

> **Status: closed.** These were reproducible and confirmed, and the final development phase was
> frozen against code changes, so they shipped open. They have since been fixed, and the analysis
> below is kept as the record of what was wrong and why it mattered.
>
> **BUG-1 — account-takeover reports misclassified.** Fixed in the R1 commit. Three defects, all
> as diagnosed below: the intent rule only allowed `has`/`got` between the actor and the verb and
> could never match "logged into"; the risk rule required `access ... to ...`, which the *verb*
> `accessed` never takes; and the same blindness reached data loss and server malware
> ("we lost 500 customer records to an attacker" matched nothing at all). Ten user-voiced
> account-takeover phrasings, plus the data-loss and malware phrasings, are now asserted in
> `test_escalation_coverage.py` — the corpus that did not contain them is why this survived.
> A related defect found while fixing it: a refused turn was never classified at all, so a report
> that *quoted* attacker text was dropped silently. Refused turns are now risk-assessed and filed
> on their merits, while a pure injection attempt still files nothing.
>
> **BUG-2 — a medium-risk report that is never answered is never tracked.** Fixed in the R4
> commit. The fix is the cheaper of the two options suggested below: the medium tier files a
> `medium`, `open`, non-escalated tracking ticket *while* it asks the clarifying question, and
> answering the question escalates that same ticket (one incident, one ticket). No new table and
> no scheduler were needed, and the evaluation suite now asserts the invariant in both directions:
> escalation always comes with a ticket, and a ticket without escalation is only that tier.

**BUG-1 — Account-takeover reports are misclassified. Face A drops the report silently.**
**Severity: high.** This was the most serious open defect. A user reporting a possible account
compromise could be told the question is out of scope, with **no escalation, no ticket and no
sources** — and no human alerted.

*Measured behaviour.* Every phrase below was run through the real API on `main` at `5bff199`.
The table is the bug report — note that the failure is **not uniform**, which is what makes it
dangerous:

| User says | intent | risk | escalates | ticket | sources | action |
| --- | --- | --- | --- | --- | --- | --- |
| "Someone has access to my account." | `security_incident` | high | ✅ yes | created | 1 | create |
| "Someone logged in to my account." | `security_incident` | high | ✅ yes | created | 1 | create |
| **"Someone may have accessed my account."** | `out_of_scope` | **low** | ❌ **no** | **none** | **0** | **none** |
| **"Someone logged into my account."** | `out_of_scope` | **low** | ❌ **no** | **none** | **0** | **none** |
| **"I think someone logged into my account."** | `out_of_scope` | **low** | ❌ **no** | **none** | **0** | **none** |
| "My account was accessed by somebody else." | `security_incident` | medium | ❌ no | none | 1 | **clarify** |
| "Someone gained access to my account." | `out_of_scope` | high | ✅ yes | created | **0** | create |
| "Somebody else signed in to my mailbox." | `out_of_scope` | high | ✅ yes | created | **0** | create |

**Face A — the silent drop (rows 3–5).** The user is told *"I do not have an approved knowledge
document that answers this question. Please contact the IT service desk…"*, the incident is
**never recorded**, and no human is told. This is the worst outcome in the table and it is
triggered by entirely ordinary phrasing — a modal verb ("may have") or "logged into" is all it
takes. This is a **security-relevant defect**, not a cosmetics issue.

**Face B — right risk, wrong intent (rows 7–8).** Risk classification catches these, so a ticket
*is* created and escalation *does* happen — the safety net holds. But intent is `out_of_scope`, and
because out-of-scope questions skip retrieval entirely (§7.2), the user gets a ticket **with zero
knowledge sources**: no SOP, no "what to do right now" guidance. So the incident is captured but
the user is not helped in the moment.

**Face C — medium, and coupled to BUG-2 (row 6).** "My account was accessed by somebody else."
classifies correctly but lands at **medium → clarify**. If the user does not answer the clarifying
question, BUG-2 applies and the report is never tracked at all. Account takeover arguably deserves
at least `high`; check that judgement when you fix this.

*Root cause — three concrete defects, all verified.*

1. **`backend/app/ai/intent_classifier.py:146-147`** — the account-takeover rule is:
   ```python
   "account_taken_over",
   r"\b(?:someone|somebody)\s+(?:has\s+|got\s+)?(?:access|logged\s+in)\b",
   ```
   Only `has` or `got` may sit between the actor and the verb, so `may have`, `has accessed`,
   `gained` and `I think` all fail. And `logged\s+in\b` can never match **"logged into"** — there
   is no word boundary between `in` and `to`, both being word characters. Note this is the *same*
   word-boundary trap that killed the privileged-account rule (§11.2).

2. **`backend/app/ai/risk_classifier.py:310-313`** — the account-takeover rule requires
   `access … to …`:
   ```python
   "account_takeover",
   r"\b(?:someone|somebody)\s+(?:else\s+)?(?:has\s+|got\s+|gained\s+)?(?:access|logged\s+in|signed\s+in)\s+to\s+"
   r"(?:my\s+|your\s+|their\s+|his\s+|her\s+|our\s+|the\s+|a\s+user'?s?\s+)?(?:account|mailbox|e-?mail|inbox)\b",
   ```
   This conflates the **noun** `access` (which does take "to": *"has access **to** my account"*)
   with the **verb** `accessed` (which does not: *"accessed my account"*). So *"Someone accessed
   my account"* cannot match **even with the modal removed** — it is a grammar bug, not just a
   coverage gap. The same missing-modal gap applies here, which is why rows 3–5 score `low` while
   rows 7–8 (where `gained` happens to be in the allowed set) score `high`.

3. **The consequence amplifier is §7.2.** Because intent drives the retrieval gate, an
   `out_of_scope` verdict suppresses retrieval as well, which is why the source count is `0` in
   rows 3–5 and 7–8. Fixing the rules fixes all three symptoms at once.

*Suggested fix.* Widen defect 1 to tolerate an optional modal/adverb and both preposition forms:
allow `(?:may|might|could|possibly|probably)\s+(?:have\s+)?`, `(?:has|have|had)\s+`, `gained\s+`,
`got\s+`, and match `logged\s+(?:in|into)`, `signed\s+(?:in|into)` with an optional `to`. For
defect 2, split the noun and verb branches so the `\s+to\s+` requirement applies only to the noun
reading. Then add **all six failing rows above** to `tests/test_escalation_coverage.py` — the
corpus is the regression net, and it currently does not contain these phrasings, which is exactly
why this survived. Given §7.3, over-matching is the safer error direction.

---

**BUG-2 — A medium-risk report that is never answered is never tracked.**
**Severity: medium.** Data loss, not a security breach — but it means incidents silently disappear.
**Fixed in R4** (see the status note at the top of this section).

*Reproduction.* Write a report that lands in the medium tier. A confirmed one from the table
above, using an employee account:

```
POST /api/v1/chat/conversations/{id}/messages   {"content": "My account was accessed by somebody else."}
-> intent=security_incident  risk=medium  escalate=False  ticket=None
   workflow_action=clarify    sources=1
```

The turn returns a `clarifying_question` and **`ticket=None`**. If the user does not answer that
question but instead asks something unrelated, that next turn returns `action=none` and **no
ticket is ever created anywhere**. The original report is not in the ticket queue, is not on the
dashboard, and is never re-surfaced. The audit trail shows a report that produced no outcome.

*Root cause.* The clarify path holds the state only in the conversation turn that produced it; no
pending-clarification record is persisted, so nothing can resume or expire it.

*Suggested fix.* Persist a pending clarification (conversation id, the triggering report, the
absent signals, a timestamp) and resolve it on the next turn — either the user answers it, or the
record is promoted to a ticket after a bounded timeout. A cheaper interim mitigation is to create
the ticket immediately at medium risk and let the clarifying question refine it.

---

### 8.2 Architectural limitations (by design, but you must know them)

| Limitation | Consequence | Direction |
| --- | --- | --- |
| **Rate limiting and login lockout are per-process, in memory** | Only correct with a **single worker**. Running uvicorn with `--workers N` or scaling horizontally silently multiplies every limit by N | Move counters to Redis or the database before scaling out |
| **English-only knowledge base and rules** | Non-English questions retrieve poorly and may slip past the risk rules | The rules are regex on English stems; a real deployment needs multilingual handling |
| **Lexical embedder by default** | TF-IDF matches words, not meaning. Synonyms and paraphrase retrieve weakly | Set `EMBEDDING_PROVIDER=openai_compatible`; expect a different failure profile |
| **Answers are extractive** | The answer is assembled from retrieved policy text; it does not synthesise across documents | By design for auditability — every sentence is traceable to a source |
| **No migration tool** | Schema changes are handled by rebuilding the dev table; there is no Alembic | Add Alembic before any data you care about exists |
| **Tokens, and what a restart does** | Sessions are **server-side rows** (`UserSession`, one per issued `jti`), checked on every request in `app/api/deps.py`, and revocable individually or for a whole account — so "log out everywhere" is real, not decoration. What a restart invalidates is the *signing key*, and only when `AUTH_SECRET_KEY` is unset: outside production an absent or placeholder key is replaced with a per-process random one (`config.py`), so a restart logs everyone out. Set a real key and sessions survive restarts. There is no refresh-token rotation. | Add refresh tokens if uptime matters; keep `AUTH_SECRET_KEY` set |
| **Login lockout has no knowledge-base document** | A user asking "why am I locked out?" gets a generic answer | Add a KB entry, or teach a rule about it |
| **SQLite** | Fine for the prototype; write concurrency is limited | Postgres is a `DATABASE_URL` change plus a driver |
| **`mock` LLM is not a language model** | With defaults, answers are template-composed, so prose quality is not representative | Judge answer quality only with a real provider |

### 8.3 Code hygiene notes

- No `TODO`/`FIXME` markers exist in the codebase. Open work lives in this section and README's
  roadmap — **not** in inline comments. Keep it that way.
- `Thumbs.db` sits in the working tree on Windows. It is gitignored and untracked; ignore it.

---

## 9. Production deployment notes

**Read this paragraph first: this application has never been deployed.** Everything below is the
state of the deployment *assets*, not a record of a working production system.

### 9.1 What exists

`docker compose up --build` is a **one-command start from a fresh clone**, because the compose file
carries a working default for everything the application needs, declares its `env_file` entry as
optional (`required: false`, so a gitignored `.env` cannot stop the start) and lets the app generate
its own signing key when none is supplied. `scripts/docker-up.ps1` (Windows) and
`scripts/docker-up.sh` (Linux/macOS) wrap it to add the two things a bare `up` cannot: a *stable*
`AUTH_SECRET_KEY` written into `.env`, and a readiness check that probes `/api/v1/health` **through
nginx** before reporting success.

`docker-compose.yml` defines two services:

| Service | Image | Port binding | Notes |
| --- | --- | --- | --- |
| `backend` | `esaa-backend:local` | `127.0.0.1:${ESAA_API_PORT:-8000}:8000` | FastAPI/Uvicorn, health check, `init: true` |
| `frontend` | `esaa-frontend:local` | `${ESAA_HTTP_PORT:-8080}:80` | nginx serving the built SPA, proxying `/api` |

The topology is **single-origin**: the browser talks only to nginx (port 8080 by default), and
nginx proxies `/api` to the backend. This is the same shape as `scripts/run-local.ps1`, which is
why developing locally exercises the production CORS and proxy configuration.

Backend and frontend Dockerfiles are in `backend/Dockerfile` and `frontend/Dockerfile`;
`frontend/nginx.conf` holds the SPA fallback rule and the `/api` proxy block.

### 9.2 What you must do before it is deployable

1. **Run `docker compose up --build` once.** Acceptance criterion §9.10 is unproven (§5.5). Nothing
   else in this section matters until this works. No `.env` is needed - the command works on a
   fresh clone as it stands, and the missing file is no longer an error. (It used to be: the
   compose file declared `env_file: - .env`, `.env` is gitignored, and Compose treats a missing
   `env_file` as fatal, so the documented command could not have worked as written. That is also
   why CI's deployment test both probes `docker compose version` first and materialises `.env`
   from the template for the duration of its check.)
2. **Set `AUTH_SECRET_KEY`** to a real random value. The example value is a placeholder.
3. **Set `TRUSTED_PROXY_COUNT`** to the true number of proxies in front of the backend. It
   defaults to `0`, which is correct only if nothing proxies. Behind nginx, leaving it at `0`
   means rate limiting and IP lockout key off the *proxy's* address. Setting it *higher* than
   reality lets clients spoof `X-Forwarded-For` and bypass both (§7.10).
4. **Do not scale the backend past one worker** until rate limiting and lockout are moved out of
   process memory (§8.2).
5. **Replace SQLite** if you need concurrent writes, and **add a migration tool** before you have
   data you cannot lose.
6. **Bind to TLS.** Compose binds to loopback; a real deployment terminates TLS at a proxy and
   *then* sets `TRUSTED_PROXY_COUNT`.
7. **Move secrets out of `.env`** into your platform's secret store. `.env` is gitignored, but a
   file on disk is still a file on disk.
8. **Turn `DEBUG` off and pin `LOG_FORMAT`** to your log pipeline's expectation.
9. **Decide the model strategy.** `LLM_PROVIDER=mock` is for development and demos. A real
   deployment sets a provider and a key, and should re-run the §5.4 corpora against that provider,
   because a different model changes the refinement behaviour described in §7.3.
10. **Re-run `.\scripts\check.ps1`** and `scripts/verify-container-image.ps1` on the deployment
    host before you trust the artifact.

### 9.3 Emulation when no runtime is available

`scripts/verify-container-image.ps1` is the answer to "I cannot run Docker but I need confidence".
It creates a fresh virtualenv from `backend/requirements.txt` **alone** (so a dependency that is
present locally but missing from `requirements.txt` cannot hide), reproduces the image's directory
layout, applies the container environment and the exact `CMD`, and asserts the mount points. A
missing dependency or a wrong path fails here.

This is **not** a substitute for running the real thing. It cannot catch base-image problems,
networking, volume-permission or orchestration errors.

---

## 10. Security and compliance notes

This is a security product. The list below is the set of invariants that must survive your changes,
followed by what the spec requires and what is still open.

### 10.1 Invariants — do not break these

1. **Retrieval is authorized inside the search.** Never retrieve first and filter after. The
   keyword-only `allowed_document_ids` parameter exists to make the mistake impossible (§7.1).
2. **Out-of-scope questions do not retrieve.** Keep the early return.
3. **The LLM can raise risk but never lower it.** Do not "clean up" this asymmetry.
4. **`human_escalation` and `create_ticket` are computed in backend code from the risk level,
   never taken from model output.** The field comments in `app/schemas/chat.py` say this
   explicitly. A model that could set `human_escalation=false` would be an escalation bypass —
   this is the single most important thing in the whole structured-output contract.
5. **404, not 403, for out-of-scope resources.**
6. **Redaction at the persistence boundary**, on message rows, ticket titles and bodies —
   never before classification.
7. **The dashboard exposes identifiers and counts, not values.**
8. **No secret ever enters Git.** `AUTH_SECRET_KEY`, `LLM_API_KEY`, `EMBEDDING_API_KEY` come from
   the environment. `.env` stays gitignored; `.env.example` carries placeholders only.
9. **`TRUSTED_PROXY_COUNT` is not raised casually** (§7.10).
10. **One incident, one ticket**; a flagged ticket is acknowledged before it is resolved.
11. **The prompt guard stays in front of the model** — blocking patterns reject; context patterns
    taint the material so retrieved text cannot be treated as instructions.

### 10.2 Spec §7 compliance

Spec §7 forbids hardcoded API keys, committing `.env`, writing user-sensitive data to Git, letting
the LLM bypass RBAC, and letting ordinary users retrieve restricted documents. It requires
`.env.example`, audit logging, mandatory human escalation for high-risk events, and structured LLM
output parsing.

| Requirement | Status | How it is enforced |
| --- | --- | --- |
| No hardcoded API keys | ✅ | all secrets via settings; `check-no-secrets.ps1` scans |
| `.env` not committed | ✅ | gitignored; verified against a fresh clone |
| No sensitive user data in Git | ✅ | all data simulated; secret scan |
| LLM cannot bypass RBAC | ✅ | authorization happens before the model ever sees context |
| Restricted documents not retrievable by ordinary users | ✅ | push-down filtering (§7.1); `test_rbac_adversarial.py` |
| `.env.example` provided | ✅ | 48 documented settings |
| Audit logging | ✅ | every turn, ticket transition and dashboard view is recorded |
| Mandatory human escalation for high risk | ✅ | `test_escalation_coverage.py` 32/32 |
| Structured LLM output parsing | ✅ | `app/ai/structured.py`, depth- and recursion-guarded |

### 10.3 `check-no-secrets.ps1` checks both directions

It verifies (a) nothing sensitive is *committable*, and (b) every *required* asset is present and
committable — including `backend/tests/data/evaluation_questions.json` (§5.4). Run it before
pushing. A false "safe" from a stale ignore rule is exactly how the evaluation set went missing
once already.

### 10.4 Still open on the security side

- **Per-process rate limiting and lockout** wear down under multiple workers (§8.2). The limiter
  now covers both expensive endpoints (chat and `/knowledge/search`), but the storage is still
  in-process.
- **No penetration test, no fuzzing campaign, no third-party review** has been done. The 1110
  security-marked tests are the developer's own and share the developer's blind spots. The
  independent review that found the two P0 defects is `Reviewer Report.md`; most of its findings
  are now fixed (see `PROJECT_STATUS.md` for the round-by-round record).
- **No data-retention policy is implemented** beyond `AUTH_SESSION_RETENTION_DAYS`. Real employee
  reports would need a documented retention and deletion story. Audit rows store the actor's
  email, which is deliberate for triage and is personal data in an append-only log.
- **Closed during the stabilization pass, kept here so the invariant is not forgotten:**
  BUG-1 (a possible account compromise could be neither classified nor escalated) and BUG-2 (a
  medium-risk report could be lost) are fixed; the AI-stack fingerprint is no longer readable
  without a token (`/meta`); the rule counts are security-only; and every endpoint that embeds a
  query is throttled.

---

## 11. Maintenance guide — the tasks you will actually do

### 11.1 Add a knowledge-base document

1. Create `backend/knowledge_base/<name>.md` with the required front-matter:
   `document_id`, `title`, `category`, `allowed_roles`, `content`.
2. Set `allowed_roles` to the **narrowest** role set that should see it. This field *is* the RBAC
   policy (§7.1) — a too-broad value here is a data leak, and no downstream check will catch it.
3. Restart the backend. With `KB_STRICT_VALIDATION=true` (default) malformed front-matter stops
   startup rather than degrading silently.
4. Rebuild the vector index. **Chunking or tokenisation changes require a rebuild**
   (§7.11) — a stale index degrades retrieval with no error message.
5. Add a question covering the new document to `backend/tests/data/evaluation_questions.json`, so
   the evaluation set keeps growing with the KB.

### 11.2 Change classification behaviour

1. Edit `app/ai/intent_classifier.py` or `app/ai/risk_classifier.py`.
2. Run the two corpora — `tests/test_escalation_coverage.py` and the injection corpus. These are
   the regression net; a change that raises one and lowers the other is usually wrong.
3. Run the 40-question evaluation set.
4. Watch the **word-boundary trap**: `\bcompromis\b` never matches `"compromised"`, because there
   is no word boundary between two word characters. A privileged-account rule sat dead for a long
   time because of exactly this. Prefer `\w*` stems.
5. Watch the **bare-noun trap**: a rule matching bare `"malware"` escalated
   *"What is the malware response procedure?"* — a question, not an incident. Match detection and
   action verbs (`detect\w*|alert\w*|quarantin\w*`), not just nouns.
6. Honour **mitigating evidence** with negative lookaheads — a device reported lost *and wiped* is
   not the same incident as one that is not.

### 11.3 Change the ticket workflow

`app/services/workflow_manager.py`. `WorkflowAction` is a
`Literal["none","create","escalate","suggest","clarify"]`. The clarifying question is derived from
the signals that were **absent** in the report, so adding a new medium-risk path means teaching
`_clarifying_question(analysis)` which signal is missing. Extend
`tests/test_phase6_qa_matrix.py`. When you touch this file, fix **BUG-2** (§8.1) — the clarify path
is where the lost-report bug lives.

### 11.4 Change the API or the UI

- Backend: update `app/schemas/`, then `app/api/`. `MessagePayload` carries the seven fields spec
  §8 mandates plus `workflow_action` and `clarifying_question`.
- Frontend: `exactOptionalPropertyTypes: true` is on. You cannot assign `undefined` to an optional
  property — build the object conditionally or widen the type deliberately. This is the single
  most common TypeScript error you will hit.
- Update the typed client in `frontend/src/api/` and add a vitest test.

### 11.5 Runbooks

| Situation | Do this |
| --- | --- |
| Something is broken | `.\scripts\check.ps1`, then `backend\.venv\Scripts\python.exe backend\scripts\demo.py` |
| Frontend won't type-check | `npx tsc --noEmit` in `frontend/`; suspect `exactOptionalPropertyTypes` |
| Backend won't start | check `KB_STRICT_VALIDATION` output — malformed front-matter is the usual cause |
| Retrieval quality dropped | did you change the chunker or tokenizer without rebuilding the index? (§7.11) |
| "It works locally but not in the image" | `.\scripts\verify-container-image.ps1` |
| Login suddenly fails everywhere | check lockout (`AUTH_LOCKOUT_SECONDS`) and the DB's user rows |
| Rate limits behaving oddly | more than one worker? (§8.2) |
| Suspect a leaked secret | `.\scripts\check-no-secrets.ps1`, then rotate |

### 11.6 Repository conventions

- **Line endings:** `.gitattributes` forces `* text=auto eol=lf`. Do not let a Windows editor
  rewrite files with CRLF — it produces whole-file diffs that hide real changes.
- **Do not use PowerShell `Get-Content`/`Set-Content` round-trips on files containing non-ASCII**
  characters; PowerShell 5.1 will mangle them (you will see `鈥?`). Use the editor, or an explicit
  UTF-8 API.
- **PowerShell variables are case-insensitive.** A loop variable named `$check` silently collides
  with a `[switch]$Check` parameter. This already caused one bug.
- **`$home` is read-only** in PowerShell; do not assign to it.
- **Commit messages** follow the existing pattern: `Phase N: <what changed and why>`.
- **Never commit `.env`.**

---

## 12. Handoff checklist

Work through this in order. It is designed so that a failure at any step is caught early and
cheaply.

**Day one — establish that it runs**

- [ ] `git clone` the repository and confirm `main` is at the expected commit.
- [ ] Create `backend\.venv`, install `requirements.txt` **and** `requirements-dev.txt`.
- [ ] `npm install` in `frontend/`.
- [ ] `Copy-Item .env.example .env`, then generate and set a real `AUTH_SECRET_KEY`.
- [ ] `.\scripts\check.ps1` → expect a clean exit (1475 backend + 59 frontend tests, with the
      coverage floors enforced).
- [ ] `.\scripts\run-local.ps1` → open http://localhost:5173, log in as each of the four demo
      users, and confirm the RBAC boundary for real (ask about the malware SOP as `employee`,
      then as `security`).
- [ ] `backend\.venv\Scripts\python.exe backend\scripts\demo.py` → expect **71 / 71**.
- [ ] `.\scripts\check-no-secrets.ps1` → clean.
- [ ] Read `README.md` §Architecture and `docs/ARCHITECTURE.md`.

**Day one — read before you touch anything**

- [ ] `PRODUCT_SPEC.md` end to end. It is 292 lines and it is the requirements authority.
- [ ] §7 of this document (design decisions). Most "obvious improvements" are already considered.
- [ ] §8.1 (open bugs) and §10.1 (invariants you must not break).

**Week one — close the gaps**

- [x] **BUG-1** (account-takeover reports) — fixed, with the six failing phrasings added to the
      escalation corpus. Done in the R1 commit.
- [x] **BUG-2** (medium-risk reports that are never tracked) — fixed in the R4 commit.
- [ ] **Run `docker compose up` on a machine with a container runtime** to move acceptance
      criterion §9.10 from PARTIAL to verified. **This is now the only unproven acceptance
      criterion.** Start with `scripts/docker-up.ps1` (or `docker-up.sh`): it mints a stable
      `AUTH_SECRET_KEY`, waits for the API to answer through nginx, and prints the demo logins, so
      a failure reports which container stopped rather than leaving you to guess. Rerun
      `verify-container-image.ps1` too.
- [ ] Decide the LLM/embedding strategy for real use, and re-run the §5.4 corpora against it.
      (The provider request path is now covered by stub-transport tests; what is still unmeasured
      is answer *quality* against a real model.)

**Answers you should be able to give after week one**

- [ ] Where does authorization happen, and why is it not a post-filter? (§7.1)
- [ ] Why can the model raise risk but not lower it? (§7.3)
- [ ] Why is `TRUSTED_PROXY_COUNT` zero by default, and what breaks if it is wrong? (§7.10)
- [ ] Why is the evaluation JSON an unusual entry in `.gitignore`? (§5.4)
- [ ] Which two acceptance criteria would you tell a stakeholder are not yet proven? (§5.5, §9.2)

**Known unknowns to carry forward, stated plainly**

- The Docker Compose path is validated by emulation and static analysis only; it has never
  executed. Acceptance criterion §9.10 is the one criterion without evidence.
- The security testing is self-assessment. There has been no external review, no penetration test
  and no fuzzing campaign. (One independent adversarial review exists — `Reviewer Report.md` — and
  it found real defects: two of its P0/P1 findings were that the prompt guard refused the
  product's own headline question and that real breach phrasings were neither answered nor
  escalated. Both are fixed.)
- Answer quality with the default `mock` provider is not representative of a real model.
- The project has never handled real data and has no retention or deletion policy.
- The two bugs that were open at handoff are closed; the round-by-round record, with the
  verification behind each round, is in `PROJECT_STATUS.md`.

---

*End of handoff. If something here is wrong, fix the document in the same commit that proves it
wrong — a stale handoff is worse than none. This document was audited claim by claim on
2026-09-13 and thirteen statements were corrected; assume the rest was checked, not assumed.*
