# PROJECT STATUS — Enterprise Security AI Assistant

**Current Phase:** Stabilization (defect repair, no new features)
This file is the running state of the project. It is updated at the end of every work
round, in the same commit as the change it describes. The requirements authority is
`PRODUCT_SPEC.md`; the inherited engineering record is `PROJECT_HANDOFF.md`; the
independent defect register is `Reviewer Report.md`.

---

## Completed

**Product phases** (`PRODUCT_SPEC.md` §11) — all ten shipped at commit `5bff199`:

- [x] Phase 1 — project scaffolding
- [x] Phase 2 — knowledge base + RAG
- [x] Phase 3 — chat UI
- [x] Phase 4 — RBAC
- [x] Phase 5 — intent + risk classification
- [x] Phase 6 — ticket workflow + escalation
- [x] Phase 7 — dashboard
- [x] Phase 8 — testing
- [x] Phase 9 — Docker deployment assets
- [x] Phase 10 — README + demo documentation

**Verification pass** (read-only, no code changed):

- [x] Architecture, functionality and P0–P3 findings re-verified by execution, not by reading
- [x] `PROJECT_HANDOFF.md` claims checked against the repository (13 inconsistencies found;
      documentation repairs are scheduled as Round 6)

## Current

**Round 1 — the silent-drop family — DONE**

- [x] P0-01 (Reviewer P0-1) — guard refused legitimate policy questions: "Show me the password
      policy" (spec §2 scenario A) was blocked as `secret_extraction`. A credential noun followed
      by a document noun is now left to retrieval and RBAC; only a value request is an extraction.
- [x] P1-01 (Reviewer P1-1 / BUG-1) — account takeover reported in ordinary words
      ("someone may have accessed my account", "someone logged into my account") fell to
      `out_of_scope`: unanswered, unescalated, unfiled. Intent and risk rules fixed; modal verbs
      and both preposition forms are tolerated, and the noun/verb grammar conflation is split.
- [x] NEW — blocked turns were never classified: a report that *quotes* attacker text was refused
      and then dropped. A refused turn is now still risk-assessed and still filed when a person is
      needed; a pure injection attempt still files nothing. Reported third-party requests are
      answered rather than refused; a reported override is still refused.
- [x] P1-01b — data loss and server malware in the words people use ("We lost 500 customer records
      to an attacker", "There is a strange process running on the server", "Someone installed a
      keylogger on my machine") now score S1/S2 per KB-009 instead of `out_of_scope`/`low`.
- [x] Duplicate intent rule removed (`privileged_account_at_risk` was listed twice, double-counting
      its weight).
- [x] Regression corpora extended: 12 document requests + 3 reported requests + 3 reported
      overrides (guard), and 4 new escalation buckets (52 S1/S2 phrasings, 9 buckets).
- [x] README + `docs/ARCHITECTURE.md` rule counts and guard section corrected to the measured
      reality.

**Round 2 — the configuration the tests measure is the configuration that ships — DONE**

- [x] P0-02 (Reviewer P0-2) — `OpenAICompatibleLLMClient.complete` was executed by nothing at all
      (`app/ai/llm.py` 84%, whole method missed). 14 stub-transport tests now cover request
      construction, the retry loop, the empty-response and non-JSON paths, and the error contract
      that must not leak the provider's text. **`llm.py` is now 98% covered**, and every line of
      `complete()` is exercised.
- [x] P0-02 (documentation half) — the `mock`/offline default is now disclosed in the README's
      opening section, with the way out (`LLM_PROVIDER=openai_compatible`), and a documentation
      test fails if that disclosure is ever buried again.
- [x] P1-02 (Reviewer P1-2) — test config ≠ shipped config. The local `.env` had drifted to
      `RETRIEVAL_RELATIVE_FLOOR=0.7` / `RETRIEVAL_TOP_K=5` while every test and `.env.example`
      used `0.5` / `6`, so expected-document recall was 25/28 on the running product and 28/28 in
      the suite — and the README published the suite's number. `.env` realigned and the README
      corrected to the measured figures.
- [x] "29 / 29" corrected to **28 / 28** (the evaluation set has 28 graded questions, not 29) in
      the README and `docs/DEMO.md`.
- [x] A drift guard now asserts that the code default, `.env.example`, and the README settings
      table agree for the six published defaults — it caught a second live drift
      (`RETRIEVAL_TOP_K` documented as 5) on its first run.

**Scheduled** (severity order; one round per commit):

- [ ] P1-03 (Reviewer P1-3) — anonymous `/api/v1/meta` discloses the AI stack. Round 3
- [ ] P1-04 (Reviewer P1-4) — `/knowledge/search` embeds unthrottled. Round 3
- [ ] P1-05 (Reviewer P1-5) — ticket `statistics` capped at 200 rows and not queue-scoped. Round 4
- [ ] P1-06 (Reviewer P1-6) — self-raised tickets ignore `category`, always IT/low, read-only.
      Round 4
- [ ] BUG-2 (handoff §8.1) — a medium-risk report whose clarification is never answered is never
      tracked. Round 4
- [ ] P1-07 (Reviewer P1-7) — dead and value-blind frontend assertions, no frontend coverage
      tooling, no CI. Round 5
- [ ] Round 6 — documentation: the WRONG/drift items in `PROJECT_HANDOFF.md`, and committing the
      handoff + reviewer report

**Decisions taken** (previously open questions):

1. *Employee ticket statistics* — reads keep the documented "the creator always sees their own
   ticket" policy, but **counts become queue-scoped and computed in SQL**: SECURITY counts
   everything, IT counts its own queue, an employee never counts security-owned rows. Removes both
   the 200-row truncation and the disclosure of security-queue state to a non-security role.
2. *Blocked turns* — the guard decides whether the assistant **answers**, never whether a person is
   **told**. Refused turns are risk-assessed and escalated on their merits; the refusal text is
   unchanged; the guard's own block keeps a medium floor.
3. *Real LLM path* — documentation-first, no behaviour change: `mock` disclosure moves into the
   README's opening section and `OpenAICompatibleLLMClient.complete` gets stub-transport tests.
   Wiring a live provider is a product decision, not a defect repair.

## Tests

| Gate | Result |
| --- | --- |
| `scripts/check.ps1` (ruff, mypy, pytest, tsc, eslint, vitest, secret scan) | **exit 0** |
| Backend `pytest -q` | **1463 passed, 1 skipped** (started at 1415/1) |
| Backend coverage `--cov=app` | **95%** (4128 statements, 214 missed); `app/ai/llm.py` **84% → 98%** |
| Frontend `npm test` | **59 passed** (2 files) |
| `security`-marked tests | 1067 → re-measured in Round 5 |
| `backend/scripts/demo.py` | **67 / 67 checks passed** |
| Evaluation set (40 questions, live API) | intent 40/40, risk 40/40, escalation 40/40, ticket 40/40, blocked 40/40, **expected document 28/28** (was 25/28 before the config realignment) |
| Escalation corpus | **52 / 52** S1/S2 phrasings escalate; 20 legitimate questions do not |
| Injection corpus | **31 / 31** blocked; 12 document requests + 3 reported requests not blocked |
| Config drift guard | code default == `.env.example` == README settings table, for the six published defaults |
| `scripts/check-no-secrets.ps1` | OK, 175 files, all required assets present |

The single skip is `tests/test_deployment_assets.py:436` — the Docker CLI is absent on this
machine, so acceptance criterion §9.10 (`docker compose up`) remains **unproven**, exactly as the
handoff states.

## Current Branch

`main` (remote `origin` = `git@github.com:Ksanadu/enterprise-security-ai-assistant.git`)

## Last Verified

2026-09-13 — Round 1, on Windows PowerShell 5.1, Python 3.12.10, Node 24.19.0.
(`pwsh` is not installed on this machine; use `powershell -ExecutionPolicy Bypass -File scripts\check.ps1`.)
