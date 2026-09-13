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

**Round 3 — what an anonymous caller may learn, and one limiter for one primitive — DONE**

- [x] P1-03 (Reviewer P1-3) — `GET /api/v1/meta` needed no token and returned the AI stack
      fingerprint (provider, model, embedding backend, vector store, retrieval `top_k`) plus
      demo-login/seed state. An anonymous caller now gets name, version, environment, feature
      flags and the role list; nothing else. Verified live: the response contains no AI key at all.
- [x] P1-03 (second half) — operational detail moved to the *authenticated*
      `GET /api/v1/chat/capabilities` (generator, vector store, `top_k`), and the rule counts
      inside it are now visible only to the security role. An employee gets capability flags
      (guard on/off, model available, which levels escalate); the security team still gets the
      numbers it operates with. `/chat/capabilities` without a token is 401 (it always was).
- [x] P1-04 (Reviewer P1-4) — `/knowledge/search` embeds a query and runs a vector search, the
      same expensive primitive as a chat turn, and had no limiter at all. Verified live: 30 rapid
      searches returned 20 × 200 then 429 from request 21, the same budget as chat, on a separate
      key so a search cannot silently spend the chat allowance.
- [x] The demo now respects the search limiter the way it already respected the chat one (a second
      run inside the same minute used to fail), and SCENARIO 0 demonstrates the new boundary
      instead of printing the stack: "the AI stack is not disclosed without a token", "rule counts
      are not disclosed to an ordinary role", "the security role still sees the counts it operates
      with". The demo is now **71 checks**, and the count is asserted against the documentation.
- [x] Frontend follows: `MetaResponse` loses `ai`, the footer prints environment and version
      rather than the provider and index, and `ChatCapabilities` carries the new `retrieval` block.

**Round 4 — tickets: routing, counting, and a loss-free clarify tier — DONE**

- [x] P1-05 (Reviewer P1-5) — `statistics()` fetched at most `MAX_PAGE_SIZE` (200) rows and counted
      them in Python, so past 200 tickets every figure was silently wrong (oldest rows first), and it
      did the counting after moving rows over the wire. It is now SQL aggregates over the *same*
      visibility predicate the list uses (`_visible_scope`), with no page cap. Verified live:
      `statistics.total` equals the listed count for all three roles.
- [x] P1-06 (Reviewer P1-6) — a self-raised ticket ignored `category` and always landed in the IT
      queue at low severity, so an employee reporting a security concern filed it where the security
      team might never triage it. The `category` now decides the queue (security set → security team,
      `medium`; everything else → the raiser's own team, `low`), the neutral default replaces the old
      `security` default, and the body still cannot set
      `severity`/`owner_role`/`status`/`source`/`escalation_required`. Verified live.
- [x] BUG-2 (handoff §8.1) — a medium-risk report whose clarifying question was never answered was
      tracked nowhere at all. The report is now filed while the question is asked: a `medium`, `open`,
      non-escalated ticket that the answer escalates if the news is worse. Verified live: the
      tracking ticket survives an unrelated next turn and is visible to the security team.
- [x] The escalation invariant is re-stated and asserted in both directions in the evaluation suite
      (escalation always comes with a ticket; a ticket without escalation is only this tracking
      tier), and `phish-003`'s expectation now records that a medium phishing report is tracked.

**Round 5 — the tests, and a pipeline that runs them — DONE**

- [x] P1-07 (Reviewer P1-7) — the frontend suite's blind spots are closed:
      - two **vacuous** assertions (`expect((await screen.findAllByText(...)).length).toBeGreaterThan(0)`)
        replaced with assertions on *where* the text appears (the answer body, scoped);
      - the queue-statistics test asserted only that a `<dt>` label rendered, so it passed with every
        number 0 or `NaN`; it now asserts the numbers bound to their labels;
      - the distributions test asserted five static card titles and passed with all-`NaN` data and an
        empty daily series; it now asserts the fixture's values per card and the two rendered days;
      - `getByText(/7/)` (satisfied by any text containing a digit 7) replaced with the count itself;
      - the "never offers a role switcher" guard only looked for a `combobox`, so a button- or
        link-based switcher slipped through; it now checks buttons, links and listboxes too.
      Each fix was **mutation-verified**: the zeroing/`NaN` mutants that used to pass now fail.
- [x] Frontend coverage tooling: `@vitest/coverage-v8` with statement/branch/function thresholds
      (measured 91.4% / 80.4% / 74.4% before they were set), plus a `test:coverage` script. The gap
      that let a value-blind test survive - a component `App` never mounts is measured by nothing -
      can no longer pass unnoticed.
- [x] Backend coverage: `app/main.py` is no longer omitted (the module that wires the whole
      application was unmeasured while every test executed it), and a `fail_under = 90` floor is set
      (measured 95%, `main.py` itself 93%).
- [x] CI (Reviewer P2-5): `.github/workflows/ci.yml` runs `scripts/check.ps1` on every push to `main`
      and every pull request - the gate existed but nothing ran it, which is how 1416 passing tests
      coexisted with a guard that refused the product's own headline question. Coverage is now part
      of the gate on both sides, not an optional extra.

**Scheduled** (severity order; one round per commit):

- [ ] Round 6 — documentation: the WRONG/drift items in `PROJECT_HANDOFF.md`, and committing the
      handoff + reviewer report

**Decisions taken** (previously open questions):

1. *Ticket statistics* — counts are taken over the caller's **visibility scope** (employee: their own
   reports; IT: their own plus the IT/employee queue; security: everything), computed as SQL
   aggregates with **no page cap**, and documented as such — the numbers must agree with the list
   rendered next to them, which a stricter "queue-only" reading would break. What is fixed is the
   silent 200-row truncation and the fetch-then-count in Python. Reads keep the documented
   "the creator always sees their own ticket" policy.
2. *Blocked turns* — the guard decides whether the assistant **answers**, never whether a person is
   **told**. Refused turns are risk-assessed and escalated on their merits; the refusal text is
   unchanged; the guard's own block keeps a medium floor.
3. *Real LLM path* — documentation-first, no behaviour change: `mock` disclosure moves into the
   README's opening section and `OpenAICompatibleLLMClient.complete` gets stub-transport tests.
   Wiring a live provider is a product decision, not a defect repair.

## Tests

| Gate | Result |
| --- | --- |
| `scripts/check.ps1` (ruff, mypy, pytest+cov, tsc, eslint, vitest+cov, secret scan) | **exit 0** |
| Backend `pytest -q` | **1475 passed, 1 skipped** (started at 1415/1) |
| Backend coverage `--cov=app` | **95%** (4213 statements, 215 missed), floor 90 enforced; `app/main.py` now measured (93%); `app/ai/llm.py` 84% → 98% |
| Frontend `npm test` | **59 passed** (2 files) |
| Frontend coverage | **91.4% statements / 80.4% branches / 74.4% functions**, thresholds 85 / 75 / 70 enforced |
| `security`-marked tests | **1110** of 1476 collected (was 1067 of 1416) |
| CI | `.github/workflows/ci.yml` runs the whole gate on push to `main` and on pull requests |
| `backend/scripts/demo.py` | **71 / 71 checks passed** (was 67; SCENARIO 0 now demonstrates the disclosure boundary and the search limiter) |
| Disclosure boundary (live) | anonymous `/meta` carries no AI-stack key; anonymous `/chat/capabilities` is 401; rule counts absent for employee, present for security |
| `/knowledge/search` throttle (live) | 30 rapid searches → 20 × 200, then 429 from request 21 (same budget as chat, separate key) |
| Ticket routing (live) | `category=security`/`phishing` → `SEC-…`/security/medium; `it`/`other` → `IT-…`/it/low; body `severity`/`owner_role`/`status` ignored |
| Ticket counts (live) | `statistics.total` == listed count for employee, IT and security; no page cap |
| Medium-report tracking (live) | `risk=medium`, `action=clarify`, ticket opened, `escalated=false`; the ticket survives a next turn that asks something else |
| Evaluation set (40 questions, live API) | intent 40/40, risk 40/40, escalation 40/40, ticket 40/40, blocked 40/40, **expected document 28/28** (was 25/28 before the config realignment) |
| Escalation corpus | **52 / 52** S1/S2 phrasings escalate; 20 legitimate questions do not |
| Injection corpus | **31 / 31** blocked; 12 document requests + 3 reported requests not blocked |
| Config drift guard | code default == `.env.example` == README settings table, for the six published defaults |
| `scripts/check-no-secrets.ps1` | OK, all required assets present |

**Repository conventions learned the hard way** (this round): never round-trip `README.md` or
`docs/DEMO.md` through PowerShell `Get-Content`/`Set-Content` — on Windows PowerShell 5.1 it reads
UTF-8 as ANSI and writes a BOM, which mangles every non-ASCII character (the handoff warns about
this in §11.6; it cost one `git checkout --` to undo). Use the editor or an explicit UTF-8 API.

The single skip is `tests/test_deployment_assets.py:436` — the Docker CLI is absent on this
machine, so acceptance criterion §9.10 (`docker compose up`) remains **unproven**, exactly as the
handoff states.

## Current Branch

`main` (remote `origin` = `git@github.com:Ksanadu/enterprise-security-ai-assistant.git`)

## Last Verified

2026-09-13 — Round 1, on Windows PowerShell 5.1, Python 3.12.10, Node 24.19.0.
(`pwsh` is not installed on this machine; use `powershell -ExecutionPolicy Bypass -File scripts\check.ps1`.)
