# Knowledge Base

**Every document in this directory is fictional.** It is sample content written
for a demonstration system. It contains no real company data, no real personal
data, and no real credentials or contact details.

## Document contract

Each document is Markdown with a YAML front-matter block. The front matter is
**security-relevant metadata**, not decoration: the retrieval layer uses it to
decide which roles may ever see the document.

```yaml
---
document_id: KB-001          # required, unique, pattern KB-###
title: Password Policy       # required, human-readable
category: policy             # required, one of: policy | sop | standard | guide | faq
allowed_roles:               # required, non-empty subset of employee | it | security
  - employee
  - it
  - security
version: "3.2"               # optional
last_reviewed: "2024-01-15"  # optional, ISO date
owner: Identity and Access Management
summary: >-                  # optional, used in the document index listing
  One-line description.
---

# Body starts here
```

### Rules enforced when the knowledge base loads

| Rule | Why |
| ---- | --- |
| `document_id` must match `^[A-Z]{2,6}-\d{3}$` and be unique | Stable citation key; duplicates would make audit records ambiguous |
| `allowed_roles` must be present and non-empty | A document with no audience is a configuration error, not a public document. **Fail closed**: it is rejected rather than exposed |
| Every role in `allowed_roles` must be a known role | Typos such as `admin` must not silently mean "nobody" or "everybody" |
| `category` must be from the controlled list | Categories feed dashboards and policy summaries |
| Body must be at least 200 characters | Prevents placeholder documents from becoming citable answers |
| Unknown front-matter keys are rejected | Catches misspelled keys such as `allow_roles`, which would otherwise silently drop the restriction |

Validation is **strict by default** (`KB_STRICT_VALIDATION=true`). A malformed
document stops the application from starting rather than being quietly skipped,
because a silently skipped document is a silent change in what the assistant is
allowed to say.

## Current documents

| ID | Title | Category | Audience |
| -- | ----- | -------- | -------- |
| KB-001 | Password Policy | policy | employee, it, security |
| KB-002 | Phishing Response SOP | sop | employee, it, security |
| KB-003 | Phishing Investigation Playbook | sop | security |
| KB-004 | Malware Incident Response SOP | sop | security |
| KB-005 | VPN Troubleshooting SOP | sop | it, security |
| KB-006 | Remote Work Security Policy | policy | employee, it, security |
| KB-007 | Data Leakage Prevention Policy | policy | employee, it, security |
| KB-008 | Access Control Policy | policy | it, security |
| KB-009 | Incident Severity Classification | standard | it, security |
| KB-010 | Endpoint Security Guide | guide | employee, it, security |
| KB-011 | Security Contact Guide | guide | employee, it, security |
| KB-012 | VPN Connection Guide | guide | employee, it, security |

## Why some topics have two documents

Several topics deliberately exist in two versions with different audiences:

* **KB-005 VPN Troubleshooting SOP** (`it`, `security`) versus
  **KB-012 VPN Connection Guide** (`employee`, …). An employee asking about VPN
  problems gets first-line self-service steps; the service desk gets the full
  diagnostic procedure.
* **KB-002 Phishing Response SOP** (`employee`-visible) versus
  **KB-003 Phishing Investigation Playbook** (`security` only) and
  **KB-004 Malware Incident Response SOP** (`security` only). Employees get the
  "what should I do right now" procedure; internal investigation technique,
  evidence handling and escalation matrices stay with the security team.

This structure is what makes role-based retrieval meaningful: the same question
produces different, correctly-scoped answers depending on who is asking.

## Adding a document

1. Copy an existing file and update the front matter.
2. Choose `allowed_roles` from the roles that genuinely need the content — the
   default should be the narrowest set, not the widest.
3. Run the knowledge base tests:

   ```powershell
   cd backend
   .\.venv\Scripts\python.exe -m pytest tests/test_rag_loader.py -q
   ```

4. Restart the backend, or call `POST /api/v1/knowledge/reindex` as a user with
   the `security` role, to rebuild the vector index.
