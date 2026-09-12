---
document_id: KB-009
title: Incident Severity Classification
category: standard
allowed_roles:
  - it
  - security
version: "1.9"
last_reviewed: "2024-02-25"
owner: Security Operations
summary: >-
  Severity levels S1 to S4, how to map an observed security event to a severity,
  response-time targets, and the mandatory escalation rules for high severity.
---

# Incident Severity Classification

> **Simulated content.** Fictional sample documentation for a demonstration
> system. Intended for IT support and the security team.

## 1. Severity levels

| Severity | Name | Description | First response | Update cadence |
| -------- | ---- | ----------- | -------------- | -------------- |
| **S1** | Critical | Confirmed breach of a critical system, ransomware, data exfiltration, or loss of a privileged account | 15 minutes, 24×7 | Every hour |
| **S2** | High | Confirmed compromise of one account or endpoint, malware execution, or credentials submitted to a phishing site | 30 minutes, 24×7 | Every 4 hours |
| **S3** | Medium | Suspicious activity that is not yet confirmed: a reported phishing email with a click, an unsupported device attempting access, a policy violation | 4 business hours | Daily |
| **S4** | Low | Reports with no evidence of compromise: spam, a phishing report with no interaction, a lost but encrypted and remotely-wiped device | 1 business day | Every 3 days |

## 2. Mapping common events to severity

| Observed event | Severity |
| -------------- | -------- |
| User reports a suspicious email without interacting | S4 |
| User clicked a phishing link, entered nothing | S3 |
| User entered credentials into a phishing page | **S2** |
| User approved an unexpected MFA prompt | **S2** |
| Malicious attachment executed on one endpoint | **S2** |
| Malware on a server, or on more than three endpoints | **S1** |
| Ransomware or confirmed data exfiltration | **S1** |
| Privileged account suspected compromised | **S1** |
| Lost device, encrypted, remote wipe succeeded | S4 |
| Lost device, unencrypted, or wipe unconfirmed | **S1** |
| Unauthorised cloud storage upload detected | S3, unless Restricted data is involved → S2 |
| Successful sign-in from an impossible-travel location | S3, unless followed by data access → S2 |

## 3. Severity adjustment rules

Escalate the severity when:

* the asset is a server, an identity system, or a system handling Restricted
  data;
* the affected account is privileged;
* the event affects multiple users or is clearly part of a campaign;
* the attacker has demonstrated persistence;
* a regulatory or contractual notification obligation may apply.

Reduce the severity only with evidence — never because the reporter seems
"probably fine".

## 4. Mandatory human escalation

The following severities **must** be handled by a human member of the security
team; the AI assistant may suggest actions but must never close them
automatically:

* **S1 and S2**: human escalation is mandatory and immediate;
* **S3**: human review before any advice is treated as final;
* **S4**: may be handled by automated guidance, with a report kept for review.

Automated ticket creation is appropriate for S2 and above, and for S3 when the
event involves credentials.

## 5. Escalation path

1. Duty security engineer (on-call rota).
2. Security lead.
3. For S1: CISO, crisis communication lead, and — where personal data is
   involved — the data protection officer and legal counsel.

If the duty engineer does not acknowledge an S1 within 15 minutes, escalate to
the security lead directly.

## 6. Closure requirements

Every S1 and S2 incident requires:

* a written timeline with UTC timestamps;
* the root cause;
* the containment and recovery actions taken;
* improvement actions with named owners and due dates;
* confirmation that no indicator remains active.
