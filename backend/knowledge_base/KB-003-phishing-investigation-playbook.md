---
document_id: KB-003
title: Phishing Investigation Playbook
category: sop
allowed_roles:
  - security
version: "1.8"
last_reviewed: "2024-02-18"
owner: Security Operations
summary: >-
  Internal investigation procedure for confirmed phishing campaigns, including
  mailbox search, header analysis, containment, and campaign-wide remediation.
  Restricted to the security team.
---

# Phishing Investigation Playbook

> **Simulated content.** Fictional sample documentation for a demonstration
> system. **Internal use only** — restricted to the Security Team.

## 1. When this playbook applies

Use this playbook when a phishing report escalates beyond a simple user report:
credentials were submitted, MFA was approved, an attachment executed, or the same
message reached multiple mailboxes.

## 2. Intake and triage

1. Create or link a **security incident ticket** and set severity using the
   Incident Severity Classification.
2. Preserve the original message as an `.eml` file before any mailbox action.
   Never sanitise or delete the evidence copy.
3. Record the reporter, timestamp, sender, subject, and all URLs.

## 3. Header and infrastructure analysis

Examine:

* `Received` chain — the first untrusted hop and the sending IP;
* `Return-Path` and `Reply-To` versus the visible `From`;
* SPF, DKIM and DMARC results (`Authentication-Results` header);
* the envelope sender domain versus the display name;
* URL reputation for every link, including redirectors and shortened URLs;
* attachment hashes (SHA-256) against the internal blocklist and a threat
  intelligence platform.

Record anti-phishing evasion techniques observed (homoglyph domains, HTML
attachment credential forms, QR-code "quishing", legitimate-service abuse).

## 4. Impact assessment

Determine:

* how many mailboxes received the message (search by sender and by subject);
* how many recipients **clicked** (URL click telemetry from the mail gateway);
* how many recipients **submitted credentials** (check identity provider sign-in
  logs for the destination domain or for impossible-travel anomalies);
* whether any **mailbox rule** was created (forwarding, delegation, hidden
  folder) after the reported time;
* whether any MFA method was changed or added;
* whether OAuth consent was granted to a third-party application.

## 5. Containment

Apply, in this order:

1. **Block** the sender address, sending domain and all URLs at the mail gateway
   and the web proxy.
2. **Purge** the message from all mailboxes using the gateway's campaign search
   and purge function.
3. **Reset** credentials and revoke refresh tokens and active sessions for every
   affected account.
4. **Re-enrol** MFA for affected accounts and confirm no attacker-controlled
   factor remains.
5. **Remove** any unauthorised mailbox rule or OAuth grant.
6. If endpoint compromise is suspected, isolate the device using the EDR console
   and follow the Malware Incident Response SOP.

## 6. Eradication and recovery

* Confirm with the account owner that access is restored and behaviour is
  normal.
* Monitor the affected accounts for 72 hours for anomalous sign-ins, mail flow
  or data access.
* If credentials for a privileged account were submitted, treat the event as
  **critical** and start a full privileged-access review.

## 7. Campaign-wide response

* Issue an organisation-wide advisory with the indicators and a reminder of the
  reporting procedure.
* If more than 5% of recipients interacted, request targeted awareness training.
* Feed the indicators into the mail gateway blocklist and the internal threat
  intelligence record.

## 8. Closure criteria

A phishing incident may be closed only when:

* the campaign is blocked and purged from all mailboxes;
* every affected account has a new credential and clean MFA enrolment;
* no mailbox rule, delegation or OAuth grant created by the attacker remains;
* no further related reports have arrived for 72 hours;
* the ticket contains the indicators, the timeline and the root cause.

## 9. Evidence and retention

Store evidence in the security case folder. Retention is 24 months for
high-severity cases. Personal data inside evidence must be limited to what the
investigation requires.
