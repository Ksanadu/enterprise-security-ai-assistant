---
document_id: KB-007
title: Data Leakage Prevention Policy
category: policy
allowed_roles:
  - employee
  - it
  - security
version: "2.3"
last_reviewed: "2024-02-11"
owner: Security Governance
summary: >-
  Data classification levels, permitted sharing channels for each level, and the
  procedure for reporting a suspected data leak.
---

# Data Leakage Prevention Policy

> **Simulated content.** Fictional sample documentation for a demonstration
> system.

## 1. Data classification

All company information carries one of four classifications.

| Level | Meaning | Examples |
| ----- | ------- | -------- |
| **Public** | Approved for release outside the company | Marketing pages, published policies |
| **Internal** | Everyday business information | Meeting notes, project plans, internal directories |
| **Confidential** | Damage if disclosed; need-to-know | Contracts, financial reports, customer lists, source code |
| **Restricted** | Severe damage or legal impact | Personal data, credentials, security incident details, merger information |

When you are unsure, classify **higher** and ask the data owner or the security
team.

## 2. Permitted sharing channels

| Level | Email | Chat | Company file storage | External sharing |
| ----- | ----- | ---- | -------------------- | ---------------- |
| Public | ✅ | ✅ | ✅ | ✅ |
| Internal | ✅ | ✅ | ✅ | ⚠️ only with a business need and a named recipient |
| Confidential | ⚠️ only to a named internal recipient | ⚠️ direct message, not a public channel | ✅ | ❌ unless approved by the data owner and protected by a sharing link with an expiry |
| Restricted | ❌ | ❌ | ✅ access-controlled folder only | ❌ |

Additional rules:

* Never send Confidential or Restricted data to a personal email account.
* Never copy Restricted data into a ticket comment, a wiki page, a chat channel
  or a screenshot.
* Never store company data on unmanaged cloud storage or personal devices.
* Use the approved secure file transfer service, not consumer file-sharing
  sites, for large Confidential transfers.

## 3. Handling personal data

* Collect only the personal data you actually need for the stated purpose.
* Do not export a personal-data spreadsheet to your local drive.
* Mask or redact identifiers when the full value is not required.
* Delete personal data when the retention period ends.
* Report any suspected personal-data breach within **24 hours** — this is a
  legal obligation, not an internal preference.

## 4. Technical controls

The company operates data loss prevention (DLP) controls on endpoints, email and
the web proxy. These may:

* block or quarantine an email containing patterns such as national ID numbers,
  card numbers or credential-like strings;
* alert on large uploads to unsanctioned cloud storage;
* watermark documents containing Restricted data.

Do not attempt to evade these controls, including by renaming files, splitting
archives, or encrypting content inside an archive to hide it from inspection.
Attempting to bypass a DLP control is a disciplinary matter.

## 5. Suspected leak procedure

If you suspect data has left the company — a misdirected email, a lost device, a
misconfigured sharing link, an unauthorised upload:

1. **Do not delete evidence** and do not attempt to "recall and forget it".
2. Report to the security team immediately (see the Security Contact Guide).
3. Provide the file names, the approximate volume of records, the recipients, and
   the exact time.
4. Preserve the message, link or device for investigation.
5. Do not contact the recipient directly without guidance from the security and
   legal teams.

The security team will assess the exposure, attempt recall where possible,
determine whether notification obligations apply, and open an incident ticket.

## 6. External sharing exceptions

An exception to the rules above requires:

* a documented business justification;
* the data owner's written approval;
* a defined expiry for the access;
* a record in the exception register reviewed quarterly.
