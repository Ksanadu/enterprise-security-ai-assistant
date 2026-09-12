---
document_id: KB-001
title: Password Policy
category: policy
allowed_roles:
  - employee
  - it
  - security
version: "3.2"
last_reviewed: "2024-01-15"
owner: Identity and Access Management
summary: >-
  Minimum password length, complexity, rotation and reuse rules for all company
  accounts, plus the requirements for multi-factor authentication and password
  managers.
---

# Password Policy

> **Simulated content.** This is fictional sample documentation created for a
> demonstration system. It does not describe any real organisation.

## 1. Scope

This policy applies to every workforce account: email, single sign-on (SSO),
VPN, business applications, administrative consoles and service accounts.
Contractors and interns are covered by the same requirements.

## 2. Password requirements

All standard user passwords **must**:

* be at least **14 characters** long;
* contain at least three of the following: lowercase letters, uppercase
  letters, digits, and symbols;
* not be a password that has appeared in a known breach corpus (checked
  automatically at set time);
* not contain the username, the employee's name, the company name, or a
  predictable variation of them;
* not be reused across a personal account and a company account.

Passwords **must not** be:

* a single dictionary word with simple substitutions (`P@ssw0rd`);
* a keyboard pattern (`qwerty1234`, `1qaz2wsx`);
* a date of birth, phone number or similar personal identifier.

### Privileged and service accounts

Accounts with administrative rights, and any non-human service account, require
**20 characters or more** and must be stored in the approved secrets vault.
Human administrators must not keep privileged credentials in a spreadsheet,
wiki page, ticket comment or chat message.

## 3. Password rotation

* Standard user accounts: rotation is **not** required on a fixed schedule.
  Rotate immediately if you suspect compromise, or if the security team requests
  it following an incident.
* Privileged accounts: rotate at least every **180 days**, and immediately after
  any personnel change affecting who holds the credential.
* Service accounts: rotate at least every **365 days** using the vault's
  automated rotation, and immediately if the secret may have been exposed.

## 4. Password reuse and storage

Use the company-approved password manager to generate and store unique
passwords. Do not:

* write passwords on paper kept at your desk;
* store passwords in a browser profile that is not managed by the company;
* save passwords in plain text files, notes applications or source code;
* share a password with a colleague — every account is personal and auditable.

## 5. Multi-factor authentication (MFA)

MFA is **mandatory** for:

* single sign-on;
* VPN and remote access;
* email and collaboration suites;
* any administrative console;
* access from an untrusted network or an unrecognised device.

Approved second factors are the company push-notification authenticator app and
hardware security keys. SMS one-time codes are permitted only as a documented
fallback and must be replaced with an app or hardware key within 30 days.

Never approve an MFA prompt you did not personally initiate. Repeated unexpected
MFA prompts ("MFA fatigue") are a sign that an attacker already has your
password — report it immediately as a security incident.

## 6. Reporting a suspected password compromise

If you believe a password has been exposed — for example you typed it into a
link from an unexpected email, or you approved an MFA prompt by mistake:

1. Change the password immediately from a known-good device.
2. Report the event to the security team the same day (see the Security Contact
   Guide).
3. Sign out of all active sessions for that account.
4. Watch for unexpected password reset emails or MFA prompts and report them.

Reporting quickly is always the right decision. There is no penalty for
reporting a mistake; there is a penalty for hiding one.

## 7. Enforcement

Accounts found to violate this policy may have their credentials reset by the IT
service desk. Repeated violations are handled through the standard HR process.
