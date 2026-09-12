---
document_id: KB-008
title: Access Control Policy
category: policy
allowed_roles:
  - it
  - security
version: "2.7"
last_reviewed: "2024-03-01"
owner: Identity and Access Management
summary: >-
  Least-privilege principles, role assignment, joiner/mover/leaver process,
  periodic access review and privileged access management. IT and security use.
---

# Access Control Policy

> **Simulated content.** Fictional sample documentation for a demonstration
> system. Intended for IT support and the security team.

## 1. Principles

* **Least privilege** — every account holds the minimum access required for its
  current role.
* **Need to know** — access to data follows business need, not seniority.
* **Separation of duties** — no single person can both request and approve a
  privileged change.
* **Deny by default** — access is granted explicitly; anything not granted is
  denied.
* **Accountability** — every account must map to exactly one human or one
  documented service.

## 2. Account types

| Type | Owner | MFA | Review cycle |
| ---- | ----- | --- | ------------ |
| Standard user | The employee | Required | Annual |
| Privileged (admin) | Named administrator | Hardware key required | Quarterly |
| Service account | Documented system owner | Certificate or vault-stored secret | Semi-annual |
| Emergency ("break glass") | Security lead | Hardware key, safe-stored | After each use |
| Third-party / contractor | Sponsoring manager | Required | On contract renewal |

Shared or generic human accounts are prohibited. New generic accounts require a
documented exception approved by the CISO.

## 3. Role assignment

1. The manager submits an access request naming the role and the business
   justification.
2. The system owner approves or rejects.
3. IT provisions the role through the identity provider using role-based groups
   — never by granting permissions directly to a user.
4. The requester verifies the access works and reports any excess.

Access requests must never be approved by the requester themselves.

## 4. Joiner, mover, leaver

**Joiner** — accounts are created only after the manager confirms the start date
and the required role. Default access is the minimum for the role, with no
elevated rights.

**Mover** — a role change triggers removal of access that is no longer required
within **3 business days**. Adding new access without removing the old is a
common cause of privilege creep; both actions are part of the same ticket.

**Leaver** — on the last working day:

* all accounts are disabled within **1 hour** of the recorded leaving time;
* sessions and refresh tokens are revoked;
* VPN, mail, SSO and application access is removed;
* company devices are returned, or remotely wiped if not;
* credentials the person knew are rotated if they had privileged access.

## 5. Privileged access management

* Administrators use a **separate privileged account**, never their daily
  account.
* Privileged sessions are brokered through the PAM vault with session recording.
* Standing (permanent) admin rights are discouraged; prefer just-in-time
  elevation with a time limit and an approval.
* Administrative actions on production systems require a change record.
* Emergency access use must be documented within 24 hours and reviewed by the
  security lead.

## 6. Periodic access reviews

* Quarterly: privileged accounts, service accounts, and access to Restricted
  data.
* Semi-annual: all application roles and group memberships.
* Annual: standard user access, and third-party accounts.

Reviewers must confirm each entry, remove what is no longer needed, and record
the outcome. "Reviewed, no change" is acceptable only with a justification.

## 7. Remote and third-party access

Remote access requires MFA and a managed device. Third-party access:

* is time-limited and expires automatically;
* is limited to the specific systems in the contract;
* is supervised or session-recorded when the third party can reach Restricted
  data;
* is removed at contract end, verified by the sponsoring manager.

## 8. Monitoring and exceptions

Access anomalies (impossible travel, sign-in from a new country, mass file
download, first-time admin action) generate alerts to the security team.
Exceptions to this policy require CISO approval, a compensating control, and an
expiry date.
