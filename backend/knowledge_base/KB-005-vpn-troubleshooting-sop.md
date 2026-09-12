---
document_id: KB-005
title: VPN Troubleshooting SOP
category: sop
allowed_roles:
  - it
  - security
version: "1.6"
last_reviewed: "2024-01-28"
owner: IT Service Management
summary: >-
  Diagnostic procedure for corporate VPN connection failures, ordered from the
  most common causes to the least. IT support and security team use.
---

# VPN Troubleshooting SOP

> **Simulated content.** Fictional sample documentation for a demonstration
> system. Intended for the IT service desk and the security team.

## 1. Confirm the symptom

Ask the user for:

* the exact error message and code;
* whether the client never connects, or connects and then drops;
* when it last worked;
* whether the failure affects every network (home Wi-Fi *and* mobile hotspot);
* whether colleagues in the same office are affected.

If several users fail at once, treat it as a service incident first: check the
VPN gateway status page before debugging a single endpoint.

## 2. Standard diagnostic order

Work top to bottom; stop as soon as a step changes the symptom.

1. **Licence and account state** — confirm the VPN entitlement is assigned and
   the account is not locked, expired or disabled.
2. **Client version** — VPN clients below the minimum supported version are
   blocked by policy. Upgrade and retry.
3. **Credentials and MFA** — a rejected MFA prompt, an expired password, or an
   out-of-sync authenticator app produce a generic "authentication failed". Test
   the same credentials on the SSO portal to isolate this.
4. **Local network** — the user's ISP or router may block the required ports.
   Test on a mobile hotspot: if it works there, the home network or ISP is the
   cause (common culprits: carrier-grade NAT, restrictive guest Wi-Fi, hotel
   captive portals).
5. **DNS** — a stale DNS cache or a home router using a filtering DNS service
   can prevent gateway name resolution. Flush the DNS cache and retry.
6. **Local firewall or endpoint protection** — a third-party personal firewall
   or an unmanaged antivirus product can block the tunnel adapter. Temporarily
   disable the third-party product to confirm, then re-enable and add an
   exception through the standard change process.
7. **Tunnel adapter / virtual NIC** — a corrupt virtual adapter shows as
   "connected, no traffic". Remove and reinstall the adapter, or reinstall the
   client.
8. **Clock skew** — certificate validation fails when the device clock is off by
   more than five minutes. Verify the time zone and synchronise.
9. **Certificate state** — an expired device certificate or a missing client
   certificate produces a handshake failure. Re-enrol the device.
10. **Split-tunnel configuration** — if only internal resources are
    unreachable, verify the split-tunnel route list and the internal DNS suffix
    configuration.

## 3. Escalation

Escalate to the network team when:

* the gateway reports capacity, licence-pool or certificate-authority errors;
* more than five users fail simultaneously;
* packet capture shows the tunnel establishing but no return traffic;
* the failure follows an infrastructure change in the last 24 hours.

Provide the network team with the client log bundle, the exact timestamp in UTC,
the source public IP, and the gateway node the client attempted.

## 4. Communication to the user

Tell the user what you changed and what to expect, and give them a workaround if
one exists (for example, browser-based access to internal web applications).
If the issue is not resolved in 30 minutes, create or update the IT ticket and
set an expectation for the next update.

## 5. Data to capture for every VPN ticket

* client version and operating system build;
* error code and timestamp (UTC);
* client log bundle;
* source network type (corporate, home, mobile);
* whether an MFA prompt was presented and approved;
* the gateway node and the assigned internal address, when visible.
